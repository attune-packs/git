from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT / "lib"))

import git_credentials


class CredentialTests(unittest.TestCase):
    def test_fetch_key_requests_scoped_decryption(self):
        calls = {}
        get_key = ModuleType("attune.api_client.api.secrets.get_key")

        def sync_detailed(ref, *, client, decrypt):
            calls.update(ref=ref, client=client, decrypt=decrypt)
            value = {"type": "https_token", "host": "example.invalid", "username": "user", "token": "synthetic"}
            return SimpleNamespace(status_code=200, parsed=SimpleNamespace(data=SimpleNamespace(value=value, encrypted=True)))

        get_key.sync_detailed = sync_detailed
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = ModuleType("attune")
        attune.context = SimpleNamespace(client="execution-client")
        modules = {
            "attune": attune,
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules):
            credential = git_credentials.load_credentials(credential_key="git.credentials")
        self.assertEqual(calls, {"ref": "git.credentials", "client": "execution-client", "decrypt": True})
        self.assertEqual(credential.type, "https_token")

    def test_key_lookup_errors_are_redacted(self):
        marker = "SENSITIVE_" + "VALUE"
        get_key = ModuleType("attune.api_client.api.secrets.get_key")
        get_key.sync_detailed = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker))
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        attune = ModuleType("attune")
        attune.context = SimpleNamespace(client="client")
        modules = {
            "attune": attune,
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules), self.assertRaises(git_credentials.GitCredentialError) as raised:
            git_credentials.fetch_attune_key("git.credentials")
        self.assertNotIn(marker, str(raised.exception))

    def test_credential_shapes_and_invalid_values(self):
        valid = [
            {"type": "https_basic", "host": "example.invalid", "username": "user", "password": "pass"},
            {"type": "https_token", "host": "example.invalid", "username": "x-access-token", "token": "token"},
            {"type": "ssh_private_key", "host": "example.invalid", "private_key": "private", "passphrase": "phrase", "known_hosts": "host key"},
            json.dumps({"type": "https_token", "host": "example.invalid", "username": "user", "token": "token"}),
        ]
        for value in valid:
            with self.subTest(value=value):
                self.assertIsNotNone(git_credentials.load_credentials(value))
        invalid = [
            {},
            {"type": "unknown"},
            {"type": "https_basic", "host": "example.invalid", "username": "user"},
            {"type": "https_token", "host": "example.invalid", "username": "user\nname", "token": "token"},
            {"type": "https_token", "host": "example.invalid", "username": "user", "token": "token\nnext"},
            {"type": "ssh_private_key", "host": "example.invalid", "private_key": "key", "extra": "bad"},
            "not json",
            [],
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(git_credentials.GitCredentialError):
                git_credentials.load_credentials(value)

    def test_remote_validation_and_transport_matching(self):
        https = git_credentials.load_credentials({"type": "https_basic", "host": "example.invalid", "username": "u", "password": "p"})
        ssh = git_credentials.load_credentials({"type": "ssh_private_key", "host": "example.invalid", "private_key": "key"})
        accepted = [
            ("https://example.invalid/repo.git", https, "https"),
            ("ssh://git@example.invalid/repo.git", ssh, "ssh"),
            ("git@example.invalid:org/repo.git", ssh, "ssh"),
            ("/tmp/repo", None, "local"),
        ]
        for remote, credential, transport in accepted:
            with self.subTest(remote=remote):
                self.assertEqual(git_credentials.validate_remote(remote, credential).transport, transport)
        rejected = [
            "https://user:pass@example.invalid/repo.git",
            "git://example.invalid/repo.git",
            "file:///tmp/repo",
            "ext::command",
            "https://example.invalid:bad/repo.git",
        ]
        for remote in rejected:
            with self.subTest(remote=remote), self.assertRaises(git_credentials.GitCredentialError):
                git_credentials.validate_remote(remote)
        with self.assertRaises(git_credentials.GitCredentialError):
            git_credentials.validate_remote("ssh://git@example.invalid/repo.git", https)
        with self.assertRaises(git_credentials.GitCredentialError):
            git_credentials.validate_remote("https://other.invalid/repo.git", https)
        with self.assertRaises(git_credentials.GitCredentialError):
            git_credentials.validate_remote("https://example.invalid:8443/repo.git", https)
        alternate_port = git_credentials.load_credentials({
            "type": "https_basic", "host": "example.invalid:8443", "username": "u", "password": "p",
        })
        self.assertEqual(
            git_credentials.validate_remote("https://example.invalid:8443/repo.git", alternate_port).transport,
            "https",
        )

    def test_https_session_uses_private_files_not_secret_environment_or_argv(self):
        marker = "SYNTHETIC_" + "SECRET"
        credential = {"type": "https_basic", "host": "example.invalid", "username": "user", "password": marker}
        session = git_credentials.git_credentials("https://example.invalid/repo.git", credential, environ={"PATH": os.environ.get("PATH", "")})
        with session:
            root = Path(session.env["GIT_ASKPASS"]).parent
            command = session.command(["ls-remote", "https://example.invalid/repo.git"])
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "secret").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / "askpass").stat().st_mode), 0o700)
            self.assertNotIn(marker, json.dumps(session.env))
            self.assertNotIn(marker, json.dumps(command))
            self.assertNotIn("ATTUNE_API_TOKEN", session.env)
            self.assertIn("core.hooksPath=/dev/null", command)
            helper = subprocess.run([str(root / "askpass"), "Password for remote"], text=True, capture_output=True, check=True)
            self.assertEqual(helper.stdout, marker)
        self.assertFalse(root.exists())

    def test_ssh_session_isolates_agent_and_private_key(self):
        marker = "PRIVATE_" + "MATERIAL"
        credential = {"type": "ssh_private_key", "host": "host.example", "private_key": marker, "known_hosts": "host.example key"}
        with git_credentials.git_credentials(
            "git@host.example:org/repo.git",
            credential,
            environ={"PATH": os.environ.get("PATH", ""), "SSH_AUTH_SOCK": "/tmp/agent"},
        ) as session:
            ssh_command = session.config_args[session.config_args.index("-c", 2) + 1]
            root = Path(ssh_command.split("=", 1)[1]).parent
            self.assertNotIn("SSH_AUTH_SOCK", session.env)
            self.assertNotIn(marker, json.dumps(session.env))
            self.assertEqual(stat.S_IMODE((root / "identity").stat().st_mode), 0o600)
            self.assertIn("StrictHostKeyChecking=yes", (root / "ssh").read_text())
        self.assertFalse(root.exists())

    def test_no_explicit_credentials_preserves_worker_authentication(self):
        environ = {
            "PATH": os.environ.get("PATH", ""),
            "SSH_AUTH_SOCK": "/tmp/agent",
            "GIT_ASKPASS": "/tmp/helper",
            "ATTUNE_API_TOKEN": "execution-token",
        }
        with git_credentials.git_credentials("https://example.invalid/repo.git", environ=environ) as session:
            self.assertEqual(session.env["SSH_AUTH_SOCK"], "/tmp/agent")
            self.assertEqual(session.env["GIT_ASKPASS"], "/tmp/helper")
            self.assertEqual(session.env["GIT_TERMINAL_PROMPT"], "0")
            self.assertNotIn("ATTUNE_API_TOKEN", session.env)

    def test_process_failure_and_timeout_are_redacted(self):
        class FailedProcess:
            pid = 12345
            returncode = 128

            def communicate(self, timeout=None):
                return "", "SENSITIVE_ERROR"

        with patch.object(git_credentials.subprocess, "Popen", return_value=FailedProcess()):
            with self.assertRaisesRegex(git_credentials.GitCredentialError, "exit code 128") as raised:
                git_credentials.run_process(["git", "status"])
        self.assertNotIn("SENSITIVE_ERROR", str(raised.exception))

        class TimedOutProcess:
            pid = 12345
            returncode = None

            def communicate(self, timeout=None):
                if timeout is not None:
                    raise subprocess.TimeoutExpired(["git"], timeout)
                self.returncode = -15
                return "", "SENSITIVE_TIMEOUT"

            def poll(self):
                self.returncode = -15
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                self.returncode = -9

        with patch.object(git_credentials.subprocess, "Popen", return_value=TimedOutProcess()), \
             patch.object(TimedOutProcess, "terminate", autospec=True, side_effect=TimedOutProcess.terminate) as terminate:
            with self.assertRaisesRegex(git_credentials.GitCredentialError, "timed out") as raised:
                git_credentials.run_process(["git", "status"], timeout=1)
        self.assertTrue(terminate.called)
        self.assertNotIn("SENSITIVE_TIMEOUT", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
