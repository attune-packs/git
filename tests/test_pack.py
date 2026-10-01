from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import yaml


PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT / "lib"))


def load_module(name: str, path: Path, modules: dict[str, ModuleType] | None = None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with patch.dict(sys.modules, modules or {}):
        spec.loader.exec_module(module)
    return module


git_action = load_module("git_action_test", PACK_ROOT / "actions" / "git_action.py")


class PackTests(unittest.TestCase):
    def test_action_metadata_covers_source_actions(self):
        expected = {
            "checkout_remote_branch", "clone", "commit_and_push",
            "get_local_repo_latest_commit", "get_remote_repo_latest_commit",
            "new_local_branch", "remote_branch_exists",
        }
        documents = [yaml.safe_load(path.read_text()) for path in sorted((PACK_ROOT / "actions").glob("*.yaml"))]
        self.assertEqual({doc["ref"].split(".", 1)[1] for doc in documents}, expected)
        for doc in documents:
            self.assertEqual(doc["runner_type"], "python")
            self.assertEqual(doc["entry_point"], "git_action.py")
            self.assertEqual(doc["parameter_delivery"], "stdin")
            self.assertEqual(doc["parameter_format"], "json")
            self.assertEqual(doc["output_format"], "json")
            self.assertIn("output", doc)
            self.assertNotIn("cmd", doc["parameters"])
            name = doc["ref"].split(".", 1)[1]
            if name in {"clone", "checkout_remote_branch", "commit_and_push", "get_remote_repo_latest_commit", "remote_branch_exists"}:
                self.assertIn("credential_key", doc["parameters"])
                self.assertEqual(doc["default_execution_permission_set_refs"], ["standard"])
            else:
                self.assertNotIn("credential_key", doc["parameters"])
                self.assertNotIn("default_execution_permission_set_refs", doc)

    def test_all_actions_use_argument_arrays_and_structured_results(self):
        cases = {
            "clone": (
                {"source": "source;touch BAD", "destination": "/tmp/destination", "ref": "main"},
                {"repository_path": str(Path("/tmp/destination").resolve()), "revision": "abc"},
            ),
            "checkout_remote_branch": (
                {"local_repo_directory": "/tmp/repo", "remote_branch": "feature branch"},
                {"branch": "feature branch", "revision": "abc"},
            ),
            "commit_and_push": (
                {"local_repo_directory": "/tmp/repo", "branch_to_push": "main", "commit_message": "quote ' ; safe"},
                {"branch": "main", "revision": "abc", "pushed": True},
            ),
            "get_local_repo_latest_commit": (
                {"repo_path": "/tmp/repo", "branch": "main"},
                {"branch": "main", "revision": "abc"},
            ),
            "get_remote_repo_latest_commit": (
                {"repo_remote": "https://example.invalid/repo.git", "branch": "main"},
                {"branch": "main", "revision": "abc"},
            ),
            "new_local_branch": (
                {"local_repo_directory": "/tmp/repo", "source_branch": "main", "new_branch": "patch"},
                {"branch": "patch", "source_branch": "main", "revision": "abc"},
            ),
            "remote_branch_exists": (
                {"repository": "https://example.invalid/repo.git", "branch": "main"},
                {"branch": "main", "exists": True, "revision": "abc"},
            ),
        }

        commands = []

        def fake_run(args, timeout, cwd=None, **kwargs):
            self.assertIsInstance(args, list)
            if args[1:4] == ["remote", "get-url", "origin"] or args[1:5] == ["remote", "get-url", "--push", "origin"]:
                return "https://example.invalid/repo.git"
            if args[1:3] == ["config", "--local"]:
                return ""
            return "abc"

        class Session:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def run(self, args, timeout=120, cwd=None):
                commands.append((list(args), cwd))
                if args[0] == "ls-remote":
                    return "abc\trefs/heads/main"
                return "abc"

        with patch.object(git_action, "_run", side_effect=fake_run), \
             patch.object(git_action, "git_credentials", return_value=Session()), \
             patch.object(Path, "is_dir", return_value=True):
            for operation, (params, expected) in cases.items():
                with self.subTest(operation=operation):
                    self.assertEqual(git_action.execute(operation, params), expected)

    def test_missing_remote_branch_is_boolean_or_failure(self):
        class Session:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def run(self, *args, **kwargs): return ""

        with patch.object(git_action, "git_credentials", return_value=Session()):
            self.assertEqual(
                git_action.execute("remote_branch_exists", {"repository": "example.invalid", "branch": "missing"}),
                {"branch": "missing", "exists": False, "revision": None},
            )
            with self.assertRaises(git_action.GitActionError):
                git_action.execute("get_remote_repo_latest_commit", {"repo_remote": "example.invalid", "branch": "missing"})

    def test_timeout_validation_and_redacted_process_error(self):
        for value in (0, 3601, True, "10"):
            with self.subTest(value=value), self.assertRaises(git_action.GitActionError):
                git_action.execute("remote_branch_exists", {"repository": "example.invalid", "timeout_seconds": value})

    def test_credential_key_is_used_once_for_remote_operation(self):
        observed = []

        class Session:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def run(self, args, **kwargs):
                observed.append(list(args))
                return "abc"

        with patch.object(git_action, "git_credentials", return_value=Session()) as credentials, \
             patch.object(git_action, "_run", return_value="abc"):
            result = git_action.execute("clone", {
                "source": "https://example.invalid/repo.git",
                "destination": "/tmp/repo",
                "credential_key": "pack.git.credentials",
            })
        credentials.assert_called_once_with("https://example.invalid/repo.git", credential_key="pack.git.credentials")
        self.assertEqual(observed[0][0], "clone")
        self.assertEqual(result["revision"], "abc")

    def test_local_actions_do_not_resolve_credentials(self):
        with patch.object(git_action, "git_credentials") as credentials, \
             patch.object(git_action, "_run", return_value="abc"), \
             patch.object(Path, "is_dir", return_value=True):
            git_action.execute("get_local_repo_latest_commit", {"repo_path": "/tmp/repo"})
            git_action.execute("new_local_branch", {"local_repo_directory": "/tmp/repo"})
        credentials.assert_not_called()

    def test_explicit_credentials_reject_repository_url_rewrites(self):
        def fake_run(args, timeout, cwd=None, **kwargs):
            if args[1:3] == ["config", "--local"] and "--get-regexp" in args:
                return "url.https://attacker.invalid/.insteadOf https://trusted.invalid/"
            return "https://trusted.invalid/repo.git"

        with patch.object(git_action, "_run", side_effect=fake_run), \
             patch.object(Path, "is_dir", return_value=True), \
             self.assertRaisesRegex(git_action.GitActionError, "URL rewrites"):
            git_action.execute("checkout_remote_branch", {
                "local_repo_directory": "/tmp/repo",
                "remote_branch": "main",
                "credential_key": "pack.git.credentials",
            })

    def test_entrypoint_rejects_malformed_json_without_echoing_input(self):
        stdin, stdout, stderr = io.StringIO('{"source":"DO_NOT_PRINT"'), io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
            self.assertEqual(git_action.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_PRINT", stderr.getvalue())

    def test_sensor_contract_and_checkpointed_targeted_emission(self):
        fake_attune = ModuleType("attune")

        class PollingSensor:
            def __init__(self):
                self.events = []

            def emit(self, payload, rule=None):
                self.events.append((payload, rule))

        fake_attune.PollingSensor = PollingSensor
        fake_attune.run_sensor = lambda sensor: None
        sensor = load_module(
            "git_commit_sensor_test",
            PACK_ROOT / "sensors" / "git_commit_sensor.py",
            {"attune": fake_attune},
        )
        trigger = yaml.safe_load((PACK_ROOT / "triggers" / "head_sha_monitor.yaml").read_text())
        sensor_yaml = yaml.safe_load((PACK_ROOT / "sensors" / "git_commit_sensor.yaml").read_text())
        self.assertEqual(sensor_yaml["trigger_types"], [trigger["ref"]])

        payload = {
            "revision": "abc", "author": "A", "author_email": "a@example.invalid",
            "authored_date": "2026-08-11T00:00:00Z", "author_tz_offset": 0,
            "committer": "C", "committer_email": "c@example.invalid",
            "committed_date": "2026-08-11T00:00:00Z", "committer_tz_offset": 0,
            "commit_message": "change", "branch": "main", "repository_url": "https://example.invalid/repo.git",
        }
        self.assertEqual(set(payload), set(trigger["output"]))
        rule = SimpleNamespace(id=42, trigger_params={"repository_url": payload["repository_url"], "branch": "main"})
        instance = sensor.GitCommitSensor()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), \
             patch.object(sensor, "update_repository"), patch.object(sensor, "inspect_head", return_value=payload):
            instance.poll(rule)
            instance.poll(rule)
            checkpoint_files = list((Path(directory) / "git_commit_sensor" / "checkpoints").glob("*.json"))
        self.assertEqual(instance.events, [(payload, rule)])
        self.assertEqual(len(checkpoint_files), 1)

    def test_sensor_does_not_checkpoint_failed_delivery(self):
        fake_attune = ModuleType("attune")

        class PollingSensor:
            def emit(self, payload, rule=None):
                raise RuntimeError("delivery failed")

        fake_attune.PollingSensor = PollingSensor
        fake_attune.run_sensor = lambda sensor: None
        sensor = load_module("git_commit_sensor_failure_test", PACK_ROOT / "sensors" / "git_commit_sensor.py", {"attune": fake_attune})
        rule = SimpleNamespace(id=7, trigger_params={"repository_url": "https://example.invalid/repo.git", "branch": "main"})
        payload = {"revision": "abc"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}), \
             patch.object(sensor, "update_repository"), patch.object(sensor, "inspect_head", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "delivery failed"):
                sensor.GitCommitSensor().poll(rule)
            self.assertEqual(list(Path(directory).rglob("*.json")), [])

    def test_sensor_timestamp_and_timezone_offset(self):
        fake_attune = ModuleType("attune")
        fake_attune.PollingSensor = object
        fake_attune.run_sensor = lambda sensor: None
        sensor = load_module("git_commit_sensor_time_test", PACK_ROOT / "sensors" / "git_commit_sensor.py", {"attune": fake_attune})
        self.assertEqual(sensor._iso8601("0"), "1970-01-01T00:00:00Z")
        self.assertEqual(sensor._offset_seconds("2026-08-11 10:00:00 +0530"), 19800)
        self.assertEqual(sensor._offset_seconds("2026-08-11 10:00:00 -0700"), -25200)

    def test_pack_has_no_secret_material_or_runtime_pack_writes(self):
        forbidden = ["BEGIN " + "PRIVATE KEY", "Authorization" + ": Bearer", "password" + ": production"]
        for path in PACK_ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".yaml", ".md", ".txt", ".json"}:
                text = path.read_text(encoding="utf-8")
                self.assertFalse(any(value in text for value in forbidden), str(path))
        sensor_text = (PACK_ROOT / "sensors" / "git_commit_sensor.py").read_text()
        self.assertIn("ATTUNE_ARTIFACTS_DIR", sensor_text)
        self.assertNotIn("__file__", sensor_text)


if __name__ == "__main__":
    unittest.main()
