"""Secure credential transport and process execution for Git pack actions."""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


class GitCredentialError(RuntimeError):
    """Safe operator-facing Git error."""


@dataclass(frozen=True)
class Credential:
    type: str
    host: str
    username: str | None = None
    secret: str | None = None
    private_key: str | None = None
    passphrase: str | None = None
    known_hosts: str | None = None


@dataclass(frozen=True)
class Remote:
    value: str
    transport: str


@dataclass(frozen=True)
class ProcessResult:
    stdout: str
    stderr: str
    returncode: int


_CREDENTIAL_FIELDS = {
    "https_basic": {"type", "host", "username", "password"},
    "https_token": {"type", "host", "username", "token"},
    "ssh_private_key": {"type", "host", "private_key", "passphrase", "known_hosts"},
}
_SCP_REMOTE = re.compile(
    r"^(?:(?P<user>[A-Za-z0-9._-]+)@)?(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(?P<path>.+)$"
)
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise GitCredentialError(f"credential field {field!r} must be a non-empty string")
    if "\x00" in value:
        raise GitCredentialError(f"credential field {field!r} contains an invalid null byte")
    return value


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field)


def _single_line(value: Any, field: str) -> str:
    text = _required_text(value, field)
    if "\r" in text or "\n" in text:
        raise GitCredentialError(f"credential field {field!r} must be a single line")
    return text


def fetch_attune_key(ref: str) -> Any:
    """Retrieve and decrypt an Attune Key value through the execution SDK client."""
    if not isinstance(ref, str) or not ref or "\x00" in ref:
        raise GitCredentialError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise GitCredentialError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client, decrypt=True)
    except Exception as exc:
        raise GitCredentialError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise GitCredentialError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise GitCredentialError(f"credential Key lookup failed with status {status}")
    try:
        data = response.parsed.data
        if data.encrypted is not True:
            raise GitCredentialError("credential Key must be encrypted")
        return data.value
    except AttributeError as exc:
        raise GitCredentialError("credential Key response was invalid") from exc


def _credential_value(value: Any) -> Any:
    if isinstance(value, Mapping) or isinstance(value, str):
        return value
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "data") and hasattr(value.data, "value"):
        return value.data.value
    return value


def load_credentials(value: Any = None, *, credential_key: str | None = None) -> Credential | None:
    """Validate a credential object, JSON string, or optional Attune Key reference."""
    if value is not None and credential_key is not None:
        raise GitCredentialError("specify credentials or credential_key, not both")
    if credential_key is not None:
        value = fetch_attune_key(credential_key)
    if value is None:
        return None
    if isinstance(value, Credential):
        return value
    value = _credential_value(value)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise GitCredentialError("credential Key must contain a JSON object") from exc
    if not isinstance(value, Mapping):
        raise GitCredentialError("credentials must be an object")

    credential_type = value.get("type")
    if credential_type not in _CREDENTIAL_FIELDS:
        raise GitCredentialError("unsupported credential type")
    unexpected = set(value) - _CREDENTIAL_FIELDS[credential_type]
    if unexpected:
        raise GitCredentialError("credentials contain unsupported fields")

    if credential_type == "https_basic":
        return Credential(
            type=credential_type,
            host=_single_line(value.get("host"), "host").lower(),
            username=_single_line(value.get("username"), "username"),
            secret=_single_line(value.get("password"), "password"),
        )
    if credential_type == "https_token":
        return Credential(
            type=credential_type,
            host=_single_line(value.get("host"), "host").lower(),
            username=_single_line(value.get("username"), "username"),
            secret=_single_line(value.get("token"), "token"),
        )
    return Credential(
        type=credential_type,
        host=_single_line(value.get("host"), "host").lower(),
        private_key=_required_text(value.get("private_key"), "private_key"),
        passphrase=_optional_text(value.get("passphrase"), "passphrase"),
        known_hosts=_optional_text(value.get("known_hosts"), "known_hosts"),
    )


def validate_remote(remote: str, credentials: Credential | None = None) -> Remote:
    """Classify a supported Git location and enforce credential transport matching."""
    if not isinstance(remote, str) or not remote or "\x00" in remote or "\n" in remote or "\r" in remote:
        raise GitCredentialError("remote must be a non-empty single-line string")
    if remote.startswith("-"):
        raise GitCredentialError("remote must not begin with an option prefix")

    if _WINDOWS_PATH.match(remote):
        transport = "local"
        hostname = None
    elif remote.startswith(("/", "./", "../", "~/")):
        transport = "local"
        hostname = None
    elif "://" in remote:
        try:
            parsed = urlsplit(remote)
            hostname = parsed.hostname
            parsed.port
        except ValueError as exc:
            raise GitCredentialError("remote URL is invalid") from exc
        if parsed.scheme == "https" and hostname:
            if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
                raise GitCredentialError("HTTPS remote URLs must not contain embedded userinfo")
            transport = "https"
        elif parsed.scheme == "ssh" and hostname:
            if parsed.password is not None:
                raise GitCredentialError("SSH remote URLs must not contain embedded passwords")
            transport = "ssh"
        else:
            raise GitCredentialError("unsupported or unsafe remote transport")
    elif "::" in remote or _URL_SCHEME.match(remote):
        raise GitCredentialError("unsupported or unsafe remote transport")
    elif _SCP_REMOTE.fullmatch(remote):
        transport = "ssh"
        hostname = _SCP_REMOTE.fullmatch(remote).group("host").strip("[]")
    else:
        transport = "local"
        hostname = None

    if credentials is not None:
        expected = "https" if credentials.type.startswith("https_") else "ssh"
        if transport != expected:
            raise GitCredentialError(f"{credentials.type} credentials require a {expected.upper()} remote")
        endpoint = hostname.lower() if hostname is not None else None
        if endpoint is not None and "//" in remote:
            parsed_port = urlsplit(remote).port
            if parsed_port is not None:
                endpoint = f"{endpoint}:{parsed_port}"
        if endpoint != credentials.host:
            raise GitCredentialError("credential host does not match the remote host")
    return Remote(value=remote, transport=transport)


def _git_environment(source: Mapping[str, str] | None = None, *, isolate_credentials: bool = False) -> dict[str, str]:
    env = dict(os.environ if source is None else source)
    if isolate_credentials:
        blocked = {
            "GIT_ASKPASS",
            "GIT_CONFIG_PARAMETERS",
            "GIT_HTTP_EXTRA_HEADER",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
            "SSH_AUTH_SOCK",
        }
        for name in list(env):
            if name in blocked or name == "GIT_CONFIG_COUNT" or name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
                env.pop(name, None)
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.pop("ATTUNE_API_TOKEN", None)
    return env


def _write(path: Path, content: str, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


class GitCredentialSession:
    """A temporary, transport-bound Git authentication environment."""

    def __init__(
        self,
        remote: str,
        credentials: Any = None,
        *,
        credential_key: str | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.credential = load_credentials(credentials, credential_key=credential_key)
        self.remote = validate_remote(remote, self.credential)
        self._source_environment = environ
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.env: dict[str, str] | None = None
        self.config_args: list[str] = ["-c", "core.hooksPath=/dev/null"]

    def __enter__(self) -> GitCredentialSession:
        self.env = _git_environment(
            self._source_environment,
            isolate_credentials=self.credential is not None,
        )
        if self.credential is None:
            return self
        self._temporary = tempfile.TemporaryDirectory(prefix="attune-git-")
        root = Path(self._temporary.name)
        try:
            if self.remote.transport == "https":
                self._configure_https(root)
            else:
                self._configure_ssh(root)
        except Exception:
            self.close()
            raise
        return self

    def _configure_https(self, root: Path) -> None:
        assert self.credential and self.credential.username is not None and self.credential.secret is not None
        _write(root / "username", self.credential.username, 0o600)
        _write(root / "secret", self.credential.secret, 0o600)
        askpass = root / "askpass"
        _write(
            askpass,
            "#!/bin/sh\n"
            "base=${0%/*}\n"
            "case $1 in\n"
            "  *Username*) exec cat \"$base/username\" ;;\n"
            "  *Password*) exec cat \"$base/secret\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            0o700,
        )
        assert self.env is not None
        self.env["GIT_ASKPASS"] = str(askpass)
        self.config_args.extend(["-c", "credential.helper=", "-c", f"core.askPass={askpass}"])

    def _configure_ssh(self, root: Path) -> None:
        assert self.credential and self.credential.private_key is not None
        key = root / "identity"
        _write(key, self.credential.private_key, 0o600)
        options = [
            "-i", str(key),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
        ]
        if self.credential.known_hosts is not None:
            known_hosts = root / "known_hosts"
            _write(known_hosts, self.credential.known_hosts, 0o600)
            options.extend(["-o", f"UserKnownHostsFile={known_hosts}"])
        wrapper = root / "ssh"
        command = " ".join(shlex.quote(item) for item in ["ssh", *options])
        _write(wrapper, f"#!/bin/sh\nexec {command} \"$@\"\n", 0o700)
        assert self.env is not None
        self.env.pop("SSH_AUTH_SOCK", None)
        self.config_args.extend(["-c", f"core.sshCommand={wrapper}"])
        if self.credential.passphrase is not None:
            _write(root / "passphrase", self.credential.passphrase, 0o600)
            askpass = root / "askpass"
            _write(askpass, "#!/bin/sh\nbase=${0%/*}\nexec cat \"$base/passphrase\"\n", 0o700)
            self.env["SSH_ASKPASS"] = str(askpass)
            self.env["SSH_ASKPASS_REQUIRE"] = "force"
            self.env.setdefault("DISPLAY", ":0")

    def command(self, args: Sequence[str]) -> list[str]:
        if self.env is None:
            raise GitCredentialError("credential session is not active")
        return ["git", *self.config_args, *_validate_args(args)]

    def run(self, args: Sequence[str], *, timeout: float = 120, cwd: str | os.PathLike[str] | None = None) -> str:
        if self.env is None:
            raise GitCredentialError("credential session is not active")
        return run_process(self.command(args), timeout=timeout, cwd=cwd, env=self.env).stdout.strip()

    def close(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self.env = None
        self.config_args = ["-c", "core.hooksPath=/dev/null"]

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def git_credentials(
    remote: str,
    credentials: Any = None,
    *,
    credential_key: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> GitCredentialSession:
    return GitCredentialSession(remote, credentials, credential_key=credential_key, environ=environ)


def _validate_args(args: Sequence[str]) -> list[str]:
    if isinstance(args, (str, bytes)) or not args:
        raise GitCredentialError("Git arguments must be a non-empty sequence")
    result = []
    for value in args:
        if not isinstance(value, str) or "\x00" in value:
            raise GitCredentialError("Git arguments must be strings without null bytes")
        result.append(value)
    return result


def _descendant_pids(root_pid: int) -> set[int]:
    parents: dict[int, int] = {}
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return set()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            parents[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in descendants and (parent == root_pid or parent in descendants):
                descendants.add(pid)
                changed = True
    return descendants


def _terminate_process(process: subprocess.Popen[str]) -> None:
    descendants = _descendant_pids(process.pid)
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_process(
    args: Sequence[str],
    *,
    timeout: float = 120,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    allowed_exit_codes: set[int] | None = None,
) -> ProcessResult:
    """Run without interactive input and terminate the process tree on timeout."""
    command = _validate_args(args)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3600:
        raise GitCredentialError("timeout must be a number from 1 to 3600 seconds")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise GitCredentialError("Git process could not be started") from exc
    try:
        stdout, stderr = process.communicate(timeout=float(timeout))
    except subprocess.TimeoutExpired as exc:
        _terminate_process(process)
        try:
            process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        raise GitCredentialError("Git operation timed out") from exc
    allowed = {0} if allowed_exit_codes is None else allowed_exit_codes
    if process.returncode not in allowed:
        raise GitCredentialError(f"Git operation failed with exit code {process.returncode}")
    return ProcessResult(stdout=stdout, stderr=stderr, returncode=process.returncode)


def run_git(
    args: Sequence[str],
    *,
    session: GitCredentialSession | None = None,
    timeout: float = 120,
    cwd: str | os.PathLike[str] | None = None,
    allowed_exit_codes: set[int] | None = None,
) -> str:
    """Run Git with an active credential session, or a sanitized default environment."""
    if session is not None:
        return session.run(args, timeout=timeout, cwd=cwd)
    command = ["git", "-c", "core.hooksPath=/dev/null", *_validate_args(args)]
    return run_process(
        command,
        timeout=timeout,
        cwd=cwd,
        env=_git_environment(),
        allowed_exit_codes=allowed_exit_codes,
    ).stdout.strip()
