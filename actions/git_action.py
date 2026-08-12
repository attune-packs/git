#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from git_credentials import GitCredentialError, git_credentials, run_git, validate_remote


GitActionError = GitCredentialError


def _string(params: dict[str, Any], name: str, default: str | None = None) -> str:
    value = params.get(name, default)
    if not isinstance(value, str) or not value:
        raise GitActionError(f"'{name}' must be a non-empty string")
    if "\x00" in value:
        raise GitActionError(f"'{name}' contains an invalid null byte")
    return value


def _timeout(params: dict[str, Any]) -> int:
    value = params.get("timeout_seconds", 120)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3600:
        raise GitActionError("'timeout_seconds' must be an integer from 1 to 3600")
    return value


def _run(
    args: list[str],
    timeout: int,
    cwd: str | None = None,
    *,
    allowed_exit_codes: set[int] | None = None,
) -> str:
    if not args or args[0] != "git":
        raise GitActionError("Git command is invalid")
    return run_git(args[1:], timeout=timeout, cwd=cwd, allowed_exit_codes=allowed_exit_codes)


def _credential_key(params: dict[str, Any]) -> str | None:
    value = params.get("credential_key")
    if value is None:
        return None
    return _string(params, "credential_key")


def _branch(params: dict[str, Any], name: str, default: str | None = None) -> str:
    value = _string(params, name, default)
    if value.startswith("-"):
        raise GitActionError(f"'{name}' must be a valid branch name")
    _run(["git", "check-ref-format", "--branch", value], 10)
    return value


def _origin(directory: str, timeout: int, *, push: bool = False, isolated: bool = False) -> str:
    if isolated:
        key = "remote.origin.pushurl" if push else "remote.origin.url"
        output = _run(
            ["git", "config", "--local", "--get-all", key],
            timeout,
            directory,
            allowed_exit_codes={0, 1},
        )
        values = [line for line in output.splitlines() if line]
        if push and not values:
            return _origin(directory, timeout, isolated=True)
        if len(values) != 1:
            raise GitActionError("origin must have exactly one repository URL with explicit credentials")
        validate_remote(values[0])
        return values[0]
    args = ["git", "remote", "get-url"]
    if push:
        args.append("--push")
    args.append("origin")
    remote = _run(args, timeout, directory)
    validate_remote(remote)
    return remote


def _reject_local_url_rewrites(directory: str, timeout: int) -> None:
    output = _run(
        ["git", "config", "--local", "--get-regexp", r"^url\..*\.(insteadOf|pushInsteadOf)$"],
        timeout,
        directory,
        allowed_exit_codes={0, 1},
    )
    if output:
        raise GitActionError("repository-local Git URL rewrites are not allowed with explicit credentials")


def _repo_path(params: dict[str, Any], name: str) -> str:
    path = Path(_string(params, name)).expanduser()
    if not path.is_dir():
        raise GitActionError(f"'{name}' must identify an existing directory")
    return str(path)


def execute(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _timeout(params)

    if operation == "clone":
        source = _string(params, "source")
        destination = _string(params, "destination")
        ref = _branch(params, "ref", "master")
        with git_credentials(source, credential_key=_credential_key(params)) as session:
            session.run(["clone", "--branch", ref, "--", source, destination], timeout=timeout)
        revision = _run(["git", "rev-parse", "HEAD"], timeout, destination)
        return {"repository_path": str(Path(destination).resolve()), "revision": revision}

    if operation == "checkout_remote_branch":
        directory = _repo_path(params, "local_repo_directory")
        branch = _branch(params, "remote_branch")
        credential_key = _credential_key(params)
        if credential_key:
            _reject_local_url_rewrites(directory, timeout)
        remote = _origin(directory, timeout, isolated=credential_key is not None)
        with git_credentials(remote, credential_key=credential_key) as session:
            source = remote if credential_key else "origin"
            session.run(["fetch", source, f"refs/heads/{branch}:refs/remotes/origin/{branch}"], timeout=timeout, cwd=directory)
        _run(["git", "checkout", "-B", branch, f"refs/remotes/origin/{branch}"], timeout, directory)
        revision = _run(["git", "rev-parse", "HEAD"], timeout, directory)
        return {"branch": branch, "revision": revision}

    if operation == "commit_and_push":
        directory = _repo_path(params, "local_repo_directory")
        branch = _branch(params, "branch_to_push", "master")
        message = _string(params, "commit_message")
        credential_key = _credential_key(params)
        if credential_key:
            _reject_local_url_rewrites(directory, timeout)
        remote = _origin(directory, timeout, push=True, isolated=credential_key is not None)
        session = git_credentials(remote, credential_key=credential_key)
        _run(["git", "checkout", branch], timeout, directory)
        _run(["git", "add", "--all", "."], timeout, directory)
        _run(["git", "commit", "-m", message], timeout, directory)
        revision = _run(["git", "rev-parse", "HEAD"], timeout, directory)
        with session:
            destination = remote if credential_key else "origin"
            session.run(["push", destination, f"refs/heads/{branch}:refs/heads/{branch}"], timeout=timeout, cwd=directory)
        return {"branch": branch, "revision": revision, "pushed": True}

    if operation == "get_local_repo_latest_commit":
        directory = _repo_path(params, "repo_path")
        branch = _branch(params, "branch", "master")
        revision = _run(["git", "rev-parse", "--verify", branch], timeout, directory)
        return {"branch": branch, "revision": revision}

    if operation in {"get_remote_repo_latest_commit", "remote_branch_exists"}:
        repository_name = "repo_remote" if operation == "get_remote_repo_latest_commit" else "repository"
        repository = _string(params, repository_name)
        branch = _branch(params, "branch", "master")
        with git_credentials(repository, credential_key=_credential_key(params)) as session:
            output = session.run(["ls-remote", "--heads", repository, f"refs/heads/{branch}"], timeout=timeout)
        matches = [line.split()[0] for line in output.splitlines() if line.split()]
        if operation == "remote_branch_exists":
            return {"branch": branch, "exists": bool(matches), "revision": matches[0] if matches else None}
        if len(matches) != 1:
            raise GitActionError("Remote branch was not found or did not resolve uniquely")
        return {"branch": branch, "revision": matches[0]}

    if operation == "new_local_branch":
        directory = _repo_path(params, "local_repo_directory")
        source = _branch(params, "source_branch", "master")
        branch = _branch(params, "new_branch", "patch_1")
        _run(["git", "checkout", "-b", branch, source], timeout, directory)
        revision = _run(["git", "rev-parse", "HEAD"], timeout, directory)
        return {"branch": branch, "source_branch": source, "revision": revision}

    raise GitActionError("Unsupported Git action")


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise GitActionError("Action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        json.dump(execute(operation, params), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("Invalid JSON action parameters", file=sys.stderr)
    except GitActionError as exc:
        print(str(exc), file=sys.stderr)
    except Exception:
        print("Unexpected Git action failure", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
