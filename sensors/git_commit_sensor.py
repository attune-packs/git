#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import attune

from git_credentials import run_git, validate_remote


TRIGGER_REF = "git.head_sha_monitor"


def _required_string(values: dict[str, Any], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _timeout(values: dict[str, Any]) -> int:
    value = values.get("timeout_seconds", 120)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3600:
        raise ValueError("timeout_seconds must be an integer from 1 to 3600")
    return value


def _run(args: list[str], timeout: int, cwd: Path | None = None) -> str:
    if not args or args[0] != "git":
        raise RuntimeError("invalid Git command")
    return run_git(args[1:], timeout=timeout, cwd=cwd)


def _paths(rule_id: int, repository_url: str, branch: str) -> tuple[Path, Path]:
    root = Path(os.environ["ATTUNE_ARTIFACTS_DIR"]) / "git_commit_sensor"
    digest = hashlib.sha256(f"{rule_id}\0{repository_url}\0{branch}".encode()).hexdigest()[:24]
    return root / "repositories" / digest, root / "checkpoints" / f"{digest}.json"


def _iso8601(epoch: str) -> str:
    return dt.datetime.fromtimestamp(int(epoch), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def inspect_head(repo: Path, repository_url: str, branch: str, timeout: int) -> dict[str, Any]:
    fields = "%H%x00%an%x00%ae%x00%at%x00%ai%x00%cn%x00%ce%x00%ct%x00%ci%x00%B"
    values = _run(["git", "show", "-s", f"--format={fields}", "HEAD"], timeout, repo).split("\0", 9)
    if len(values) != 10:
        raise RuntimeError("unexpected git commit metadata")
    author_offset = _offset_seconds(values[4])
    committer_offset = _offset_seconds(values[8])
    return {
        "revision": values[0],
        "author": values[1],
        "author_email": values[2],
        "authored_date": _iso8601(values[3]),
        "author_tz_offset": author_offset,
        "committer": values[5],
        "committer_email": values[6],
        "committed_date": _iso8601(values[7]),
        "committer_tz_offset": committer_offset,
        "commit_message": values[9].rstrip("\n"),
        "branch": branch,
        "repository_url": repository_url,
    }


def _offset_seconds(value: str) -> int:
    suffix = value.rsplit(" ", 1)[-1]
    sign = -1 if suffix.startswith("-") else 1
    return sign * (int(suffix[1:3]) * 3600 + int(suffix[3:5]) * 60)


def update_repository(repo: Path, repository_url: str, branch: str, timeout: int) -> None:
    repo.parent.mkdir(parents=True, exist_ok=True)
    if not (repo / ".git").is_dir():
        if repo.exists():
            raise RuntimeError("sensor repository path exists but is not a Git clone")
        _run(["git", "clone", "--branch", branch, "--single-branch", "--", repository_url, str(repo)], timeout)
        return
    _run(["git", "fetch", "origin", f"refs/heads/{branch}"], timeout, repo)
    _run(["git", "checkout", "-B", branch, "FETCH_HEAD"], timeout, repo)


def read_checkpoint(path: Path) -> str | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        raise RuntimeError("sensor checkpoint is unreadable")
    revision = value.get("revision") if isinstance(value, dict) else None
    if not isinstance(revision, str) or not revision:
        raise RuntimeError("sensor checkpoint is invalid")
    return revision


def write_checkpoint(path: Path, revision: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"revision": revision}) + "\n", encoding="utf-8")
    temporary.replace(path)


class GitCommitSensor(attune.PollingSensor):
    interval = 30.0

    def poll(self, rule: Any) -> None:
        values = rule.trigger_params
        repository_url = _required_string(values, "repository_url")
        remote = validate_remote(repository_url)
        if remote.transport == "local":
            raise ValueError("repository_url must use HTTPS or SSH")
        branch = values.get("branch", "master")
        if not isinstance(branch, str) or not branch:
            raise ValueError("branch must be a non-empty string")
        timeout = _timeout(values)
        _run(["git", "check-ref-format", "--branch", branch], min(timeout, 10))
        repo, checkpoint = _paths(rule.id, repository_url, branch)
        update_repository(repo, repository_url, branch, timeout)
        payload = inspect_head(repo, repository_url, branch, timeout)
        previous = read_checkpoint(checkpoint)
        if previous == payload["revision"]:
            return
        if previous is not None or values.get("emit_initial", True):
            self.emit(payload, rule=rule)
        write_checkpoint(checkpoint, payload["revision"])


if __name__ == "__main__":
    attune.run_sensor(GitCommitSensor)
