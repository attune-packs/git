# Git Attune Pack

This pack adapts the Apache-2.0 StackStorm Exchange `git` pack at revision
`e291834ae9f5fda45ae5c089f004a7e9fb631594` for current Attune behavior. Version
0.2.0 adds optional Attune Key-backed authentication to network-capable actions.

## Requirements

- Python 3.10 or newer and the core Python runtime.
- The `git` executable on every selected action and sensor worker.
- Network access from workers to remote repositories.
- A writable `ATTUNE_ARTIFACTS_DIR` for sensor clones and checkpoints.
- Worker placement for repositories or local working trees available only on selected workers.

## Authentication

The network-capable actions `clone`, `checkout_remote_branch`,
`commit_and_push`, `get_remote_repo_latest_commit`, and `remote_branch_exists`
accept an optional `credential_key`. The Key must be encrypted and owned either
by the `git` pack or by the executing action. These actions request only the
reserved `standard` execution permission, which permits scoped reads and
decryption of pack-owned and action-owned Keys; it does not grant arbitrary Key
access.

For a pack-owned Key, create it with a local ref such as `credentials`,
`owner_type: pack`, and `owner_pack_ref: git`. Attune constructs the canonical
ref `pack.git.credentials`, which is the value to pass as `credential_key`.
Action-owned Keys use `owner_action_ref` and canonical refs such as
`action.git.clone.credentials`.

An HTTPS token credential Key has this JSON shape:

```json
{
  "type": "https_token",
  "host": "git.example.invalid",
  "username": "REDACTED_GIT_USERNAME",
  "token": "REDACTED_GIT_ACCESS_TOKEN"
}
```

For password authentication, use `type: https_basic` and replace `token` with
`password`. The lowercase `host` binds the credential to one exact remote
endpoint; include `:port` when the URL uses an explicit non-default port. The
action rejects use against another endpoint.

For HTTPS, Git sends the username and token using HTTP Basic authentication,
with the token in the password position. This is not Bearer-token
authentication. Do not embed a username, password, or token in any repository
URL; pass a clean `https://host/path/repository.git` URL and select the Key with
`credential_key`.

An SSH credential Key has this JSON shape; `passphrase` is optional:

```json
{
  "type": "ssh_private_key",
  "host": "git.example.invalid",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nREDACTED_PRIVATE_KEY\n-----END OPENSSH PRIVATE KEY-----",
  "known_hosts": "git.example.invalid ssh-ed25519 REDACTED_HOST_PUBLIC_KEY",
  "passphrase": "REDACTED_PRIVATE_KEY_PASSPHRASE"
}
```

Host verification remains enabled and the action never accepts unknown hosts
automatically. When `known_hosts` is present, it becomes the isolated host file
for the invocation; otherwise the worker's verified SSH host policy applies.
Include every hostname form used by the repository URL, including a non-default
port form when applicable. Do not put a private key or passphrase in a repository
URL or action parameter.

When `credential_key` is omitted, the action does not fetch a Key. Public
repositories can use anonymous access, and private repositories can fall back
to existing non-interactive authentication on the selected worker, such as an
SSH agent or Git credential helper. Interactive prompting is disabled.

Credential helpers, private keys, known-hosts data, and passphrase helpers are
materialized only in a private temporary directory for the Git invocation and
removed during normal cleanup, including handled failures and timeouts. They
are not written into the repository or pack tree. A process hard kill, worker
crash, or host loss can bypass application cleanup and leave temporary files
until the worker or operating-system temporary-file policy removes them; secure
and isolate the worker's temporary storage accordingly.

The local-only actions `get_local_repo_latest_commit` and `new_local_branch` do
not accept `credential_key` and do not request the `standard` permission.

## Actions

The seven source actions retain their refs and primary inputs. They return
structured JSON and invoke Git with argument arrays rather than interpolated
shell commands. Every operation accepts `timeout_seconds` from 1 to 3600,
defaulting to 120. The timeout applies independently to each Git command, not
to the complete action, so a multi-command action can run longer than this
value. On timeout the current Git process is terminated and the action fails;
an operating-system hard kill cannot guarantee application cleanup or rollback
of remote or local effects already completed.

`checkout_remote_branch` always fetches the repository's configured remote
named `origin`. `commit_and_push` always pushes `branch_to_push` to `origin`.
The other remote lookup actions use the repository URL supplied in their
parameters. `clone` uses `source`, which may be a remote URL or worker-local
path.

`commit_and_push` intentionally fails when there is nothing to commit, matching
the source command chain. It stages all changes below the repository path and
therefore has broad side effects. Commands completed before a later failure or
timeout are not rolled back. Local repository actions operate on the filesystem
of the selected Attune worker, not an implicit StackStorm remote host.

Example flat execution parameters:

```json
{
  "repository": "https://git.example.invalid/example/project.git",
  "branch": "main",
  "credential_key": "pack.git.readonly_credentials",
  "timeout_seconds": 60
}
```

## Commit Sensor

Create one enabled rule per repository branch using trigger
`git.head_sha_monitor`. Trigger parameters are:

- `repository_url`: required non-secret repository location.
- `branch`: branch to monitor, default `master`.
- `emit_initial`: emit current head when no checkpoint exists, default `true`.
- `timeout_seconds`: timeout for each Git command, default 120.

The sensor checks every 30 seconds, uses a rule-targeted event, and stores each
clone and checkpoint below `ATTUNE_ARTIFACTS_DIR/git_commit_sensor`. A checkpoint
is written only after successful event emission. Updates report the latest
observed branch head; multiple commits between polls are not replayed.

Sensor tokens cannot access Attune Keys, so `credential_key` is not available
to the commit sensor. Private repository monitoring requires existing
non-interactive authentication and SSH host verification on the selected sensor
worker. Do not place credentials in `repository_url`.

## Fidelity

| Source | Attune target | Fidelity | Important differences | Follow-up |
|---|---|---|---|---|
| Seven command actions | Seven Python actions with one shared entrypoint | adapted | Structured output, safe argv execution, per-command timeout, optional scoped Key authentication for network actions; worker-local instead of StackStorm remote runner | Configure Keys, worker placement, and fallback Git authentication |
| `GitCommitSensor` | `git.git_commit_sensor` | adapted | One rule per repository, durable checkpoints, artifact-backed clones, UTC timestamps, targeted events; no Key access | Configure existing worker authentication for private repositories |
| Embedded `git.head_sha_monitor` trigger | `git.head_sha_monitor` trigger | adapted | Required fields are explicit and timestamps are corrected to UTC | Update downstream rules to use structured payload fields |
| `config.schema.yaml` repository array | Trigger parameters per enabled rule | adapted | Repository lifecycle follows Attune rule lifecycle rather than pack config reload | Create one rule for each repository branch |
| StackStorm remote runner context | Attune worker placement | manual | No automatic SSH hop or StackStorm runner result envelope | Select workers that own each local worktree |
| GitHub PR merge sample rule | No generated component | partial | It is unrelated to Git commit monitoring and Attune webhook ingress is deployment-specific | Implement only after choosing an ingress trigger and safe destination action |
| Live StackStorm sensor test | Deterministic mocked unit tests | adapted | No external network or StackStorm test framework | Add opt-in integration tests if required |

The source has no workflows, queues, retries, compensation, or action output
schemas. This conversion does not claim equivalent cancellation behavior for a
Git subprocess terminated by different runner implementations.

## Validation

```bash
attune --output json pack check /home/david/Codebase/attune-packs/git
attune pack test /home/david/Codebase/attune-packs/git --detailed
```

The installed CLI may be older than the current source tree. In this workspace,
the equivalent current CLI can be run from the Attune repository with `cargo run`.

## Upstream And License

This is a modified adaptation of the original
[StackStorm Exchange Git pack](https://github.com/StackStorm-Exchange/stackstorm-git).
The upstream Apache License 2.0 is included in [LICENSE](LICENSE), with
attribution and source revision details in [NOTICE](NOTICE).
