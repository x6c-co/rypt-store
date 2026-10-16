# rypt-store — Feature 01: Environment Secrets

Status: draft 01, 2026-10-16.
Depends on: `spec/00-core.md`. Every term, table, and rule in the core spec applies here.

## 1. Scope

Feature 01 delivers:

- key/value secrets per environment;
- secret versioning with last-N retention and restore;
- soft delete with a restore window;
- the Compare grid across environments;
- `.env` import and export;
- service tokens;
- the CLI client commands for secrets;
- the UI for all of the above.

Out of scope for feature 01, each planned as its own feature file: folders and paths, secret references and imports between environments, secret rotation, dynamic secrets, secret syncs to external targets, approval workflows, the Kubernetes operator, PKI and SSH certificates, secret scanning.

## 2. Data model

### 2.1 `secrets`

| Column | Meaning |
|---|---|
| `id` | UUIDv7. |
| `tenant_id`, `project_id`, `environment_id` | Owner. |
| `name` | Matches `^[A-Za-z_][A-Za-z0-9_]{0,255}$`. Case-sensitive. |
| `comment` | Optional plaintext note, max 1024 characters. The UI states that comments are not encrypted. |
| `current_version` | Integer, the latest version number. |
| `created_at`, `updated_at` | Timestamps. |
| `deleted_at` | NULL unless soft-deleted. |

Index: `CREATE UNIQUE INDEX ... ON secrets(environment_id, name) WHERE deleted_at IS NULL`.

### 2.2 `secret_versions`

| Column | Meaning |
|---|---|
| `id` | UUIDv7. |
| `tenant_id`, `secret_id` | Owner. |
| `version` | Integer starting at 1. UNIQUE `(secret_id, version)`. |
| `dek_id` | Logical key ID of this version's DEK. The DEK's wrap lives in `key_wraps`. |
| `ciphertext` | BLOB: `nonce || ciphertext || tag`, AES-256-GCM under the DEK, AAD per core 5.5. |
| `value_mac` | BLOB: HMAC-SHA256 of the plaintext value under the project comparison key (2.3). |
| `created_by_kind`, `created_by_id` | Principal. |
| `created_at` | Timestamp. |
| `restored_from` | Version number when the version was created by a restore, else NULL. |

Values are UTF-8 text, multi-line allowed, max 64 KiB. Empty values are allowed.

### 2.3 Comparison key

The project comparison key is `HKDF-SHA256(IK, salt = project_id, info = "rypt-store/v1/compare")`. `value_mac` lets the server compute equality across environments without decrypting values. A stolen database without the IK does not allow offline guessing of values from `value_mac`.

The comparison key depends only on the IK, so key mode changes do not touch `value_mac`. A provider migration does not change the IK's bytes, only its wrap.

### 2.4 `service_tokens`

| Column | Meaning |
|---|---|
| `id` | UUIDv7. |
| `tenant_id`, `project_id` | Scope. |
| `name` | Human label, unique per project. |
| `token_hash` | SHA-256 of the secret part. |
| `token_prefix` | First 8 characters of the secret part, for display. |
| `permission` | `read` or `read_write`. |
| `expires_at` | Required. Max `tokens.max_ttl` (default 365d) from creation. |
| `created_by`, `created_at` | Creator. |
| `last_used_at` | Updated at most once per minute per token. |
| `revoked_at` | NULL unless revoked. |

Table `service_token_environments` (`token_id`, `environment_id`) holds the environments a token can reach. A token reaches at least one environment.

Token format: `rst_<id>_<secret>`. `<id>` is the token's UUID in Crockford base32. `<secret>` is 32 random bytes in Crockford base32. The full token is shown once at creation.

### 2.5 Config additions

```yaml
secrets:
  versions_kept: 20          # core D18
  deleted_retention: 720h    # soft-deleted secrets purge after 30 days
tokens:
  max_ttl: 8760h
```

## 3. Operations

### 3.1 Create and update

A write creates a new version. The request carries the expected `current_version` (0 for create) as the `If-Match` header value. A mismatch returns 409 `conflict`.

Steps:

1. Authorize `secret.write` on the environment.
2. Generate a 256-bit DEK.
3. Encrypt the value under the DEK with the value AAD.
4. Wrap the DEK per the project's key mode: under the PK in modes A and B, or under the provider in mode C.
5. Compute `value_mac`.
6. Send one storage batch: insert `secret_versions`, insert the DEK's `key_wraps` row, `UPDATE secrets SET current_version = :new WHERE id = :id AND current_version = :expected` (or insert the `secrets` row on create), and the audit event.
7. A zero-row update returns 409.
8. Enqueue a prune job for the secret when its version count exceeds `versions_kept`.

### 3.2 Read

Authorize `secret.read`. Load the current version, unwrap the DEK through the cache, decrypt, and write a `secret.read` audit event. Responses carrying values set `Cache-Control: no-store`.

A bulk read (environment export, CLI `run`) writes one `secret.read.bulk` audit event listing the secret IDs, rather than one event per secret.

Under mode C, a cold-cache bulk read of N secrets costs N provider unwraps. The settings page and the project key-mode selector state the per-read cost of each mode.

### 3.3 Version history and restore

- History lists versions with number, author, timestamp, and `restored_from`. History does not include values.
- Fetching one old version's value is a `secret.read` with the version number in the audit metadata.
- Restore decrypts the old version and writes its value as a new version with `restored_from` set. Restore uses a fresh DEK.

### 3.4 Version pruning

The prune job keeps the newest `versions_kept` versions of each secret. Pruning deletes the old version rows and their DEK wraps in one batch. Deleting the DEK wrap makes the old ciphertext unrecoverable. The job writes one `secret.versions.pruned` audit event per run with per-secret counts.

### 3.5 Delete and restore deleted

- Delete sets `deleted_at` and writes `secret.delete`. Versions and wraps remain.
- Deleted secrets appear in a "Recently deleted" list per environment.
- Restore clears `deleted_at`. Restore fails with 409 when an active secret already uses the name.
- The purge job deletes secrets whose `deleted_at` is older than `deleted_retention`, with all versions and DEK wraps, and writes `secret.purge`.

### 3.6 Compare

`GET .../projects/{project}/compare` returns one row per secret name present in any environment. Each row holds, per environment, `missing` or a `group` label. Environments whose current values share a `value_mac` within the row share a group label. Group labels are small integers assigned per row and carry no information outside the row. The response contains no values and no MACs.

### 3.7 Import and export

- Import: `POST .../environments/{environment}/secrets/import` takes a `.env` body (`text/plain`) and a `mode` of `skip_existing` or `overwrite`. The parser follows common dotenv rules: `KEY=value`, optional `export ` prefix, single and double quotes, `\n` escapes inside double quotes, multi-line values inside double quotes, and `#` comments. The response lists created, updated, skipped, and rejected names with reasons. Each changed secret gets a version. The audit log records one `secret.import` event plus one write event per changed secret.
- Export: `GET .../environments/{environment}/secrets/export?format=dotenv|json` returns every current value. Export is a bulk read.

### 3.8 Service tokens

- Creation requires `token.manage`. The request names the project, environments, permission, expiry, and label.
- Authentication: the bearer authenticator parses the token, looks up the row by `<id>`, and compares the SHA-256 of `<secret>` in constant time. Revoked, expired, or unknown tokens return 401 and write `token.denied`.
- A token principal can call only the secret endpoints of its project, only for its environments, and only writes when the permission is `read_write`. Other paths return 404.
- Revocation sets `revoked_at` immediately.

## 4. API

All paths are under `/api/v1/tenants/{tenant}/projects/{project}`.

```
GET    /compare
GET    /environments/{environment}/secrets                    names, comments, versions, timestamps; no values
POST   /environments/{environment}/secrets                    create {name, value, comment}
GET    /environments/{environment}/secrets/{name}             includes value
PUT    /environments/{environment}/secrets/{name}             update {value, comment}; If-Match required
DELETE /environments/{environment}/secrets/{name}
GET    /environments/{environment}/secrets/{name}/versions
GET    /environments/{environment}/secrets/{name}/versions/{version}   includes value
POST   /environments/{environment}/secrets/{name}/versions/{version}/restore
GET    /environments/{environment}/secrets/deleted
POST   /environments/{environment}/secrets/deleted/{id}/restore
POST   /environments/{environment}/secrets/import
GET    /environments/{environment}/secrets/export
GET    /environments/{environment}/secrets/values             bulk read for CLI run/export; JSON map

GET    /tokens
POST   /tokens                                                returns the full token once
DELETE /tokens/{id}                                           revoke
```

Secret responses include `ETag: "<current_version>"`.

## 5. CLI

The CLI is the same binary as the server (core D6).

### 5.1 Configuration and context

- User config: `<os.UserConfigDir()>/rypt-store/config.yaml`, mode 0600. Holds server URL, CLI session token, and the last-used tenant.
- Project context: `.rypt-store.yaml` in the working directory or any parent. Holds `server`, `tenant`, `project`, and `environment` (default environment). `rypt-store init` writes the file interactively. The file contains no credentials and is safe to commit.
- Credential precedence: the `RYPT_STORE_TOKEN` environment variable (a service token) wins over the CLI session token. The service token's own scope then fixes tenant and project.
- Flags `--tenant`, `--project`, `--env`, and `--server` override the context file.

### 5.2 Commands

```
rypt-store login [--server URL]          device flow (core 7.4)
rypt-store logout
rypt-store init                          write .rypt-store.yaml
rypt-store secrets list                  names, versions, updated time
rypt-store secrets get NAME [--version N] [--plain]
rypt-store secrets set NAME [--from-file PATH | --from-stdin] [--comment TEXT]
rypt-store secrets set NAME=VALUE        accepted; prints a warning that the value is now in shell history
rypt-store secrets delete NAME
rypt-store secrets history NAME
rypt-store secrets restore NAME --version N
rypt-store import FILE [--overwrite]
rypt-store export [--format dotenv|json|shell]
rypt-store run [--keep-existing] -- COMMAND [ARGS...]
rypt-store tokens list|create|revoke
```

`run` behavior:

- `run` fetches the environment's values in one bulk read.
- `run` starts the command with the secrets added to the current environment. Secrets override existing variables unless `--keep-existing` is set.
- `run` forwards SIGINT, SIGTERM, and SIGHUP to the child, and exits with the child's exit code.
- `run` never writes values to disk.

`get --plain` prints only the value with no trailing newline, for use in scripts. Without `--plain`, output is a small table.

All commands accept `--output json` for machine-readable output.

## 6. UI

Follows core section 14.

- **Compare tab** (project default view): the grid from core 14.3. Clicking a cell opens that environment's secret detail. Missing cells offer "Add to <environment>".
- **Environment tab**: table of name, masked value, version, updated time, updated by. Row actions: Reveal, Copy, Edit, History, Delete. Copy fetches and copies without displaying, and audits the read. Toolbar: Add secret, Import .env, Export, Recently deleted.
- **Secret editor**: a dialog with a monospace multi-line value field, comment field, and Save. The dialog sends `If-Match`. On 409 the dialog states that someone else saved a newer version and offers to reload.
- **History drawer**: version list, per-version Reveal, and Restore with a confirmation that names the version number.
- **Service tokens page** (project settings): list with label, prefix, environments, permission, expiry, last used. Create shows the full token once in a monospace field with a Copy button and the text "This token is shown once."
- **Key mode display**: the project settings page shows the project's key mode and the per-read rypt.dev cost of each mode. Changing the mode starts a mode migration (core 5.7) and shows its progress.

## 7. Audit actions added

`secret.create`, `secret.update`, `secret.read`, `secret.read.bulk`, `secret.delete`, `secret.restore`, `secret.purge`, `secret.version.restore`, `secret.versions.pruned`, `secret.import`, `token.create`, `token.revoke`, `token.denied`.

## 8. Tests

- Create, update with correct and stale `If-Match`, read, history, restore, delete, restore deleted, name reuse after delete.
- Value AAD binding: copying a ciphertext between rows fails decryption.
- Pruning deletes DEK wraps, and pruned versions return 404.
- Compare returns correct groups and never includes values or MACs.
- dotenv import against a fixture set of edge cases: quotes, escapes, multi-line, `export` prefix, comments, invalid names.
- Service token scope: wrong project, wrong environment, write with `read`, expired, revoked.
- Mode C provider-call counts for single and bulk reads, cold and warm cache.
- CLI: `run` signal forwarding and exit code passthrough, credential precedence, `--keep-existing`.
- Playwright: add, reveal, edit, history, restore, import, compare.

## 9. Acceptance criteria

1. On a fresh compose instance, a user completes setup, creates a project, adds secrets to dev and prod, and sees the Compare grid show equal and different values correctly.
2. `rypt-store login`, `rypt-store init`, and `rypt-store run -- env` print the project's secrets in the child environment.
3. A CI job using `RYPT_STORE_TOKEN` with a `read` token reads prod secrets and receives 404 for a write attempt.
4. `rypt-store audit verify` returns OK after the above, and the audit log shows every read and write.
5. After `rypt-store keys migrate --to rypt` and a project mode change from B to C, every secret still reads back unchanged, and the provider-op counter matches the dry-run estimate.
