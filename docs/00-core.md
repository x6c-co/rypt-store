# rypt-store — Core Specification

Status: draft 01, 2026-10-16.
Audience: Claude Code, building rypt-store from an empty repository.
Companion files: `spec/01-environment-secrets.md` (first feature). Each later feature gets its own `spec/NN-<feature>.md`.

## 1. Purpose

rypt-store is an open-source, self-hosted secrets manager. rypt-store offers the core features of Infisical, an open-source secrets management platform, with no paid tier and no feature gating.

rypt-store exists to drive adoption of rypt.dev. rypt.dev is a hosted symmetric encryption API that wraps and unwraps data keys under keys held in a cloud KMS. rypt-store uses rypt.dev to protect its key hierarchy. rypt-store also runs without rypt.dev in a local-only mode, and offers a one-command migration from local-only mode to rypt.dev.

The target audience is the self-hosted community: homelab operators, small teams, and small agencies hosting secrets for several clients.

## 2. Decisions

| # | Topic | Decision |
|---|---|---|
| D1 | Name | `rypt-store`. Lowercase in all copy, matching the rypt.dev brand rule. |
| D2 | License | MIT. |
| D3 | Backend language | Go. The rypt.dev client is the `github.com/x6c-co/rypt` module. |
| D4 | Database | rqlite first, behind a storage interface. Queries use SQL accepted by both SQLite and PostgreSQL. |
| D5 | Frontend | React with TypeScript, built with Vite, served as a static SPA embedded in the Go binary. |
| D6 | Packaging | One binary. `rypt-store server` runs the server. Other subcommands are the CLI client. |
| D7 | Tenancy | Multi-tenant schema with a single-tenant default. Every tenant-owned row carries `tenant_id`. The UI hides tenant switching until a user belongs to more than one tenant. |
| D8 | Hierarchy | Tenant → Project → Environment. |
| D9 | User auth | Local accounts: password plus TOTP or WebAuthn passkeys. Authentication sits behind an interface so OIDC can be added later. |
| D10 | Machine auth | Static service tokens scoped to one project and a set of environments, with an expiry. Machine auth sits behind the same interface so machine identities and workload identity federation can be added later. |
| D11 | Authorization | Fixed tenant-level roles: owner, admin, member, viewer. |
| D12 | Key provider | `local` or `rypt`, set instance-wide in the config file. |
| D13 | Key mode | A (root key), B (per-project key), or C (per-secret-version key). The instance config sets a default. Each project can override the default. |
| D14 | Re-wrap | v1 supports both provider changes and key mode changes. Every re-wrap is atomic per project. |
| D15 | rypt outage policy | Operator chooses `serve_cached` or `fail_closed`. |
| D16 | rypt credentials | One rypt API token and one rypt key ID per instance, from the config file or environment variables. Keys are created in the rypt.dev dashboard. |
| D17 | Audit log | Append-only and hash-chained, one chain per tenant plus one instance chain. Retention is configurable. |
| D18 | Secret versions | The last N versions are kept per secret. N is configurable. |
| D19 | API | REST under `/api/v1`. The OpenAPI 3.1 document is the source of truth. Server stubs are generated with oapi-codegen. |
| D20 | TLS | The server terminates TLS. CertMagic manages ACME certificates. User-supplied certificate files are accepted. A self-signed certificate is generated when neither is configured. |
| D21 | Bootstrap | The server prints a one-time setup token to the logs on first start. The setup wizard requires the token. |
| D22 | Compose | One rqlite node plus the rypt-store server. |
| D23 | Spec layout | This core file plus one file per feature. |

## 3. Defaults chosen during drafting

These defaults were not discussed. Each default is reversible before the build starts.

| # | Topic | Default |
|---|---|---|
| X1 | Go module path | `github.com/x6c-co/rypt-store`. |
| X2 | rqlite client | `github.com/rqlite/rqlite-go-http`, the official thin HTTP client from the rqlite project, pinned to a commit in `go.mod`. The upstream README warns of breaking changes. |
| X3 | Cipher | AES-256-GCM from the Go standard library, 96-bit random nonce per encryption. |
| X4 | Password hashing | Argon2id via `golang.org/x/crypto/argon2`. |
| X5 | TOTP | `github.com/pquerna/otp`. |
| X6 | WebAuthn | `github.com/go-webauthn/webauthn`. |
| X7 | Authorization code | Plain Go behind one function, `authz.Can(principal, action, resource)`. The single entry point lets Cerbos replace the implementation later. |
| X8 | CLI user login | Browser-approved device flow modeled on RFC 8628. |
| X9 | Frontend libraries | React Router for routing, TanStack Query for server state, Radix UI primitives for accessible dialogs and menus, `openapi-typescript` plus `openapi-fetch` for a typed API client, plain CSS with custom properties. |
| X10 | Fonts | Libre Franklin and IBM Plex Mono, matching the rypt.dev brand kit, bundled into the binary. No font CDN. |
| X11 | Config | One YAML file. Environment variables prefixed `RYPT_STORE_` override file values. |
| X12 | Secret names | Secret names are stored in plaintext. Secret values are encrypted. |
| X13 | Metrics | Prometheus endpoint at `/metrics`, including a counter of rypt.dev operations. |
| X14 | DNS-01 providers | Cloudflare, Route 53, DigitalOcean, Hetzner, and Porkbun libdns providers are compiled in. Other providers are added by build tag. |
| X15 | Shipped defaults | `keys.provider: local`, `keys.default_mode: B`, `rypt.outage_policy: fail_closed`, `auth.require_mfa: true`, `secrets.versions_kept: 20`. |
| X16 | Value comparison | The Compare grid uses an HMAC of each value under a per-project key derived from the IK, so equality is computed without decrypting values (feature 01, 2.3). |

## 4. Architecture

### 4.1 Process layout

The `rypt-store server` process contains:

- the HTTP server: API, static SPA, health endpoints, metrics;
- the TLS manager (CertMagic);
- the key service, which owns the key hierarchy and the unwrapped-key cache;
- the storage layer (rqlite implementation);
- the audit writer;
- the background job runner (version pruning, audit retention, re-wrap migrations, session expiry).

v1 supports one server process per database. Section 8.3 describes the guard that makes concurrent audit writers safe anyway.

### 4.2 Repository layout

```
cmd/rypt-store/          main; cobra-style subcommands (server + CLI)
internal/server/         HTTP wiring, middleware, embedded SPA
internal/api/            generated oapi-codegen code + handler implementations
internal/authn/          authenticators (session, service token; later OIDC, machine identity)
internal/authz/          roles, actions, Can()
internal/keys/           key hierarchy, providers, cache, re-wrap migrations
internal/keys/provider/  local and rypt providers
internal/secrets/        secret and version domain logic
internal/audit/          event model, hash chain, verify, export, retention
internal/store/          storage interface
internal/store/rqlite/   rqlite implementation
internal/store/migrate/  schema migrations (embedded SQL files)
internal/tlsmgr/         CertMagic, file certs, self-signed
internal/config/         config loading
internal/cli/            CLI client commands
api/openapi.yaml         OpenAPI source of truth
web/                     React app (Vite)
deploy/                  docker-compose.yml, .env.example, config.example.yaml
spec/                    these specification files
```

### 4.3 Storage interface

The storage interface exposes domain operations, not generic transactions. rqlite executes transactions only as a single batch of statements, so a read-then-write transaction is not available. Every operation that must be atomic is expressed as one batch of write statements.

Rules:

- Each atomic unit is one call on the storage interface, for example `CreateSecretVersion(ctx, version, auditEvent)`.
- The rqlite implementation sends each atomic unit as one batch request with the `transaction` flag set.
- Conflicts are detected with UNIQUE constraints and conditional `UPDATE ... WHERE` clauses, not with locks held across round trips.
- A future PostgreSQL implementation wraps the same unit in a database transaction.
- Schema migrations are numbered SQL files embedded in the binary and applied at start-up. The migration table is `schema_migrations`.
- IDs are UUIDv7 strings. Timestamps are RFC 3339 UTC strings in TEXT columns, so ordering works in both SQLite and PostgreSQL.
- Booleans are INTEGER 0/1. JSON columns are TEXT.
- Writes use rqlite's default strong write path. Reads that feed security decisions (sessions, tokens, key wraps) use rqlite's `strong` read consistency. Listing reads use `weak` consistency.

## 5. Key hierarchy

### 5.1 Terms

- **Provider**: the component that wraps the top-level key. The provider is `local` or `rypt`.
- **Instance key (IK)**: one 256-bit key per instance, always wrapped directly by the provider. The IK encrypts instance-level data (TOTP secrets) and derives per-project comparison keys (feature 01) through HKDF-SHA256. The IK is created at first start.
- **Root key (RK)**: one 256-bit key per instance. The RK exists only when at least one project uses mode A.
- **Project key (PK)**: one 256-bit key per project, used in modes A and B.
- **Data encryption key (DEK)**: one 256-bit key per secret version. Every secret value is encrypted under its own DEK.
- **Wrap**: encryption of one key under another key or under the provider.

### 5.2 Modes

| Mode | Chain | rypt.dev operations |
|---|---|---|
| A | provider → RK → PK → DEK → value | One unwrap per RK cache miss. |
| B | provider → PK → DEK → value | One unwrap per project per PK cache miss. |
| C | provider → DEK → value | One unwrap per secret version per DEK cache miss, plus one wrap per secret write. |

Under the `local` provider, all three modes cost nothing external. The mode still applies, so a later provider change to `rypt` keeps the chosen mode.

The instance default mode is `keys.default_mode` in the config. A project's mode is chosen at project creation and stored in `projects.key_mode`. Changing a project's mode later is a re-wrap migration (5.7).

### 5.3 Providers

The provider interface:

```go
type Provider interface {
    Name() string                                    // "local" or "rypt"
    Wrap(ctx context.Context, plaintextKey []byte, aad []byte) (WrappedKey, error)
    Unwrap(ctx context.Context, w WrappedKey, aad []byte) ([]byte, error)
    Rewrap(ctx context.Context, w WrappedKey, aad []byte) (WrappedKey, error) // provider-side rotation
}

type WrappedKey struct {
    Provider   string // "local" | "rypt"
    KeyRef     string // local: KEK fingerprint; rypt: rypt key ID (UUID)
    KeyVersion string // rypt key version when returned by the API; empty for local
    Ciphertext []byte
}
```

**local provider.** The local provider holds a 256-bit key-encryption key (KEK). The KEK comes from `keys.local.kek_file` (raw 32 bytes, mode 0600) or from `RYPT_STORE_LOCAL_KEK` (base64). When neither exists on first start, the server generates the KEK file in the data directory and logs its path. Wrap uses AES-256-GCM. `KeyRef` is the first 16 hex characters of the SHA-256 of the KEK, so a wrong KEK is detected before decryption.

**rypt provider.** The rypt provider calls the `github.com/x6c-co/rypt` module. Claude Code must read the module's exported API before implementing the adapter and map Wrap, Unwrap, and Rewrap to the module's envelope operations. When the module accepts AAD, the adapter passes the AAD from 5.5. When the module does not accept AAD, the adapter stops and reports the gap instead of dropping the binding silently. The adapter reads the token from `rypt.token` / `RYPT_STORE_RYPT_TOKEN` and the key ID from `rypt.key_id` / `RYPT_STORE_RYPT_KEY_ID`. The adapter records the rypt request ID from each response in the audit event for that operation, when the module exposes the request ID.

Every provider call increments the Prometheus counter `rypt_store_provider_ops_total{provider,op,result}`.

### 5.4 Wrapped key storage

Table `key_wraps` holds every wrapped key. One logical key can have several wraps during a migration.

| Column | Meaning |
|---|---|
| `id` | UUIDv7. |
| `key_id` | Logical key ID (IK, RK, PK, or DEK). |
| `key_kind` | `instance`, `root`, `project`, `dek`. |
| `tenant_id` | NULL for the IK and RK. |
| `project_id` | NULL for the IK and RK. |
| `wrapper_kind` | `provider`, `root`, `project`. |
| `wrapper_ref` | Provider name and KeyRef, or the wrapping key's `key_id`. |
| `key_version` | Provider key version, when present. |
| `ciphertext` | BLOB. Local and parent-key wraps store `nonce || ciphertext || tag`. |
| `state` | `pending`, `active`, `retired`. |
| `created_at` | Timestamp. |

Exactly one wrap per `key_id` is `active`. A partial unique index enforces the rule: `CREATE UNIQUE INDEX ... ON key_wraps(key_id) WHERE state = 'active'`.

### 5.5 Associated data

Every wrap and every value encryption carries AAD that binds the ciphertext to its position in the hierarchy. A ciphertext copied to another row fails authentication.

- IK wrap: `rypt-store/v1/ik/<instance_id>/<ik_id>`
- RK wrap: `rypt-store/v1/rk/<instance_id>/<rk_id>`
- PK wrap: `rypt-store/v1/pk/<tenant_id>/<project_id>/<pk_id>`
- DEK wrap: `rypt-store/v1/dek/<tenant_id>/<project_id>/<dek_id>`
- Secret value: `rypt-store/v1/val/<tenant_id>/<environment_id>/<secret_id>/<version>`

`instance_id` is a UUID generated at first start and stored in table `instance`.

### 5.6 Cache and outage policy

The key service caches the unwrapped IK, RK, PKs, and DEKs in memory.

- Cache entries live for `keys.cache_ttl` (default 15m). Expired entries are re-unwrapped on next use.
- Key material is held in `[]byte`, never in `string`. Eviction overwrites the bytes with `clear()` before release.
- Key material never appears in logs, errors, panics, or `fmt` output. Key-holding types implement `String()`, `GoString()`, and `Format()` to print a redaction marker.
- The cache size is bounded by `keys.cache_max_entries` (default 10000). Eviction is least-recently-used.

`rypt.outage_policy` controls behavior when the rypt provider returns a network error or a 5xx:

- `fail_closed` (default): any operation that needs an unwrap fails with HTTP 503 and the error code `key_provider_unavailable`.
- `serve_cached`: expired cache entries continue to serve for up to `rypt.max_stale` (default 24h) past expiry while the provider is unreachable. Each stale use is counted in `rypt_store_stale_key_uses_total`. Writes that need a provider wrap (mode C) still fail with 503.

A 4xx from rypt.dev (bad token, key not found, quota exceeded) is never treated as an outage. A 429 surfaces to the caller as HTTP 503 with the code `key_provider_quota`, and the UI shows a banner naming the rypt.dev quota.

### 5.7 Re-wrap migrations

A re-wrap migration changes the provider or a project's key mode without re-encrypting secret values. Secret values stay encrypted under their DEKs. Only the wraps change.

Migration kinds:

- `provider`: every top-level wrap (`wrapper_kind = provider`), including the IK, moves to the new provider. The IK moves first, as its own unit of work, before any project. The new provider must be configured before the migration starts. Example: `local` → `rypt`.
- `mode`: one project moves between modes A, B, and C.
- `rotate`: every rypt wrap is rewrapped to the current rypt key version through `Provider.Rewrap`.

Procedure for each project, as one unit of work:

1. Load the project's active wraps.
2. Compute the new wraps. Mode changes create or discard a PK as needed. A → B: unwrap PK under RK and wrap PK under the provider. B → C: unwrap each DEK under PK and wrap each DEK under the provider; the PK is retired. C → B: generate a PK, wrap the PK under the provider, and wrap each DEK under the PK.
3. Insert the new wraps with `state = pending`.
4. Verify: unwrap every pending wrap and compare the result to the original key in constant time. Any mismatch aborts the project and deletes the pending rows.
5. Flip: one batch sets old active wraps to `retired`, sets pending wraps to `active`, updates `projects.key_mode` when the mode changed, and appends the audit event.
6. Evict the project's cache entries.

Retired wraps are deleted after `keys.retired_wrap_retention` (default 7d). Until deletion, an operator can roll back by running the reverse migration.

Migrations run as background jobs recorded in table `key_migrations` (`id`, `kind`, `params` JSON, `state`, `projects_total`, `projects_done`, `error`, `started_by`, timestamps). A job resumes from the first unfinished project after a restart. A failed project marks the job `failed` and leaves every finished project in its new state.

`--dry-run` reports the number of provider operations the migration will spend, by project, before anything changes. The estimate matters under the rypt.dev free tier, which has a hard operation cap.

Provider loading rules:

- The server loads every provider whose configuration is present: the local provider when a KEK is available, and the rypt provider when a token and key ID are set.
- `keys.provider` names the provider used for new wraps.
- Unwrap dispatches on `WrappedKey.Provider`, so existing local wraps stay readable after `keys.provider` changes to `rypt`.
- The server refuses to start when any active or retired wrap references a provider whose configuration is absent. The error message names the provider and the count of affected wraps.

Operator procedure for `local` → `rypt`: add the rypt token and key ID, set `keys.provider: rypt`, restart, run `rypt-store keys migrate --to rypt`. The local KEK file can be removed after the retired wraps are deleted (`keys.retired_wrap_retention`). The Settings page shows the count of wraps still referencing each provider.

## 6. Tenancy and data model

### 6.1 Entities

- **Instance**: the deployment. Has one `instance_id`, one provider, a default key mode, and instance admins.
- **User**: global to the instance. A user belongs to zero or more tenants through memberships.
- **Tenant**: owns projects, memberships, service tokens, and an audit chain.
- **Project**: belongs to one tenant. Has a key mode.
- **Environment**: belongs to one project. Has a name, a slug, and a sort position. New projects start with `dev`, `staging`, and `prod`.
- **Secret** and **secret version**: defined in `spec/01-environment-secrets.md`.

### 6.2 Core tables

Feature files add their own tables. Core tables:

- `instance` (`id`, `created_at`, `setup_completed_at`)
- `users` (`id`, `email` UNIQUE, `display_name`, `password_hash`, `is_instance_admin`, `disabled_at`, `created_at`, `updated_at`)
- `user_totp` (`user_id` PK, `secret_ciphertext`, `confirmed_at`). The TOTP secret is encrypted with AES-256-GCM under the IK (5.1), with AAD `rypt-store/v1/totp/<user_id>`.
- `user_recovery_codes` (`id`, `user_id`, `code_hash`, `used_at`)
- `webauthn_credentials` (`id`, `user_id`, `credential_id` UNIQUE, `public_key`, `sign_count`, `transports`, `name`, `created_at`, `last_used_at`)
- `sessions` (`id_hash` PK, `user_id`, `kind` `web`|`cli`, `mfa_satisfied`, `created_at`, `expires_at`, `last_seen_at`, `ip`, `user_agent`)
- `device_auth_requests` (`device_code_hash`, `user_code`, `user_id`, `state`, `expires_at`)
- `tenants` (`id`, `name`, `slug` UNIQUE, `created_at`, `deleted_at`)
- `tenant_memberships` (`tenant_id`, `user_id`, `role`, `created_at`; PK `tenant_id, user_id`)
- `invitations` (`id`, `tenant_id`, `email`, `role`, `token_hash`, `expires_at`, `accepted_at`)
- `projects` (`id`, `tenant_id`, `name`, `slug`, `key_mode`, `created_at`, `deleted_at`; UNIQUE `tenant_id, slug`)
- `environments` (`id`, `tenant_id`, `project_id`, `name`, `slug`, `position`, `created_at`; UNIQUE `project_id, slug`)
- `service_tokens`: defined in `spec/01-environment-secrets.md`.
- `key_wraps`, `key_migrations`: section 5.
- `audit_events`, `audit_chains`: section 8.
- `jobs` (`id`, `kind`, `state`, `run_after`, `attempts`, `last_error`, timestamps)

Every query on a tenant-owned table filters by `tenant_id`. The storage interface takes `tenantID` as an explicit argument on every tenant-scoped method. Tests assert that a principal from tenant X receives 404 for every object in tenant Y.

### 6.3 Tenant UI rule

The setup wizard creates one tenant named after the organization field. The tenant switcher appears only when the signed-in user belongs to two or more tenants. Instance admins create additional tenants from instance settings.

## 7. Authentication and authorization

### 7.1 Principals

```go
type Principal struct {
    Kind     PrincipalKind // user | service_token (later: machine_identity)
    ID       string
    TenantID string        // the tenant in scope for this request
    Role     Role          // users only
    Scope    *TokenScope   // service tokens only
}

type Authenticator interface {
    // Authenticate returns (nil, nil) when the request carries no credential of this kind.
    Authenticate(r *http.Request) (*Principal, error)
}
```

The middleware runs authenticators in order: session cookie, bearer service token, bearer CLI session token. The first non-nil principal wins. Later features register new authenticators (OIDC login, machine identities, workload identity federation) without changing handlers.

The tenant in scope comes from the URL path (`/api/v1/tenants/{tenant}/...`). A user principal must hold a membership in that tenant. A service token principal is bound to one tenant and one project, and any other path returns 404.

### 7.2 Local accounts

- Passwords: Argon2id, parameters `m=64MiB, t=3, p=2`, 16-byte salt, stored in PHC string format. Minimum length 12. No composition rules. Maximum length 1024.
- MFA: TOTP (RFC 6238, 30-second step, SHA-1, 6 digits for authenticator-app compatibility) and WebAuthn passkeys. A user can enroll both. Ten single-use recovery codes are issued at first MFA enrollment and stored as Argon2id hashes.
- MFA enforcement: `auth.require_mfa` (default `true`). A user without MFA who signs in under the requirement can reach only the MFA enrollment flow.
- Login rate limit: 10 failed attempts per account per 15 minutes and 30 failed attempts per source IP per 15 minutes. Exceeding the limit returns 429. Every failure is audited.
- Password reset: an instance admin or tenant owner generates a one-time reset link (valid 1h) and delivers the link out of band. v1 sends no email.

### 7.3 Sessions

- Web sessions use an opaque 256-bit random token in a cookie: `__Host-rypt_store_session`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.
- The database stores the SHA-256 of the token, never the token.
- Idle timeout: `auth.session_idle` (default 12h). Absolute lifetime: `auth.session_max` (default 7d).
- State-changing requests from the SPA must carry the header `X-Rypt-Store-Request: 1`. The server rejects cookie-authenticated mutations without the header. The header plus `SameSite=Strict` is the CSRF defense.
- Users can list and revoke their own sessions.

### 7.4 CLI login

`rypt-store login --server <url>` runs a device flow:

1. The CLI requests a device code and a short user code.
2. The CLI prints the user code and the approval URL.
3. The user opens the URL in a signed-in browser, confirms the user code, and approves.
4. The CLI polls and receives a CLI session token (`rsc_` prefix), stored in the CLI config file with mode 0600.

CLI sessions use the same `sessions` table with `kind = cli` and their own lifetime, `auth.cli_session_max` (default 30d).

### 7.5 Roles

| Action | Constant | owner | admin | member | viewer |
|---|---|---|---|---|---|
| Read secret values | `secret.read` | ✓ | ✓ | ✓ | ✓ |
| Create, update, delete secrets; restore versions | `secret.write` | ✓ | ✓ | ✓ | |
| Create, rename, delete projects and environments | `project.manage` | ✓ | ✓ | | |
| Change a project's key mode | `project.key_mode` | ✓ | ✓ | | |
| Create and revoke service tokens | `token.manage` | ✓ | ✓ | | |
| Invite and remove members; change roles below own | `member.manage` | ✓ | ✓ | | |
| View and export the tenant audit log | `audit.read` | ✓ | ✓ | | |
| Change owner role; delete tenant | `tenant.own` | ✓ | | | |

Instance admins additionally manage tenants, instance settings, provider migrations, and the instance audit chain. Instance admin status does not grant access to a tenant's secrets without a membership.

Every handler calls `authz.Can(principal, action, resource)` before acting. Actions are string constants (`secret.read`, `secret.write`, `project.manage`, ...). A table-driven test covers every action for every role.

## 8. Audit log

### 8.1 Events

Every security-relevant action writes one audit event in the same storage batch as the change it records. Event fields:

| Field | Meaning |
|---|---|
| `id` | UUIDv7. |
| `chain_id` | Tenant ID, or `instance` for instance-level events. |
| `seq` | Gapless integer per chain, starting at 1. |
| `ts` | RFC 3339 UTC with milliseconds. |
| `actor_kind` | `user`, `service_token`, `system`. |
| `actor_id` | Principal ID. |
| `action` | Dotted name, e.g. `secret.read`, `secret.update`, `auth.login.failed`, `keys.migration.flip`. |
| `target_kind`, `target_id` | The object acted on. |
| `project_id`, `environment_id` | When applicable. |
| `result` | `success` or `denied` or `error`. |
| `ip`, `user_agent`, `request_id` | Request context. |
| `provider_request_id` | rypt.dev request ID, when a provider call occurred. |
| `metadata` | JSON object. Never contains secret values, key material, tokens, or password data. |
| `prev_hash` | Hex SHA-256 of the previous event in the chain, or 64 zeros for `seq = 1`. |
| `hash` | Hex SHA-256 of `prev_hash` concatenated with the canonical JSON of every other field. |

Canonical JSON: keys sorted, no insignificant whitespace, UTF-8, timestamps as strings, `metadata` canonicalized recursively.

Events written: login success and failure, MFA enrollment and removal, session revocation, secret reads (value fetches, including bulk export), secret writes, deletes, and restores, version pruning (summary event per job run), service token creation, revocation, and denied use, membership and role changes, project and environment changes, key mode changes, migration start, flip, and completion, provider outage transitions, setup completion, and audit retention pruning.

Listing secret names does not write an event. Fetching values does.

### 8.2 Head hash

Table `audit_chains` (`chain_id` PK, `head_seq`, `head_hash`, `anchor_seq`, `anchor_hash`, `updated_at`) holds each chain's head. The UI shows the head hash and sequence on the audit page. API responses for audit endpoints include the head in the response body.

### 8.3 Concurrency guard

The writer computes `seq` and `prev_hash` from `audit_chains`, then sends one batch:

1. `UPDATE audit_chains SET head_seq = :seq, head_hash = :hash WHERE chain_id = :chain AND head_seq = :seq - 1`
2. `INSERT INTO audit_events (...)` with UNIQUE `(chain_id, seq)`
3. The domain change being recorded.

When the insert violates the UNIQUE constraint, the whole batch fails. The writer re-reads the head and retries up to 5 times. Within one process, a per-chain mutex prevents most retries. The guard makes multiple writers safe even though v1 runs one process.

### 8.4 Verification and export

- `rypt-store audit verify [--tenant <slug>|--instance]` walks a chain from its anchor, recomputes every hash, and reports the first broken link or `OK <seq> <hash>`.
- `GET /api/v1/tenants/{tenant}/audit/verify` runs the same check server-side.
- Export: `GET /api/v1/tenants/{tenant}/audit/export?from=&to=` streams JSON Lines, one event per line, including `prev_hash` and `hash`. `rypt-store audit export` wraps the endpoint.

### 8.5 Retention

`audit.retention_days` (default 0, meaning keep forever). The retention job deletes events older than the retention window and records the last deleted event's `seq` and `hash` as the new anchor in `audit_chains`. Verification starts from the anchor. The job writes an `audit.pruned` event naming the deleted range and the anchor hash.

## 9. API

- The OpenAPI 3.1 document `api/openapi.yaml` is the source of truth. `oapi-codegen` (v2, `std-http` server with strict handlers) generates Go types and server interfaces into `internal/api/gen`. `go generate ./...` regenerates the code. CI fails when generated code is stale.
- The frontend's typed client is generated from the same document with `openapi-typescript`.
- Base path: `/api/v1`. Tenant-scoped resources live under `/api/v1/tenants/{tenant}`. `{tenant}`, `{project}`, and `{environment}` accept slugs.
- Errors use RFC 9457 `application/problem+json` with a stable `code` extension field. Example codes: `not_found`, `forbidden`, `validation_failed`, `conflict`, `key_provider_unavailable`, `key_provider_quota`, `mfa_required`, `setup_required`.
- Pagination: cursor-based, `?limit=` (default 50, max 500) and `?cursor=`. Responses carry `next_cursor`.
- Every response carries `X-Request-Id`. The server generates the ID when the client does not send one.
- Core endpoints are listed below. Feature files list their own endpoints.

```
GET    /healthz                         liveness; no auth
GET    /readyz                          database + provider reachability; no auth
GET    /metrics                         Prometheus; bound to metrics.listen (default 127.0.0.1:9090)

POST   /api/v1/setup                    complete first-run setup (requires setup token)
GET    /api/v1/setup/status

POST   /api/v1/auth/login               email + password → session or mfa challenge
POST   /api/v1/auth/mfa/totp            verify TOTP
POST   /api/v1/auth/mfa/webauthn/begin
POST   /api/v1/auth/mfa/webauthn/finish
POST   /api/v1/auth/logout
POST   /api/v1/auth/device              CLI device flow start
POST   /api/v1/auth/device/token        CLI polling
POST   /api/v1/auth/device/approve      browser approval (session)
GET    /api/v1/me
GET    /api/v1/me/sessions
DELETE /api/v1/me/sessions/{id}
(MFA enrollment, WebAuthn registration, recovery code endpoints under /api/v1/me/mfa/...)

GET    /api/v1/tenants
POST   /api/v1/tenants                                   instance admin
GET    /api/v1/tenants/{tenant}
GET    /api/v1/tenants/{tenant}/members
POST   /api/v1/tenants/{tenant}/invitations
PATCH  /api/v1/tenants/{tenant}/members/{user}
DELETE /api/v1/tenants/{tenant}/members/{user}

GET    /api/v1/tenants/{tenant}/projects
POST   /api/v1/tenants/{tenant}/projects                 body includes key_mode (optional)
GET    /api/v1/tenants/{tenant}/projects/{project}
PATCH  /api/v1/tenants/{tenant}/projects/{project}
DELETE /api/v1/tenants/{tenant}/projects/{project}
GET    /api/v1/tenants/{tenant}/projects/{project}/environments
POST   /api/v1/tenants/{tenant}/projects/{project}/environments
PATCH  /api/v1/tenants/{tenant}/projects/{project}/environments/{environment}
DELETE /api/v1/tenants/{tenant}/projects/{project}/environments/{environment}

GET    /api/v1/tenants/{tenant}/audit
GET    /api/v1/tenants/{tenant}/audit/export
GET    /api/v1/tenants/{tenant}/audit/verify

GET    /api/v1/instance/settings                         instance admin
GET    /api/v1/instance/audit
GET    /api/v1/instance/keys                             provider, default mode, op counts, cache stats
POST   /api/v1/instance/keys/migrations                  {kind, params, dry_run}
GET    /api/v1/instance/keys/migrations/{id}
```

## 10. First-run setup

1. On start, when `instance.setup_completed_at` is NULL, the server generates a 32-byte setup token, stores its hash, and prints the token to stdout once in a clearly delimited block.
2. Every route except `/healthz`, `/readyz`, the static SPA, and `/api/v1/setup*` returns `setup_required` until setup completes.
3. The SPA shows the setup wizard. The wizard asks for the setup token, admin email, password, and organization name (the first tenant). The wizard shows the provider and the default key mode read-only, as set in the config file.
4. The wizard enrolls MFA for the admin before finishing when `auth.require_mfa` is true.
5. Completion creates the instance admin, the first tenant with the admin as owner, writes the first instance audit event, and invalidates the setup token.
6. The setup token expires after 24h. A restart before completion issues a new token.

## 11. TLS

`tls.mode` selects the certificate source:

- `acme`: CertMagic obtains and renews certificates for `tls.domains`. `tls.acme.email` is required. `tls.acme.ca` defaults to Let's Encrypt production and accepts any ACME directory URL, including Let's Encrypt staging and private ACME CAs such as step-ca (Smallstep's open-source certificate authority). `tls.acme.challenge` is `http`, `tls-alpn`, or `dns`. DNS-01 takes `tls.acme.dns.provider` and provider-specific credentials from environment variables. CertMagic storage is `<data_dir>/certmagic`.
- `files`: `tls.cert_file` and `tls.key_file`. The server reloads the pair on SIGHUP and when either file's modification time changes (checked every 60 seconds).
- `self_signed`: the server generates an ECDSA P-256 certificate for `tls.domains` plus `localhost` and the container's IPs, valid 1 year, stored in `<data_dir>/tls`. The UI shows a persistent notice while self-signed mode is active.

The default when `tls.mode` is unset: `acme` when `tls.domains` and `tls.acme.email` are set, otherwise `self_signed`.

The server listens on `server.https_listen` (default `:8443` in the container, published as 443). `server.http_listen` (default `:8080`, published as 80) serves HTTP-01 challenges and redirects everything else to HTTPS. `server.http_listen: ""` disables the HTTP listener.

TLS settings: minimum TLS 1.2, Go default cipher suites, HSTS `max-age=31536000` when the mode is `acme` or `files`.

## 12. Configuration

Example `deploy/config.example.yaml`:

```yaml
data_dir: /data

server:
  https_listen: ":8443"
  http_listen: ":8080"
  public_url: "https://secrets.example.com"

database:
  driver: rqlite
  url: "http://rqlite:4001"
  username: ""
  password: ""

tls:
  mode: ""              # acme | files | self_signed; empty = auto
  domains: ["secrets.example.com"]
  acme:
    email: ""
    ca: ""              # empty = Let's Encrypt production
    challenge: http     # http | tls-alpn | dns
    dns:
      provider: ""      # cloudflare | route53 | digitalocean | hetzner | porkbun
  cert_file: ""
  key_file: ""

keys:
  provider: local       # local | rypt
  default_mode: B       # A | B | C
  cache_ttl: 15m
  cache_max_entries: 10000
  retired_wrap_retention: 168h
  local:
    kek_file: /data/local.kek

rypt:
  token: ""             # prefer RYPT_STORE_RYPT_TOKEN
  key_id: ""            # rypt key UUID from the rypt.dev dashboard
  outage_policy: fail_closed   # fail_closed | serve_cached
  max_stale: 24h

auth:
  require_mfa: true
  session_idle: 12h
  session_max: 168h
  cli_session_max: 720h

secrets:
  versions_kept: 20

audit:
  retention_days: 0

metrics:
  listen: "127.0.0.1:9090"
```

Environment variables override file values by path: `keys.provider` becomes `RYPT_STORE_KEYS_PROVIDER`. Secrets (`rypt.token`, `database.password`, DNS provider credentials) are documented as environment-variable-only in the README examples.

## 13. Docker Compose

`deploy/docker-compose.yml` starts a working instance with one command:

- Service `rqlite`: the official `rqlite/rqlite` image, one node, data on volume `rqlite-data`, port 4001 not published.
- Service `rypt-store`: the image built from the repository `Dockerfile` (multi-stage: Node build of `web/`, Go build with the SPA embedded, distroless runtime, non-root user). Volume `rypt-store-data` at `/data`. Ports 443:8443 and 80:8080. `depends_on` rqlite with a health check.
- `deploy/.env.example` lists `RYPT_STORE_RYPT_TOKEN`, `RYPT_STORE_RYPT_KEY_ID`, `RYPT_STORE_TLS_DOMAINS`, `RYPT_STORE_TLS_ACME_EMAIL`.
- With no `.env`, `docker compose up` yields a local-provider, self-signed instance reachable at `https://localhost`. The setup token appears in `docker compose logs rypt-store`.

The README documents backup: the rqlite backup API plus the `/data` volume. The README states that losing `local.kek` under the local provider makes every secret unrecoverable.

## 14. Frontend system

Design guidance below follows the frontend-design review. The visual system derives from the rypt.dev brand kit so rypt-store reads as part of the rypt family.

### 14.1 Subject and job

The subject is a secrets manager for self-hosters. The primary job is reading and changing secret values across environments without mistakes. The secondary job is answering "who changed what" from the audit log.

### 14.2 Tokens

Colors come from the rypt.dev brand kit, light and dark:

| Token | Light | Dark | Use |
|---|---|---|---|
| `--paper` | `#F3F2EF` | `#101319` | Page background. |
| `--surface` | `#FFFFFF` | `#181C23` | Tables, panels. |
| `--ink` | `#14181F` | `#ECEAE6` | Primary text. |
| `--ink-2` | `#4B5058` | `#AAB0B9` | Secondary text. |
| `--rule` | `#D9D6D0` | `#2A2F38` | Borders, dividers. |
| `--seal` | `#8A2B3A` | `#D97F89` | Primary action, focus ring, selected state. |
| `--brass` | `#836428` | `#C9A662` | Notices: local-only mode, self-signed TLS, stale keys. |
| `--crit` | `#C0392B` | `#E8705F` | Destructive actions, errors. |

Type: Libre Franklin for interface text. IBM Plex Mono for secret names, secret values, token prefixes, hashes, and IDs. Monospace marks data that users copy into code, so the monospace face carries meaning here. Both families are SIL Open Font License fonts and are bundled as WOFF2 files.

Theme follows `prefers-color-scheme`, with a manual override stored in `localStorage`.

### 14.3 Layout

```
┌──────────────┬──────────────────────────────────────────────┐
│ rypt-store   │ project-name                    [Add secret] │
│              │ ┌─────────┬──────┬──────────┬──────┐        │
│ [tenant ▾]*  │ │ Compare │ dev  │ staging  │ prod │        │
│              │ └─────────┴──────┴──────────┴──────┘        │
│ Projects     │                                              │
│  api         │  NAME            dev     staging   prod      │
│  web         │  DATABASE_URL    ●       ●         ●≠        │
│  billing     │  STRIPE_KEY      ●       ●         —         │
│              │  LOG_LEVEL       ●       ●=dev     ●         │
│ Audit log    │                                              │
│ Settings     │                                              │
└──────────────┴──────────────────────────────────────────────┘
* tenant switcher appears only with 2+ tenants
```

- Left sidebar: product name, tenant switcher (conditional), project list, audit log, settings. The sidebar collapses to a top drawer under 860px width.
- The project view opens on the Compare grid. The grid's rows are secret names, and its columns are environments. A cell shows set, missing (`—`), or equal-to-another-environment, computed server-side from keyed value MACs (feature 01, 2.3) so values never reach the browser for comparison. The Compare grid is the product's one distinctive element. Every other screen stays plain.
- An environment tab lists that environment's secrets with masked values. Reveal, copy, edit, and history are per-row actions. Reveal fetches the value on demand and audits the read. A revealed value re-masks after 30 seconds.
- Audit log: a dense table with filters (actor, action, project, time range), the chain head hash shown at the top, and a Verify button that calls the verify endpoint.
- Settings (instance admin): provider, default key mode, rypt.dev operation counts for the current UTC month (counted locally), migrations with progress, TLS mode.

### 14.4 Behavior and copy

- Copy is plain, sentence case, and names user concepts: "Add secret", "Reveal", "Revoke token". The button label and the confirmation toast use the same verb.
- Destructive actions (delete secret, delete environment, revoke token, change key mode) require typing the object's name.
- Local-only mode shows a persistent brass notice in Settings and a dismissible one in the sidebar: "Keys are stored on this server's disk. Move them to rypt.dev with `rypt-store keys migrate --to rypt`."
- Empty states state the next action: "No secrets in prod. Add one, or import a .env file."
- The quality floor is mandatory: keyboard navigation for every action, visible focus rings in `--seal`, `prefers-reduced-motion` respected, WCAG AA contrast, and usable layouts down to 360px width.
- Motion is limited to responses to user actions: row expand, dialog open, toast.

## 15. Security requirements

- Secret values, key material, tokens, and passwords never appear in logs. The logger uses `log/slog` with a redacting handler. Request and response bodies are never logged.
- Responses carrying secret values set `Cache-Control: no-store`.
- Security headers on every response: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Constant-time comparison for every token and hash comparison.
- `govulncheck` and `go test -race` run in CI.

## 16. Testing

- Unit tests for every package. Table-driven authz tests for every action and role.
- Integration tests start rqlite with `testcontainers-go` (a Go library that runs Docker containers for tests) and run against a fake rypt provider that counts calls and can inject 5xx, 429, and timeouts.
- Key hierarchy tests cover every provider and mode pair, every migration transition (A↔B, B↔C, A↔C, local→rypt, rotate), failure injection at each migration step, and restart mid-migration.
- Tenant isolation tests: every endpoint returns 404 for cross-tenant IDs.
- Audit tests: chain verification, tamper detection (modified field, deleted row, reordered rows), concurrent writers, retention anchoring.
- Frontend: Vitest for logic and Playwright for the setup wizard, login with TOTP, and the add-reveal-edit-history flow.

## 17. Build order

1. Repository skeleton, config, logging, storage interface, rqlite implementation, schema migrations.
2. Key service: local provider, modes A/B/C, cache, AAD. The rypt provider adapter follows once the module API is mapped.
3. Audit writer, hash chain, verify.
4. Setup flow, local accounts, sessions, MFA, authz.
5. Tenants, projects, environments.
6. Feature 01 (`spec/01-environment-secrets.md`).
7. TLS manager.
8. Frontend shell, setup wizard, login, settings.
9. Re-wrap migrations and the migration UI.
10. Docker image, compose file, README.

Each step ends with passing tests and a commit.
