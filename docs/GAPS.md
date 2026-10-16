# Implementation gaps and deviations

This file records where the build differs from `00-core.md` and
`01-environment-secrets.md`, and what could not be verified in the build
environment. Each entry names the spec section.

## Not verified here

The build machine had no Docker, no ACME certificate authority, and no rypt.dev
credentials.

- **Docker image and compose file (core 13).** The `Dockerfile` and
  `deploy/docker-compose.yml` are written but were not built or run. The image
  tags they use exist, and CI runs `docker compose config` and `docker build`.
- **Feature 01 acceptance criterion 1** names a fresh compose instance. The
  same flow (setup, project, secrets in dev and prod, Compare grid) passes in
  Playwright against the real binary and rqlite, outside compose.
- **Feature 01 acceptance criterion 5** names rypt.dev. It passes against a
  fake rypt provider (`TestKeyMigrationAcceptance`), not the live service. The
  rypt adapter itself is tested against an HTTP server that speaks the rypt
  module's wire format, covering AAD passthrough and error classification.
- **ACME issuance (core 11).** The CertMagic configuration, challenge wiring,
  and DNS provider selection are tested; obtaining a certificate is not.
- **testcontainers (core 16).** Integration tests start a local `rqlited`
  (`make tools`). The testcontainers path is implemented but did not run.

## rypt.dev module (`github.com/x6c-co/rypt` v0.1.0)

Core 5.3 asks the adapter to map Wrap, Unwrap, and Rewrap to the module's
envelope operations, to pass AAD, and to record request IDs. The module accepts
AAD on `Wrap` and `Unwrap`, so the AAD binding of core 5.5 holds for rypt
wraps. Three gaps remain:

1. **Rewrap costs two operations.** `rypt.Client.Rewrap` is documented for
   ciphertexts made by `Encrypt`, not for wrapped data keys from `Wrap`. The
   adapter does not assume the formats are interchangeable: its `Rewrap` is
   `Unwrap` followed by `Wrap` under the configured key. A `rotate` migration
   therefore spends two metered operations per wrap for the rewrap itself, the
   `--dry-run` estimate counts them, and the key passes through the server's
   memory briefly.
2. **No key version.** Successful wrap responses carry no key version, so
   `key_wraps.key_version` stays empty for rypt wraps.
3. **No request ID on success.** The module exposes the request ID only on
   errors (`rypt.Error.RequestID`). Audit events record `provider_request_id`
   for failed provider calls only.

## API additions (core 9, feature 01 4)

The spec lists the core endpoints; the build adds the ones its flows need.
All are in `api/openapi.yaml`:

- `POST /api/v1/setup/totp`: the wizard enrolls the admin's authenticator app
  before setup completes (core 10.4). Passkeys can be added after setup.
- `POST /api/v1/auth/mfa/recovery`: sign in with a recovery code.
- `GET /api/v1/auth/device/requests/{user_code}`: the approval page shows the
  CLI's request.
- `POST /api/v1/auth/password-reset`, `GET` and
  `POST /api/v1/auth/invitations/{token}[/accept]`: the one-time links of core
  7.2 and invitations.
- `PUT /api/v1/me/password`, `GET /api/v1/tenants/{tenant}/invitations`,
  `POST /api/v1/tenants/{tenant}/members/{user}/password-reset`.
- `POST /api/v1/tenants/{tenant}/projects/{project}/key-mode`: tenant owners
  and admins change a project's key mode (`project.key_mode`).
- `GET /api/v1/instance/users`, `POST /api/v1/instance/users/{user}/password-reset`,
  `GET /api/v1/instance/audit/export`, `GET /api/v1/instance/audit/verify`,
  `GET /api/v1/instance/keys/migrations`.
- `GET /api/v1/me` also describes a service token's scope, so the CLI can
  resolve the tenant and project from `RYPT_STORE_TOKEN`.

## Behaviour choices

- **Reserved secret names.** `deleted`, `export`, `import`, and `values` are
  refused as secret names, because `.../secrets/{name}` would collide with the
  fixed paths of feature 01 section 4.
- **Slug and label reuse.** Project slugs are unique among live projects, and
  service token labels among unrevoked tokens (partial unique indexes), so a
  deleted project's slug or a revoked token's label can be reused.
- **Schema additions.** Beyond the spec's columns: `batch_guards` (preconditions
  inside one rqlite batch), `instance.setup_token_*`, `sessions.public_id`
  (revocation without exposing the token hash), `webauthn_credentials.data`
  (the library's full credential record), `key_wraps.retired_at` (the
  retention clock), `password_resets`, and `provider_op_counts` (the Settings
  page's monthly counts).
- **Recovery codes** are Argon2id hashes with lighter parameters than
  passwords (8 MiB, t=1). The codes carry 60 bits of randomness.
- **Migrations.** `keys migrate --to P` requires `keys.provider` to already be
  `P`, following the operator procedure of core 5.7, so new wraps and moved
  wraps land on the same provider. The dry-run estimate counts metered
  (non-local) provider operations, and migrations unwrap source keys directly
  rather than through the cache so that the estimate is exact.
- **Per-process state.** Login rate limits, TOTP replay protection, and
  WebAuthn challenges live in memory, matching v1's one server process per
  database.
- **CLI TLS.** `--ca-file` and `--insecure` (or `RYPT_STORE_CA_FILE` and
  `RYPT_STORE_INSECURE=1`) let the CLI reach a server with a self-signed
  certificate.
- **Canonical JSON (core 8.1)** is produced by Go's `encoding/json` with HTML
  escaping off and keys sorted. Third-party verifiers must match its escaping
  of U+2028, U+2029, and invalid UTF-8.

## Web interface

- **CSP and dialogs.** The required policy, `default-src 'self'`, blocks the
  `<style>` element that Radix dialogs inject to lock page scrolling. Dialogs
  work and trap focus, but the page behind an open dialog can scroll, and the
  browser logs one CSP report per dialog open.
