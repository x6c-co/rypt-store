# rypt-store

rypt-store is an open-source, self-hosted secrets manager for homelabs, small
teams, and agencies that host secrets for several clients. It covers the core
of a secrets platform with no paid tier and no feature gates:

- secrets per environment, with versions, restore, soft delete, and a Compare
  grid that shows which environments share a value without revealing any
- `.env` import and export, a CLI, and `rypt-store run` to start a process
  with its secrets
- service tokens scoped to one project, a set of environments, and an expiry
- local accounts with TOTP, passkeys, and recovery codes; owner, admin,
  member, and viewer roles; several tenants on one instance
- a hash-chained audit log that you can verify and export
- a key hierarchy wrapped by a key on the server's disk, or by
  [rypt.dev](https://rypt.dev), with a one-command migration between them

The server, the web interface, and the CLI ship as one binary. Data lives in
[rqlite](https://rqlite.io).

## Quick start

```sh
cd deploy
docker compose up -d
docker compose logs rypt-store   # copy the setup token from the delimited block
```

Open <https://localhost>, accept the self-signed certificate, and enter the
setup token. The wizard creates the first admin, enrolls their authenticator
app, and creates the first tenant. The token is valid for 24 hours; restart
the server to print a new one.

For a public hostname with a Let's Encrypt certificate, copy
`deploy/.env.example` to `deploy/.env` and set `RYPT_STORE_TLS_DOMAINS` and
`RYPT_STORE_TLS_ACME_EMAIL`. Ports 80 and 443 must reach the host.

## The CLI

```sh
rypt-store login --server https://secrets.example.com   # approve in the browser
rypt-store init                                         # writes .rypt-store.yaml
rypt-store secrets set DATABASE_URL --from-stdin < url.txt
rypt-store secrets get DATABASE_URL --plain
rypt-store secrets list
rypt-store import .env
rypt-store export --format shell
rypt-store run -- ./server                              # secrets in the child's environment
```

`.rypt-store.yaml` holds the server, tenant, project, and default environment.
It contains no credentials and is safe to commit. The CLI session is stored in
your user config directory with mode 0600. `--tenant`, `--project`, `--env`,
and `--server` override the context file, and every command accepts
`--output json`.

In CI, set `RYPT_STORE_TOKEN` to a service token. It takes precedence over a
CLI session, and its scope fixes the tenant and project:

```sh
rypt-store tokens create --name ci --env prod --permission read --expires 90d
RYPT_STORE_TOKEN=rst_... RYPT_STORE_SERVER=https://secrets.example.com rypt-store run --env prod -- make deploy
```

`rypt-store run` adds the secrets to the current environment (they override
existing variables unless you pass `--keep-existing`), forwards SIGINT,
SIGTERM, and SIGHUP to the child, exits with the child's exit code, and never
writes values to disk.

Against a server with a self-signed certificate, pass
`--ca-file /path/to/self-signed.crt` (the server logs the path; in compose it
is `/data/tls/self-signed.crt` in the `rypt-store-data` volume).

## Configuration

Configuration is one YAML file (`rypt-store server --config FILE`, or
`RYPT_STORE_CONFIG`). Every value can be overridden by an environment variable
named after its path: `keys.provider` becomes `RYPT_STORE_KEYS_PROVIDER`. Keep
secrets such as `rypt.token`, `database.password`, and DNS provider
credentials in environment variables. `deploy/config.example.yaml` lists
every setting with its default.

Shipped defaults: the `local` key provider, key mode B, `fail_closed` when
rypt.dev is unreachable, MFA required, and the last 20 versions of each secret
kept.

## Keys

Every secret version is encrypted with AES-256-GCM under its own data key
(DEK). The DEK is wrapped according to the project's key mode, and the top of
the chain is wrapped by the key provider:

| Mode | Chain | rypt.dev operations |
|---|---|---|
| A | provider → root key → project key → DEK → value | one unwrap per root-key cache miss |
| B | provider → project key → DEK → value | one unwrap per project-key cache miss |
| C | provider → DEK → value | one unwrap per secret version per cache miss, and one wrap per write |

The **local** provider wraps keys with a key-encryption key in
`data_dir/local.kek` (or `RYPT_STORE_LOCAL_KEK`). The **rypt** provider wraps
them with a key held in rypt.dev's cloud KMS, so a copy of the database and the
server's disk is not enough to read secrets. Unwrapped keys are cached in
memory for `keys.cache_ttl`. With `rypt.outage_policy: serve_cached`, cached
keys keep working for up to `rypt.max_stale` while rypt.dev is unreachable.

### Moving from local keys to rypt.dev

1. Create a key in the rypt.dev dashboard and an API token for it.
2. Set `RYPT_STORE_RYPT_TOKEN`, `RYPT_STORE_RYPT_KEY_ID`, and
   `RYPT_STORE_KEYS_PROVIDER=rypt`, then restart the server.
3. Run `rypt-store keys migrate --to rypt --dry-run` to see how many rypt.dev
   operations the move will spend, then `rypt-store keys migrate --to rypt`.

Secret values are not re-encrypted; only wraps move. Each project moves
atomically, and an interrupted migration resumes from where it stopped. Keep
`local.kek` until `keys.retired_wrap_retention` (7 days by default) has
passed: until then the old wraps still reference it, the server refuses to
start without it, and you can roll back by setting `keys.provider` back to
`local`, restarting, and migrating `--to local`.

`rypt-store keys migrate --project api --mode C` changes one project's key
mode, and `rypt-store keys rotate` rewraps every rypt wrap under the key's
current version. Both accept `--dry-run`.

## TLS

The server terminates TLS itself (TLS 1.2 or later):

- `tls.mode: acme` obtains and renews certificates for `tls.domains` with
  CertMagic, from Let's Encrypt or any ACME directory (`tls.acme.ca`, for
  example step-ca). The challenge is `http`, `tls-alpn`, or `dns`. DNS-01
  supports Cloudflare (`CLOUDFLARE_API_TOKEN`), Route 53 (the AWS SDK's
  credential chain, `AWS_REGION`), DigitalOcean (`DIGITALOCEAN_API_TOKEN`),
  Hetzner (`HETZNER_API_TOKEN`), and Porkbun (`PORKBUN_API_KEY`,
  `PORKBUN_API_SECRET_KEY`).
- `tls.mode: files` serves `tls.cert_file` and `tls.key_file` and reloads them
  on SIGHUP or when either file changes.
- With neither configured, the server generates a self-signed certificate for
  `tls.domains`, `localhost`, and its own addresses, and the web interface
  shows a notice.

The HTTP listener (`server.http_listen`) answers ACME challenges and redirects
everything else to HTTPS.

## Audit log

Every security-relevant action, including every read of a secret value, is
written to an append-only audit log in the same database batch as the change it
records. Events are hash-chained, with one chain per tenant and one for the
instance:

```sh
rypt-store audit verify            # OK <seq> <hash>, or the first broken link
rypt-store audit verify --instance
rypt-store audit export -o audit.jsonl
```

`audit.retention_days` prunes old events and keeps the last deleted event's
hash as the anchor that verification starts from.

## Backup

Back up both:

- the database, through rqlite's backup API, for example
  `docker compose exec rqlite wget -qO- http://localhost:4001/db/backup > rypt-store.sqlite`
  (restore with rqlite's `/db/load` endpoint); and
- the `/data` volume of the rypt-store container, which holds `local.kek`,
  certificates, and ACME account data.

**With the local provider, losing `local.kek` makes every secret
unrecoverable.** Store a copy of it apart from the database backups. With the
rypt provider, the rypt.dev key protects the hierarchy instead; keep the key,
and do not schedule it for deletion while any wrap uses it.

## Metrics and health

- `GET /healthz`: the process is alive.
- `GET /readyz`: the database and the key provider are reachable.
- `/metrics` on `metrics.listen` (default `127.0.0.1:9090`): Prometheus
  metrics, including `rypt_store_provider_ops_total{provider,op,result}`.

## Development

Requirements: Go 1.27, Node 24 or later, and `make tools`, which downloads
`rqlited` into `.tools/` for the integration tests. Without it, integration
tests use Docker through testcontainers, or skip with a message.

```sh
make tools            # download rqlited
make test             # go test ./...
make test-race
make generate         # regenerate server stubs and web types from api/openapi.yaml
make check-generated  # fail when generated code is stale
make build            # web/dist, then bin/rypt-store with the SPA embedded
make e2e              # Playwright against a fresh server (npx playwright install chromium first)
make vuln             # govulncheck
```

`api/openapi.yaml` is the source of truth for the API: the Go server stubs,
the CLI's client, and the web client's types are generated from it.

The specifications are in [`docs/`](docs): `00-core.md` and
`01-environment-secrets.md` (they refer to the folder as `spec/`).
[`docs/GAPS.md`](docs/GAPS.md) records where the build differs from them and
what this repository could not verify.

## License

MIT. See [LICENSE](LICENSE).
