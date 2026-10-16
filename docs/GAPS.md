# Implementation gaps and deviations

This file records where the build differs from `00-core.md` and
`01-environment-secrets.md`, and why. Each entry names the spec section.

## rypt.dev module (`github.com/x6c-co/rypt` v0.1.0)

Core 5.3 asks the adapter to map Wrap, Unwrap, and Rewrap to the module's
envelope operations, to pass AAD, and to record request IDs. The module
accepts AAD on `Wrap` and `Unwrap`, so the AAD binding of core 5.5 holds for
rypt wraps. Three gaps remain:

1. **Rewrap costs two operations.** `rypt.Client.Rewrap` is documented for
   ciphertexts made by `Encrypt`, not for wrapped data keys from `Wrap`. The
   adapter does not guess that the formats are interchangeable: its
   `Rewrap` is `Unwrap` followed by `Wrap` under the configured key. A
   `rotate` migration therefore spends two metered operations per wrap, the
   `--dry-run` estimate counts two, and the key passes through the server's
   memory briefly during the rewrap.
2. **No key version.** Successful wrap responses carry no key version, so
   `key_wraps.key_version` stays empty for rypt wraps.
3. **No request ID on success.** The module exposes the request ID only on
   errors (`rypt.Error.RequestID`). Audit events record
   `provider_request_id` for failed provider calls only.
