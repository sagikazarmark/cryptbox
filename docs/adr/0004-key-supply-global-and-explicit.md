---
status: accepted
---

# Keys are supplied globally or explicitly, with no feature gates

> Amended by [ADR-0006](0006-keys-are-passed-in.md). The process-wide keys and the
> automatic column remain only for `FieldOnly` fields. Explicit operations take
> keyrings instead of routed providers.
>
> Amended before the release after 0.5.0: the implicit forms (`seal_global`,
> `open_global`, `with_index()`, `probes()`) are removed. Each saved one
> argument, and their names disagreed on which form took keys. The installed
> keys back only the automatic column; `keys::installed()` returns them to code
> that passes them on.

Every operation has an explicit form that takes keys (`encrypt_with`,
`decrypt_with`, `prepare_with`, …) and is always available. On top of it, a
process-wide `keys::install(Keys)` backs the implicit forms (`encrypt()`,
`decrypt()`). `Keys` holds the encryption and blind-index providers, usually
routers. sqlx `Decode` receives no context, so the auto-encrypting column
type takes its key source as a type parameter:
`Encrypted<F, K = GlobalKeys>`, whose column impls require `K: KeyContext`. A
user can name their own static (a second keyring, a tenant, a test fixture)
instead of the global. Explicit decryption returns the default `K`;
`with_key_context` moves the value into another. Together, the explicit forms
and `K` are the escape hatch from the global.

## Considered Options

- **Feature-gate the global (or the explicit API)**: rejected. Cargo features
  unify across the build, so any dependency enabling `global-keys` turns it on
  for everyone, and a gate can never switch the global off. Gating the explicit
  API would hide the foundation the global is built on. Each gate also adds a
  docs.rs badge, doubles the feature-powerset CI matrix, and cannot be removed
  without a semver break.
- **Thread-local or task-local key scopes** (`with_scoped`): rejected. Code that
  runs outside the scope (`spawn`, `spawn_blocking`, another executor, after an
  `.await` on another thread) silently falls back to the global keys. The
  prototyped thread-local also leaked key material.
- **A key-context hook per field**: rejected. It duplicates the router
  ([ADR-0003](0003-field-aware-key-providers.md)).

## Consequences

- The global fails closed: a second `install` returns `AlreadyInstalled` and
  never replaces, and implicit calls return `KeysNotInstalled` rather than
  falling back or panicking.
- Teams that forbid the global enforce it with clippy `disallowed_methods` on
  `keys::install` and the implicit forms. A separate `cryptbox-global` crate
  remains an option if lint enforcement proves insufficient.
- `KeyContext` survives, but only as the sqlx adapter's key source, not on fields.
