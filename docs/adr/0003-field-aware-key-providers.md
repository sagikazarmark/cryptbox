---
status: superseded by ADR-0006
---

# Key providers receive the field; a router maps fields to providers

Key providers are asked for keys on behalf of a field:
`current_key(field: FieldId)` and `key(field: FieldId, id: KeyId)`, and the same
for blind-index providers. The crate ships a `Router` provider that maps field
IDs to providers (`Router::strict().route::<Iban>(payments)…`). This replaces the
per-profile `Keys` type. Which KMS protects a field is deployment configuration,
and it can change freely because the envelope records the key ID. Moving keys to
a single application-level provider without field awareness would let one
`iban.encrypt()` silently land under the general key hierarchy.

## Considered Options

- **Key slot on the field** (`#[cryptbox(keys = PaymentsKeys)]`): rejected. It
  puts infrastructure choice into type declarations and creates a second source
  of truth next to the router.
- **Explicit keyring at every call site**: rejected. It is only as safe as every
  caller's discipline, and passing the wrong keyring succeeds without error.

## Consequences

- Routing is by `FieldId`, not Rust type, so two markers with one ID resolve the
  same way.
- `Router::strict()` rejects unrouted fields and is the documented default. A
  fallback router exists but falls back visibly (e.g. in a schema manifest).
- Duplicate or conflicting routes for one field are rejected.
- Simple keyrings ignore the field argument; single-KMS applications see no
  difference.
