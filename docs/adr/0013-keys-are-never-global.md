---
status: accepted
---

# Keys are never global

Every operation takes the keys to use, and nothing reads a process-wide global.
The installed keys (`keys::install`, `keys::installed`, `AlreadyInstalled`,
`Error::KeysNotInstalled`) and the automatic SQLx column they backed, `Plain<F>`,
are removed before the 0.6.0 release. A column is `Sealed<F>`, and the
application seals and opens it with the keys it passes in, as it already does
for records, values with blind indexes, and tenants' values.

[ADR-0004](0004-key-supply-global-and-explicit.md) kept the global because SQLx
`Decode` receives no context, so a column that opens itself has nowhere else to
find keys. By 0.6.0 that column served only standalone values without blind
indexes, and it was the last reader of the global:

- `Plain<F>` over a seal with a blind index compiled and wrote no index, and over
  a record field's seal it compiled and wrote the wrong context
  ([ADR-0012](0012-a-record-is-a-context-layer-over-a-seal.md)). Neither failed
  until a lookup missed or a read reported `ContextMismatch`.
- It was the crate's only ambient state, against
  [ADR-0010](0010-records-carry-their-bound-values.md)'s rule that database
  layers carry only ciphertext and sealing and opening are explicit calls.
- No example used it, and it saved one `open(&keys)` per read.

## Considered Options

- **Keep the global behind the `sqlx-*` features**, as it shipped: rejected. The
  feature gate did not remove either pitfall, and removing the global after a
  release would be breaking, while adding it back is not.
- **Keep `Plain<F>` with keys as a type parameter** (`Plain<F, K>`, ADR-0004's
  original `KeyContext`): rejected for the same pitfalls; a static per key source
  is the global again, one per type.

## Consequences

- 0.5's `Encrypted<T, P>` column becomes `Sealed<P>` with an explicit
  `open(&keys)`; there is no one-to-one replacement.
- A process that wants global keys keeps them itself, such as in a `OnceLock`,
  and passes them on. A `cryptbox-global` crate, or `Plain<F>` again, can be
  added later without a breaking change if a real need appears.
- Tests never share installed keys, so every test runs in parallel with its own
  keyrings.
- [ADR-0004](0004-key-supply-global-and-explicit.md) is superseded.
