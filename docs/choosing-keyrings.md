# Choosing keyrings

Operations take the keys to use directly, so deciding which keyring protects
which values is application code. That decision is not
cryptographically checked when values are written: this page lists the mistakes
the library cannot detect, the rules that make them loud instead of silent, and
how to test the choice.
[Documentation](README.md) · [Bindings](bindings.md) · [Shredding](shredding.md).

## What the library guarantees, and what it does not

| Property | Who establishes it |
| --- | --- |
| Ciphertext cannot move across seals or records | The library: the binding is in the AAD and the key derivation |
| Opening with the wrong keyring fails loudly | The library, **provided** key IDs follow the [rules below](#key-id-rules) |
| Values of one tenant are sealed under that tenant's keyring | Your code: an unchecked decision at write time |
| A seal's values are sealed under the custody it requires | Your code: never checked |

A keyring, and the `Keys` pair, serve every value passed to them alike. To keep
seals or tenants apart, pass each call the keyring it needs, chosen in one place
in your code.

## Four mistakes that fail silently at write time

Sealing succeeds under any keyring. Each of these is discovered later, or not at
all:

- **Wrong tenant.** Sealing tenant A's data under tenant B's keyring succeeds. It
  surfaces only when A is read with A's keyring, which may be long after the
  write, and the value is then unreadable by the tenant that owns it.
- **Wrong custody.** A seal's values sealed under the wrong key hierarchy — an IBAN
  under the general keyring rather than the payments one — is never detected.
  The data stays readable, so nothing fails; only a review finds it.
- **Shredding.** A value sealed under the wrong tenant's keyring survives the
  destruction of its own tenant's keys, or is destroyed along with another
  tenant's. Both are silent: one leaves
  data that should be gone, the other loses data that should have stayed.
- **Audit.** The library cannot report which keys protect which seal, so
  "which keyring holds this seal's data" is a question only your own records
  answer.

The first two are write-time errors with delayed symptoms, so make them
impossible in one place: resolve keys in a single function of your own rather
than at each call site, and [test that resolution](#test-the-choice).

## Key-ID rules

A key ID is the non-secret name of exact key material, and it is what turns
"opened with the wrong keyring" into a loud failure. An envelope names the key
that sealed it; opening looks up exactly that ID and returns
`Error::UnknownEncryptionKey` when the keyring does not hold it. It never falls
back to the current key.

| Rule | Why |
| --- | --- |
| Generate every ID as a random UUID, as `EncryptionKey::generate` does | Two independently provisioned keyrings then never collide |
| Never reuse an ID for different material | A reused ID makes a wrong key look like the right one, and opening fails as corruption |
| Keep IDs unique within a keyring | `EncryptionKeyring::new` rejects a repeat with `KeyError::DuplicateEncryptionKey` |
| Never share an ID across keyrings | Sharing removes the loud failure: the wrong keyring appears to hold the right key |
| Keep the ID and its bytes together for the life of the data | Replacing a lost key with new material under the same ID cannot recover ciphertext |
| Generate encryption and blind-index roots independently | The roles are separate; one root must never serve both |

Provision each generation once and reload the same pair after restarts. See
[key lifecycle](key-rotation.md) for changing which generation is current.

## Write the custody decision down

Because the library cannot report custody, the mapping has to live where
reviewers and auditors can see it and where a test can check it. Keep, beside
the [manifest snapshot](integration.md#guarding-the-schema-in-ci), a committed
table of one row per seal:

| Seal | Keys per | Custody | Shreddable per |
| --- | --- | --- | --- |
| `CustomerEmail` | `org` | `general` keyring, per org | the org |
| `CustomerIban` | `org` | `payments` keyring, per org | the org |
| `AuditNote` | none | `general` keyring, one process-wide | not shreddable |

Derive that table from the same constant your key resolution reads, so the code
and the review artifact cannot drift, and treat a diff to it as a review gate: a
seal moving between custody labels is a migration of who can read the data, not
a refactor. A seal protected by one process-wide keyring cannot
be shredded on its own; say so explicitly rather than leaving it blank.

## Resolve keys in one place

Resolving keys is synchronous application code and must not do I/O on the
sealing path. Load and refresh keys outside these calls and serve a local
snapshot: a function that takes what the value belongs to, such as its org, and
returns the keyring that protects it, or an error. The
[tenant example](../examples/tenant_field.rs) resolves one keyring per tenant
from a `HashMap<&str, EncryptionKeyring>` in three lines, and passes it to
each call.

Cloning a keyring shares its keys rather than copying material, which is what
makes refreshing simple:

- **Hand one out from behind a lock** or from a swapped snapshot. Operations
  already in flight keep the keyring they were handed, so a refresh never
  changes the keys of a call that has started. The
  [custom-field example](../examples/custom_field/main.rs)'s
  `CachedEncryptionKeys` holds its snapshot in an `RwLock` and replaces it
  wholesale.
- **Cache per tenant.** Key a map of keyrings by your tenant ID type.
- **Fail closed.** Return `Error::KeysUnavailable` when the snapshot is not
  loaded or the tenant is unknown, rather than falling back to another tenant's
  keys. A refresh that fails must not widen access.
- **Promote and retain deliberately.** A refreshed keyring keeps every previous
  key whose values have not been resealed; dropping one makes those values
  unreadable.

Blind-index keyrings follow the same rules, with independently generated roots;
`Keys` pairs an encryption keyring with one.

For the automatic SQLx column, the keys are a type: `Plain<F, K>` reads its keys
from `K`, the installed keys by default. It serves only standalone seals without
blind indexes, because a column decoder does not see the row. A record's fields
are sealed by the record. See
[keyrings](integration.md#keyrings) for the process-wide forms and how to
forbid them.

## Test the choice

Key resolution is ordinary application logic, so test it like any other:

- **Assert which generation sealed a value.** `Sealed::key_id` returns the key
  generation the envelope names, so a test can compare it with the current key of
  the keyring the value should have been sealed under:
  `assert_eq!(sealed.key_id(), payments.current().id())`. The ID is
  unauthenticated metadata, which is enough for a test over a value your test
  just sealed.
- **Assert that another tenant's keyring cannot open it.** With per-tenant key
  IDs, opening with another tenant's keyring returns
  `Err(Error::UnknownEncryptionKey(_))`; the
  [tenant example](../examples/tenant_field.rs) asserts exactly that.
- **Assert that an unknown tenant fails closed**, with
  `Err(Error::KeysUnavailable)`, rather than resolving to a default keyring.
- **Give each test its own keyrings.** Explicit operations never read the
  installed keys, so tests run in parallel without contending on process-wide
  state. See [testing and diagnostics](testing.md).

A test that seals a value and opens it again with the same keys proves a round
trip, not custody: it passes even when every seal shares one keyring. Pin the
keyring identity, not only the round trip.

## Shredding depends on all of this

Destroying a tenant's root keys only removes access to the values that were
actually sealed under them. A single write under the wrong keyring survives, and
the library cannot tell you about it, so per-tenant shredding rests on the custody
map, its tests, and the storage inventory. Follow
[shredding a tenant](shredding.md), and treat a tenant whose custody is untested
as not shreddable.

Key destruction is also not the only path to a value: leaked keys, leaked
plaintext, and copies outside the inventory are unaffected by any of it. See
[retirement and recovery](key-rotation.md#retirement-and-recovery) and the
[threat model](security.md).

## What to read next

- [Bindings](bindings.md): what values are bound to, and where they come from.
- [Shredding a tenant](shredding.md): the runbook and its prerequisites.
- [Key lifecycle](key-rotation.md): staging, promotion, rollback, retirement.
- [Custom-field example](../examples/custom_field/README.md#implementor-obligations):
  the contract of keys the application refreshes.
- [ADR-0006](adr/0006-keys-are-passed-in.md): why keys are passed in, and the
  seam reserved for library-owned routing.
