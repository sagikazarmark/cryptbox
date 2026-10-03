---
status: accepted
---

# Keys are passed in; choosing which keys is application code

> Amended for the documentation mitigations (#96). The guide is
> [`docs/choosing-keyrings.md`](../choosing-keyrings.md) and the destruction
> procedure is [`docs/shredding.md`](../shredding.md). #89 built
> `testing::assert_sealed_under`, which the guide's tests use, but not
> `Manifest::custody`, so the guide keeps a committed custody table beside the
> manifest snapshot.
>
> Amended when implemented (#100). The provider traits are removed entirely, not
> reduced to `current_key()` / `key(id)`: the keyrings are the only key types.
> A source returns its keyring by value, and cloning a keyring shares its keys.
> A borrowed keyring could not be handed out from behind a lock, a swapped
> snapshot, or a lazily filled per-scope cache, which a routing source needs.

> Amended by [ADR-0009](0009-scopes-have-views.md). Key sources are typed by the
> seal's keys view, `EncryptionKeySource<K>` and `BlindIndexKeySource<K>`, and
> receive its values instead of an untyped `KeyScope`, which is removed.

> Amended by [ADR-0010](0010-records-carry-their-bound-values.md). Keys are
> passed in without a source trait: `seal`, `open`, and `probes` take `Keys` or
> a keyring, and the application chooses which keys protect which values.

`seal`, `open`, and the index operations take the keys to use directly. The crate
ships concrete keyrings (`EncryptionKeyring`, `BlindIndexKeyring`, and the `Keys`
pair). Each holds the current key plus previous keys, looked up by the key ID in
the envelope. Deciding which keyring protects which field or scope is
application code. This keeps the core small, and it keeps key loading and
caching, which are async and KMS-specific, outside the library. Routing can be
added back later without breaking changes.

The seam is reserved now. Operations accept any `EncryptionKeySource` /
`BlindIndexKeySource`, and the library passes each source the field (or index)
and the binding's `KeyScope`. The built-in keyrings ignore both and return
themselves. A later release can add an owner check
(`fn owner(&self) -> Option<KeyScope> { None }`) and a routing source, both as
additive changes.

## Considered Options

- **A library-owned labelled `KeySet`** with per-field routes, tenant labels,
  owner attestation, and revocation, verified at seal time: deferred. It catches
  custody mistakes when data is written, but it roughly doubled the key API
  before anyone needed it.
- **Field-aware providers plus `Router`** ([ADR-0003](0003-field-aware-key-providers.md)):
  superseded. Providers go back to `current_key()` / `key(id)` without
  context.
- **Keys selected inside `seal` from the context** (the context drives key
  selection): rejected. It interleaves async resolution with sealing, and it
  lets the context choose its own keys.

## Consequences

What the binding still guarantees:

- Ciphertext can't move across rows, scopes, or fields. The binding is in the AAD
  and the HKDF info.
- Opening with the wrong keyring fails loudly, as long as key IDs are generated
  UUIDs and never shared across keyrings.

What becomes the application's responsibility, and fails **silently at write
time**:

- **Wrong scope.** Sealing scope A's data with scope B's keyring succeeds. It is
  only found when A is read with A's keyring.
- **Wrong custody.** A field sealed under the wrong KMS (for example, an IBAN
  under the general KMS) is never detected.
- **Shredding.** Misrouted values survive destruction of their scope's keys, or
  are destroyed along with another scope's keys.
- **Audit.** The library can't report which keys protect which field.

Mitigations, required in v1:

- A "choosing keyrings" guide that states these failure modes and warns about
  shredding. **Done:** [`docs/choosing-keyrings.md`](../choosing-keyrings.md) and
  [`docs/shredding.md`](../shredding.md).
- `testing::assert_sealed_under::<F>(&sealed, &keyring)`, so applications can
  unit-test which keyring seals a field (#89).
- `Manifest::custody::<F>("…")` declarative labels, so reviewers and auditors see
  custody (#89).
- `Error` is `#[non_exhaustive]`. `KeyScope`, the `keys` role, and KMS
  encryption-context helpers that take a `KeyScope` all exist in v1.
- Per-scope shredding should not be relied on in production until an owner
  check exists.

Effect on earlier ADRs:

- **[ADR-0003](0003-field-aware-key-providers.md) is superseded.** `Router` and
  the field-aware provider signatures shipped by #67 are removed. This is a
  pre-1.0 breaking change.
- **[ADR-0004](0004-key-supply-global-and-explicit.md) is amended.**
  `keys::install` and the automatic column (`Plain<F, K = GlobalKeys>`) remain,
  but only for `FieldOnly` fields. The explicit forms are now `seal`/`open` taking
  keys, and there are still no feature gates.
