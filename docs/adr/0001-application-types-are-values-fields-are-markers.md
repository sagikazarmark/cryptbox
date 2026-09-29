---
status: accepted
---

# Application types are values; fields are separate markers

> Amended by [ADR-0005](0005-runtime-binding-is-the-core.md), which supersedes the
> `Field` shape and the `Encrypted<F>` carrier. The split between values and
> fields still stands.
>
> Amended by [ADR-0007](0007-seals-may-be-their-own-values.md). A field is now a
> *seal*, and a seal may be its own value type, so the split between values and
> markers is a choice rather than a rule; a value type shared by several seals
> still never carries an ID. `derive(Plaintext)` and application `Plaintext`
> impls are retired in favour of an explicit `transparent` adapter or `codec`.

The `profile!` macro is replaced by traits plus thin derives. An application's own
types (`struct Address { .. }`, `struct Email(String)`) are **values**: they say
how they encode, never where they are stored. A **field** is a separate marker
type that carries the field ID, value type, codec, and padding
(`#[derive(cryptbox::Field)] #[cryptbox(id = "…", value = Address, codec = cryptbox::Json)] struct HomeAddress;`).
A field ID binds ciphertext to a storage location, and one domain concept
(`Email`) routinely lives in several locations (`users.email`, `invites.email`),
so identity cannot live on the value type without either sharing an ID across
columns (ciphertext becomes swappable) or forcing a newtype per column (which is
a marker again).

## Considered Options

- **The type is the field** (`#[derive(Field)] struct UserEmail(String)`, `email.encrypt()`):
  rejected. Besides the swap/newtype problem, it puts plaintext in a type users
  will `derive(Debug, Serialize)` on, forces `Serialize` onto the protected type
  for JSON, lets `struct Row { email: UserEmail }` store plaintext silently, and
  infers the codec from the type's shape, so refactoring `UserEmail(String)`
  silently changes stored bytes.
- **Record-level derive on the storage row** (IDs on `Ciphertext<_>` columns,
  generated marker modules): not adopted as the core. Generated modules hurt
  discoverability and hygiene, and manual impls would become second-class. It
  may return later as optional sugar that expands to the same field markers.
- **Unsealed `DefaultCodec` / per-type default codec**: rejected as the only
  mechanism. A library can flip its own type's default behind a Cargo feature,
  silently changing stored bytes in every downstream app (reproduced in a
  prototype).

## Consequences

- Traits: `Codec<T>` is a strategy only; `Plaintext` (derivable, crate-provided
  and frozen for `String`, `Vec<u8>`, `Secret<String>`, `Secret<Vec<u8>>`) names a
  value's default codec and replaces the sealed `DefaultCodec`; `Field` merges
  today's `Field` and `EncryptionProfile` and drops `NAME` and `Keys`;
  `BlindIndexSpec` is bound to one field, removing the `str`/`String` duplicate
  impls and the three-parameter turbofish.
- Derives (`Field`, `BlindIndexSpec`, `Plaintext`) expand to exactly the impl a
  user would write by hand and nothing else: no `Debug`, `Deref`, `From`, or
  hidden items. IDs must be UUID literals validated at expansion and are never
  derived from identifiers. A codec is never inferred from a struct's shape.
- One derive writes two impls. `#[derive(Plaintext)]` without `codec` on a
  single-field tuple struct (`struct Email(String)`) makes the type its own
  codec, which stores exactly the bytes of the inner type's `Plaintext` codec.
  It emits `impl Codec<Self>` alongside `impl Plaintext`, because no
  crate-provided adapter can wrap or unwrap the value without `From` or
  `Deref`. This follows the inner type's declared default rather than inferring
  a codec from the shape. Changing the inner type still changes the stored
  bytes unless the new default encodes identically, so it needs the same
  migration review as any codec change.
- The derives live in a proc-macro crate, reversing the earlier rejection in
  `docs/research/profile-declaration-syntax.md`; the manual trait path stays
  first-class, so the derive remains optional.
- Plaintext hygiene stays with the `Encrypted<F>` carrier and `Secret<T>`, not
  with application types.
