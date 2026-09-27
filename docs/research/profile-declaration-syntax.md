# Profile declaration syntax: macro kinds and prior art

Research notes for shrinking the `profile!` declaration in `src/profile.rs`.
Gathered 2026-09-26 against Rust 1.98.1 (local toolchain) and the sources
linked inline. Claims marked **unverified** could not be traced to a primary
source.

## Summary and recommendation

**Keep `macro_rules!`, move to a one-line form with defaults and an optional
override block:**

```rust
cryptbox::profile! {
    /// The user's email address.
    pub UserEmail: String = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25";
}

cryptbox::profile! {
    pub Avatar: Vec<u8> = "…uuid…" { binding: unbound, padding: cryptbox::PadToBlock<16> };
}
```

Defaults: `name = stringify!(UserEmail)`, `binding = field_bound`, `padding =
NoPadding`, `keys = GlobalKeyContext`, and `codec = <T as DefaultCodec>::Codec`
where a `#[diagnostic::on_unimplemented]` note on `DefaultCodec` tells the user
to write `{ codec: … }` when there is no default. A prototype of this macro compiled
under edition 2024 / `rust-version = "1.85"`. `$v:ty` may be followed by `=` and
`{` ([follow-set rules](https://doc.rust-lang.org/reference/macros-by-example.html#follow-set-ambiguity-restrictions)),
doc comments pass through, and the `on_unimplemented` note prints as intended
(see [Error messages](#3-error-message-quality)).

Why not a proc macro (attribute or derive):

- It needs a second `proc-macro = true` crate
  ([Reference](https://doc.rust-lang.org/reference/procedural-macros.html)) plus
  `syn`/`quote`/`proc-macro2`. That is a new build-time code-execution dependency
  for a crypto crate that has none today
  ([Reference: "same security concerns that Cargo's build scripts have"](https://doc.rust-lang.org/reference/procedural-macros.html)).
  The ecosystem is also in the middle of a `syn` 2 → 3 transition
  ([syn 3.0.0, 2026-07-18](https://github.com/dtolnay/syn/releases/tag/3.0.0)).
- The main benefits of a proc macro are spans that point at the offending literal
  and validating the UUID at expansion time. Those matter little here: `field_id!`
  already rejects bad UUIDs at compile time through const evaluation (verified;
  the error spans the whole invocation but names the failure).
- The value type is not a natural fit for either proc-macro shape.
  `struct UserEmail(String)` reads as a newtype, which the marker is not.
  `#[cryptbox::field("…", value = String)]` puts a type inside an attribute string
  or meta, which is less readable than `UserEmail: String`.
- There is a forward path that needs no proc macros. RFC 3697 (declarative
  *attribute* macros) is implemented on nightly behind `macro_attr` and not yet
  stable ([tracking issue #143547](https://github.com/rust-lang/rust/issues/143547)).
  Once stable, `#[cryptbox::field("uuid")] pub struct UserEmail;` could be offered
  from `macro_rules!` alone. RFC 3698 (declarative *derive*) does **not** support
  helper attributes
  ([RFC text](https://rust-lang.github.io/rfcs/3698-declarative-derive-macros.html)),
  so `#[derive(Field)] #[cryptbox(id = …)]` is not a future option there.

Trade-offs of the recommendation:

- Defaulting the codec makes the persistent byte format depend on a crate-chosen
  default. `EncryptionProfile` docs already state that the codec defines persistent
  schema (`src/profile.rs`), so each `DefaultCodec` impl becomes a permanent
  compatibility promise. Keep the set tiny (`String → Utf8`, `Vec<u8> → Raw`) and
  give no default for serde types, where the Json/Postcard choice must stay
  explicit.
- Defaulting `binding` to `field_bound` reverses today's "always required" rule
  (`profile!` docs). It is the safer default and matches "secure unless opted out"
  prior art: AWS DB-ESDK defaults every non-key attribute to `ENCRYPT_AND_SIGN`
  ([AWS](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/ddb-java-using.html)),
  and Rails is non-deterministic unless `deterministic: true`
  ([Rails guide](https://guides.rubyonrails.org/active_record_encryption.html)).
  `unbound` stays an explicit opt-out token.
- `name` defaulting to `UserEmail` rather than `user-email` is harmless because
  `Field::NAME` is documented as non-unique, non-stable diagnostics
  (`src/binding.rs`).
- Override keys must appear in a fixed order in a plain `macro_rules!` matcher.
  Out-of-order keys give "no rules expected `binding`" (verified). A tt-muncher
  can accept any order but makes errors worse.

## Prior art

| Crate / system | Macro kind | Declaration shape | Where the related type or config goes |
|---|---|---|---|
| [bitflags 2](https://docs.rs/bitflags/latest/bitflags/) | `macro_rules!` | `bitflags! { pub struct Flags: u32 { const A = 1; } }`, or user-written `pub struct Flags(u32);` + `bitflags! { impl Flags: u32 { … } }` | Bits type after `:` in the macro header, the same shape as `UserEmail: String` |
| [diesel `table!`](https://github.com/diesel-rs/diesel/blob/master/diesel/src/macros/mod.rs) | function-like **proc macro** today (`pub use diesel_derives::table_proc as table`) | `table! { users (id) { id -> Integer, name -> Text } }` | SQL types after `->` inside the DSL. When it moved from `macro_rules!` is **unverified** |
| diesel derives (`Queryable`, `Insertable`) | derive | `#[derive(Insertable)] #[diesel(table_name = users)]` | Attribute arg (path) |
| [sea-orm `DeriveEntityModel`](https://docs.rs/sea-orm/latest/sea_orm/derive.DeriveEntityModel.html) | derive | `#[derive(DeriveEntityModel)] #[sea_orm(table_name = "posts")] struct Model { … }` | Attribute args; generates `Entity`, `Column`, `PrimaryKey` |
| [uuid `uuid!`](https://github.com/uuid-rs/uuid/blob/main/src/macros.rs) | `macro_rules!` + const fn | `const X: Uuid = uuid!("…");` | n/a. The proc-macro `macro-diagnostics` feature was deprecated to a no-op in [PR #856](https://github.com/uuid-rs/uuid/pull/856) (2026-01) because its better errors were no longer being delivered and it was opt-in anyway |
| [typed-builder](https://docs.rs/typed-builder) | derive (`typed-builder-macro` crate, [Cargo.toml](https://github.com/idanarye/rust-typed-builder/blob/master/Cargo.toml)) | `#[derive(TypedBuilder)] struct S { #[builder(default)] x: u32 }` | Field attributes |
| [strum](https://docs.rs/strum) | derive, behind `derive` feature ([Cargo.toml](https://github.com/Peternator7/strum/blob/master/strum/Cargo.toml)) | `#[derive(EnumString)] enum E { #[strum(serialize = "a")] A }` | Helper attributes |
| [nutype](https://docs.rs/nutype/latest/nutype/) | attribute | `#[nutype(sanitize(trim), validate(…), derive(Debug))] pub struct Username(String);` | Wrapped type is the tuple field. It really is a newtype, which cryptbox's marker is not |
| [derive_more](https://docs.rs/derive_more) | derive, one Cargo feature per derive ([Cargo.toml](https://github.com/JelteF/derive_more/blob/master/Cargo.toml)) | `#[derive(From, Display)]` | Helper attributes |
| [ref-cast](https://docs.rs/ref-cast) | derive (`ref-cast-impl`, always on, [Cargo.toml](https://github.com/dtolnay/ref-cast/blob/master/Cargo.toml)) | `#[derive(RefCast)] #[repr(transparent)] struct S(str);` | User writes the struct and repr; derive only adds impls |
| [typenum](https://docs.rs/typenum) | no proc macros; checked-in generated code (build scripts removed, [CHANGELOG](https://github.com/paholg/typenum/blob/main/CHANGELOG.md)) | `type N = U42;` | Type-level values are plain types / associated types |
| [static_assertions](https://docs.rs/static_assertions) | `macro_rules!`; optional `proc` feature ([Cargo.toml](https://github.com/nvzqz/static-assertions/blob/master/Cargo.toml)) | `const_assert!(…); assert_impl_all!(T: Send);` | Macro args |
| [encrypted-message](https://docs.rs/encrypted-message/latest/encrypted_message/) (Rust) | none | `EncryptedMessage<String, MyConfig>`; `impl Config for MyConfig { type Strategy = Deterministic; fn keys(&self) … }` | **Generic param + associated type on a marker config**, the closest analogue to cryptbox's `EncryptionProfile<T>` |
| [vaulted](https://docs.rs/vaulted-derive/latest/vaulted_derive/) (Rust) | derive | `#[derive(Vaulted)] #[vaulted(table = "users")] struct User { #[vaulted(encrypt, blind_index)] email: String }` | Per-field helper attrs; field-name segment is AAD ("changing it later orphans existing values") |
| [cipherstash-dynamodb](https://docs.rs/cipherstash-dynamodb/latest/cipherstash_dynamodb/) (Rust) | derives (`Encryptable`, `Decryptable`, `Searchable`) | `#[cipherstash(query = "exact")] email: String`, `#[cipherstash(plaintext)]` | Field helper attrs; encrypted by default |
| [struct-box](https://docs.rs/struct-box/latest/struct_box/) (Rust) | derive | `#[derive(StructBox, Serialize, Deserialize)]` | Context passed at call time |
| [Rails AR Encryption](https://guides.rubyonrails.org/active_record_encryption.html) | class macro | `encrypts :email, deterministic: true, downcase: true` | Keyword options; no per-attribute ID in the payload per the guide |
| [AWS DB-ESDK](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/ddb-java-using.html) | Java annotations or a map | `@DynamoDbEncryptionSignOnly` on a getter, or `attributeActionsOnEncrypt.put("attr", ENCRYPT_AND_SIGN)` | Per-attribute action; logical table name is cryptographically bound |
| [JPA `AttributeConverter<X,Y>`](https://jakarta.ee/specifications/persistence/3.1/apidocs/jakarta.persistence/jakarta/persistence/attributeconverter) | annotation `@Convert(converter = …)` | `class C implements AttributeConverter<String, byte[]>` | **Generic params** on the converter type |
| [Tink AEAD](https://developers.google.com/tink/aead) | none | `aead.encrypt(plaintext, associatedData)` | AAD passed per call; Tink suggests binding to context such as a user ID |

Takeaways:

- Declaring a **marker/config type with associated types** that is not the value
  itself (encrypted-message's `Config`, JPA converters) usually appears without
  macros. The macro is sugar over a trait the user could implement by hand, which
  cryptbox already documents.
- **bitflags' `Name: Type` header** is the closest `macro_rules!` precedent for
  `UserEmail: String`. bitflags 2 also added an `impl Flags: u32 { … }` form so
  users can write their own struct and derives
  ([docs](https://docs.rs/bitflags/latest/bitflags/)), and made the `Flags` trait
  publicly implementable to support macro-free use
  ([CHANGELOG 2.3.0](https://github.com/bitflags/bitflags/blob/main/CHANGELOG.md)).
- Rust field-encryption crates that use derives (vaulted, cipherstash) derive on
  the **record struct**, with per-field attributes. That is a different unit than
  cryptbox's per-field marker, so their macro choice does not transfer directly.
- Proc-macro crates that care about dependency weight gate them behind a
  feature: strum `derive`, serde `derive`
  ([serde.rs](https://serde.rs/derive.html)), zeroize `derive`
  ([Cargo.toml](https://github.com/RustCrypto/utils/blob/master/zeroize/Cargo.toml)),
  and derive_more per-derive features.

## 1. Where the ID/config and the related type go

Three patterns appear across the sources above:

1. **Macro header type** (`Name: Type`, bitflags). Reads naturally and keeps the
   marker a unit struct. Works in `macro_rules!` because `ty` may be followed by
   `=`, `{`, `,` or `;`
   ([follow sets](https://doc.rust-lang.org/reference/macros-by-example.html#follow-set-ambiguity-restrictions)).
2. **Attribute argument** (`#[diesel(table_name = users)]`, `#[sea_orm(…)]`).
   Only available through proc macros on stable. A type in attribute position
   (`value = String`) is legal meta syntax but reads worse and needs `syn` to
   parse into a type.
3. **Tuple field** (nutype, ref-cast). Correct only when the type actually wraps
   the value. For cryptbox it would suggest `UserEmail("a@b")` is constructible,
   which is false. **Avoid.**

`EncryptionProfile<T>` is generic, so one marker could in principle implement
it for several `T`. Every candidate syntax covers exactly one `T`. Anyone who
needs more writes the impl by hand, which the explicit form already supports.

## 2. Proc-macro costs

- **Separate crate.** Proc macros "must be defined in the root of a crate with the
  crate type of `proc-macro`" and cannot be used in the defining crate
  ([Reference](https://doc.rust-lang.org/reference/procedural-macros.html)). That
  means a `cryptbox-macros` crate, versioned in lockstep (ref-cast, typed-builder
  and derive_more pin `=x.y.z` on their impl crates; see their Cargo.toml files
  linked above).
- **Compile time.** dtolnay's watt README cites "20+ seconds it can take to compile
  complex procedural macros and their dependencies", against ~3 s for a shared
  Wasm runtime ([watt](https://github.com/dtolnay/watt)). syn puts functionality
  behind features "in order to optimize compile time"; defaults are `derive`,
  `parsing`, `printing`, `clone-impls` and `proc-macro`, and `full` is opt-in
  ([syn lib.rs](https://github.com/dtolnay/syn/blob/master/src/lib.rs)). A profile
  macro would need only `derive` + `parsing`. No cryptbox-specific measurement was
  made.
- **MSRV.** syn 3.0.6, quote 1.0.47 and proc-macro2 1.0.107 declare
  `rust-version = "1.71"`
  ([syn](https://github.com/dtolnay/syn/blob/master/Cargo.toml),
  [quote](https://github.com/dtolnay/quote/blob/master/Cargo.toml),
  [proc-macro2](https://github.com/dtolnay/proc-macro2/blob/master/Cargo.toml)),
  well under cryptbox's 1.85. The practical MSRV risk is transitive drift: a
  downstream report shows a pinned 1.81 toolchain unable to build
  `zeroize_derive` 1.5.0 after it moved to edition 2024 / MSRV 1.85 (search
  result, **unverified** beyond the
  [zeroize_derive CHANGELOG](https://github.com/RustCrypto/utils/blob/master/zeroize_derive/CHANGELOG.md),
  which confirms the bump).
- **syn major-version churn.** syn 3.0.0 shipped 2026-07-18
  ([release](https://github.com/dtolnay/syn/releases/tag/3.0.0)). RustCrypto's
  `zeroize_derive` on master already depends on `syn = "3"`
  ([Cargo.toml](https://github.com/RustCrypto/utils/blob/master/zeroize_derive/Cargo.toml)),
  so until the ecosystem converges, a new macro crate adds to the chance that
  users compile syn 2 and 3 side by side.
- **Supply chain.** Proc macros run with the compiler's privileges and "have the
  same security concerns that Cargo's build scripts have"
  ([Reference](https://doc.rust-lang.org/reference/procedural-macros.html)).
  cargo-vet's `safe-to-deploy` covers them explicitly: "for crates which generate
  deployed code (e.g. build dependencies or procedural macros), reasonable usage
  of the crate should output code which meets the above criteria"
  ([cargo-vet built-in criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html)).
  The 2023 serde_derive precompiled-binary episode
  ([serde#2538](https://github.com/serde-rs/serde/issues/2538), reverted in
  [v1.0.184](https://github.com/serde-rs/serde/releases/tag/v1.0.184)) is the
  standard example of why auditors care. I found **no written RustCrypto policy**
  on proc-macro deps. Their observable practice is to keep them optional
  (zeroize `derive = ["zeroize_derive"]`, not default).
- **Gating pattern if ever needed.** Use serde-style
  `features = ["derive"]` → `dep:cryptbox-macros`, re-exported from `cryptbox`
  ([serde.rs](https://serde.rs/derive.html)). The cost is that the nicer syntax
  becomes feature-conditional. RFC 3697/3698 name exactly this as motivation:
  "provide these macros unconditionally without requiring the user to enable a
  feature"
  ([RFC 3698](https://rust-lang.github.io/rfcs/3698-declarative-derive-macros.html)).

## 3. Error-message quality

Observed with a local prototype on rustc 1.98.1:

- **Missing default codec** (via `on_unimplemented`; output abbreviated):

  ```
  error[E0277]: `Thing` has no default codec
   2 | exp::profile! { pub Secret: Thing = "z"; }
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no default codec for this value type
     = note: specify one explicitly: `{ codec: cryptbox::Json }`
  help: the following other types implement trait `DefaultCodec`: `String`, `Vec<u8>`
  ```

  The span covers the whole invocation rather than just `Thing`, but the message,
  note and list of implementors are clear.
- **Grammar errors** give `no rules expected \`binding\`` / `no rules expected
  \`z\`` pointing at the offending token, with a note naming the expected matcher
  (`$id:literal`). They are adequate for a small, fixed grammar, and get worse
  with tt-munchers.
- **Invalid UUID** (current `cryptbox::profile!`, verified): `error[E0080]:
  evaluation panicked: identifier contains non-hexadecimal characters`, spanning
  the invocation. It is eager even though the const sits inside an impl, because
  `field_id!` expands to a nested non-generic `const`.
- **Proc macros** can report through `compile_error!` or panics
  ([Reference](https://doc.rust-lang.org/reference/procedural-macros.html)), and
  can attach errors to the exact literal's span. That is the one real
  diagnostic advantage here.
- **`#[diagnostic::on_unimplemented]`** was stabilized in
  [Rust 1.78.0](https://blog.rust-lang.org/2024/05/02/Rust-1.78.0/) (well under
  MSRV 1.85). It supports `message`, `label` and repeated `note`, with `{Self}` and
  `{GenericParam}` interpolation
  ([Reference](https://doc.rust-lang.org/reference/attributes/diagnostics.html)).
  Literal braces are escaped as `{{ }}` (verified). The same page documents
  `#[diagnostic::do_not_recommend]`; its stabilization version was not checked
  (**unverified**).

## 4. Tooling (rustdoc, rust-analyzer)

- **rustdoc** (verified locally): `/// …` doc comments forwarded through
  `$(#[$attr:meta])*` render on the generated struct. The item's `[src]` link
  points at the macro **invocation** lines, not the macro definition. The
  `Field` / `EncryptionProfile<String>` impls appear under "Trait
  Implementations" as usual.
- **rust-analyzer** expands proc macros only through its proc-macro server:
  `procMacro.enable` (default `true`) "implies `cargo.buildScripts.enable`", and
  attribute macros additionally need `procMacro.attributes.enable` (default
  `true`) ([RA config](https://rust-analyzer.github.io/book/configuration.html)).
  Users who disable these, or who list the macro under `procMacro.ignored`, lose
  the generated items entirely. `macro_rules!` expansion does not depend on those
  settings. That `macro_rules!` is expanded in-process is inferred from the config
  docs and **unverified** from RA source.
- **Go-to-definition** on a macro-generated `UserEmail` resolving to the ident
  token in the invocation (because the ident's span comes from user input) is
  expected behaviour but **unverified**. With attribute/derive forms the user
  writes a real `struct`, so navigation and "find references" are trivially right.
  This is the main ergonomics point in their favour, and the reason bitflags 2
  added the user-written-struct form.

## 5. Hygiene and other mechanics

- **User-written item inside `macro_rules!`.** Supported:
  `$(#[$a:meta])* $vis:vis struct $name:ident;` matches, using the `vis`, `ident`
  and `meta` fragments
  ([Reference](https://doc.rust-lang.org/reference/macros-by-example.html#metavariables)).
  A prototype `field! { /// doc \n pub struct Other; id = "…" }` compiled and
  documented correctly (verified). This gives "the user writes the struct" with
  no proc macro, at the cost of slightly more ceremony than `pub UserEmail:
  String = "…";`.
- **Hygiene.** `macro_rules!` uses mixed-site hygiene. Only locals and labels are
  definition-site, while items resolve at the invocation site, and `$crate`
  resolves paths to cryptbox
  ([Reference](https://doc.rust-lang.org/reference/macros-by-example.html#hygiene)).
  So the generated `struct $name` is an ordinary item visible to the caller, as it
  is today. Proc macros are fully unhygienic and must use absolute paths
  ([Reference](https://doc.rust-lang.org/reference/procedural-macros.html)).
- **Attribute/derive via `macro_rules!`.**
  - RFC 3697 ([text](https://rust-lang.github.io/rfcs/3697-declarative-attribute-macros.html)):
    `attr(args) (item) => { … }` rules. Nightly `#![feature(macro_attr)]`,
    tracking issue [#143547](https://github.com/rust-lang/rust/issues/143547),
    open, labelled "needs to bake", no stabilization PR yet.
  - RFC 3698 ([text](https://rust-lang.github.io/rfcs/3698-declarative-derive-macros.html)):
    `derive() (item) => { … }` rules. Nightly `#![feature(macro_derive)]`,
    tracking issue [#143549](https://github.com/rust-lang/rust/issues/143549),
    open. Helper attributes are explicitly **not** supported, so
    `#[cryptbox(id = …)]` cannot be expressed.
  - **Neither is usable on stable** as of 2026-09-26. When RFC 3697 stabilizes,
    `#[cryptbox::field("uuid")] pub struct UserEmail;` (value type in the attr
    args or a separate form) becomes possible with zero dependencies. It would
    sit above the MSRV at that point, so it would need a feature flag or an MSRV
    bump.

## Candidate comparison

| Candidate | Deps | Stable today | Where `String` goes | Diagnostics | RA/doc |
|---|---|---|---|---|---|
| **One-line `macro_rules!`** (recommended) | none | yes | `Name: String` header | invocation-span; `on_unimplemented` note | docs forwarded; src link to invocation |
| Current block `macro_rules!` | none | yes | header | same | same |
| Item-style `macro_rules!` (`pub struct X; id = "…"`) | none | yes | needs an extra `: String` / `value =` slot | same | real-looking item |
| `#[cryptbox::field("…", value = String)]` | `cryptbox-macros` + syn | yes (proc) | attr arg | exact spans | needs RA proc-macro server |
| `#[derive(Field)] #[cryptbox(id, value)]` | same | yes (proc) | helper attr | exact spans | same; derive cannot touch the struct |
| RFC 3697 attr via `macro_rules!` | none | **no** (nightly) | attr args | macro_rules-level | real item |
