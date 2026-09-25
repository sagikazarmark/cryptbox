# CryptBox documentation

**Task index · current development guidance.** Start here to choose a task.
The latest release is 0.5.0; this checkout includes unreleased code and docs,
including stored-byte Serde support. See [document authority and versions](#document-authority-and-versions).

## Choose a task

| Task | Start here | Continue with |
| --- | --- | --- |
| Decide whether to adopt | [Suitability and security](security.md) | [Feature/platform reference](features.md) |
| Encrypt a first field | [Fresh-project tutorial](first-field.md) | [Field-bound SQLite](first-field-sqlite.md), [concepts](concepts.md) |
| Store and search durable SQLx data | [PostgreSQL / SQLite consumer](searchable-sqlx.md) | [Testing](testing.md#durable-searchable-consumer), [integration trial](searchable-sqlx-walk.md) |
| Serialize stored values | [Stored-value tutorial (unreleased Serde support)](stored-values.md) | [Stored-value assurance](stored-values.md#obtain-additional-assurance) |
| Rotate keys and rewrite data | [Key rotation example](../examples/key_rotation.rs) | [Maintenance sweep how-to](reencryption-sweep.md) |
| Adopt encryption over existing data | [Legacy migration how-to](legacy-migration.md) | [Legacy example](../examples/legacy_migration.rs), [plaintext example](../examples/plaintext_migration.rs) |
| Review security | [Review path and gates](security.md#security-review-path) | [Wire-format reference](wire-format.md), [suite research](suite-evaluation.md), [proposed policy](suite-1-usage-policy.md) |
| Test and diagnose an integration | [Testing and diagnostics how-to](testing.md) | [Stored-value assurance procedure](stored-values.md#obtain-additional-assurance) |
| Extend profiles and providers | [Custom-profile recipe](custom-profile.md) | [Plaintext and key ownership](concepts.md#plaintext-and-key-ownership) |
| Maintain documentation | [Documentation checks](documentation.md) | [Adoption walk](adoption-walk.md), [first-field docs-only walk](first-field-walk.md) |

The first-field and SQLx tutorials use published 0.5.0 with explicit local
providers. Fleet rotation continues in [#58].

### Integration caveat

The [SQLite exercise](first-field-sqlite.md) now preserves the first tutorial's
field binding. Its keys and database are ephemeral; follow the
[durable-key next step](first-field.md#next-keep-keys-across-restarts) before persisting data.
Continue with [durable secret loading, runtime/TLS setup and restart](searchable-sqlx.md).

## Document authority and versions

Four independent identifiers appear in this project:

| Identifier | Current value | Meaning |
| --- | --- | --- |
| Crate release | **0.5.0** | Rust package/API release; see the [release](https://github.com/sagikazarmark/cryptbox/releases/tag/v0.5.0) and [changelog](../CHANGELOG.md) |
| Ciphertext / blind-index format | **1 / 1** (`0x01`) | Separate stored-byte layout versions; see [wire format](wire-format.md) |
| Encryption suite ID | **1** (`0x01`) | HKDF-SHA-256 and XChaCha20-Poly1305 construction, not a crate version |
| Historical design generation | **v0.1** | The original [design draft](spec.md), not a current API or wire-version label |

A crate release does not automatically change stored formats, and a format
version does not describe all persistent profile choices. Read the
[persistent-schema reference](https://docs.rs/cryptbox/0.5.0/cryptbox/#persistent-schema)
before storing durable data.

**Release users:** use the exact version selector on docs.rs. The
[0.5.0 API](https://docs.rs/cryptbox/0.5.0/cryptbox/) and
[0.5.0 source archive](https://docs.rs/crate/cryptbox/0.5.0/source/) are frozen
release material. They do not contain these later documentation improvements or
the unreleased `serde` feature. The checkout's unchanged package version alone
does not establish release parity; see the [feature reference](features.md).
Repository-relative links describe the checkout you are reading; GitHub `main`
links describe development. Do not substitute `/latest/` when diagnosing older
data or API behavior. Match the dependency version first, then check its format
and profile schema. No production approval follows from any version number.

### Canonical owners

| Surface | Primary role and authority |
| --- | --- |
| [Project landing page](../README.md) | Positioning, experimental status, compact demonstration, task discovery |
| [Crate landing reference](https://docs.rs/cryptbox/0.5.0/cryptbox/) | Type model, persistent schema, concise security boundary, API links; the [feature/platform reference](features.md) is a shared Markdown source included in current rustdoc |
| [Glossary](../CONTEXT.md) and [concepts explanation](concepts.md) | Canonical terms and their relationships; current versus future binding support |
| [Security explanation](security.md) | Adoption threat model, unsuitable use cases, review path and unfinished gates |
| [First-field tutorial](first-field.md) and [SQLite continuation](first-field-sqlite.md) | Complete published-release consumer setup and first success; snippets shared with executed examples |
| [Searchable SQLx tutorial](searchable-sqlx.md) | Durable key loading, PostgreSQL/SQLite CRUD, nullable/deferred reads, macro prerequisites and verified lookup |
| [Stored-value tutorial](stored-values.md) | Unreleased explicit Serde consumer path using a checkout dependency, plus assurance steps |
| [Maintenance](reencryption-sweep.md) and [legacy migration](legacy-migration.md) how-tos | Existing bounded maintenance procedures; operational extensions remain tracked downstream |
| [Plaintext migration redirect](plaintext-migration.md) | Preserves the old entry point; canonical procedure is legacy migration |
| [Testing how-to](testing.md) | Local providers, automatic-adapter isolation, diagnostic metadata |
| [Custom-profile recipe](custom-profile.md) | Executable codec, normalizer and provider extensions; contracts live beside public traits and ownership is explained in concepts |
| [Wire-format reference](wire-format.md) | Current experimental stored layouts and provisional vectors |
| [Suite evaluation](suite-evaluation.md) | Dated research and rationale, not an approval or current API tutorial |
| [Suite usage policy](suite-1-usage-policy.md) | Proposed operational policy; not accepted or library-enforced limits |
| [Original specification](spec.md) | Historical design and API sketches, superseded by current references |
| [Documentation maintenance](documentation.md) and [adoption walk](adoption-walk.md) | Reproducible checks, publication rules, reader-evaluation evidence |
| [Changelog](../CHANGELOG.md) | Release history, not usage instructions |

### Runnable examples

Run from a checkout with the prerequisites in the crate reference:

| Example | Command |
| --- | --- |
| [First field](../examples/first_field.rs) | `cargo run --locked --example first_field` |
| [Custom profile](../examples/custom_profile.rs) | `cargo run --locked --example custom_profile` |
| [Key rotation](../examples/key_rotation.rs) | `cargo run --locked --example key_rotation` |
| [Maintenance sweep](../examples/reencryption_sweep.rs) | `cargo run --locked --example reencryption_sweep --features sqlx-sqlite` |
| [Legacy migration](../examples/legacy_migration.rs) | `cargo run --locked --example legacy_migration --features migrate,sqlx-sqlite` |
| [Plaintext migration](../examples/plaintext_migration.rs) | `cargo run --locked --example plaintext_migration --features migrate,sqlx-sqlite` |
| [Blind-index lookup](../examples/blind_indexes.rs) | `cargo run --locked --example blind_indexes` |
| [Stored values](../examples/stored_values.rs) | `cargo run --locked --example stored_values --features serde` |
| [SQLite](../examples/sqlx_sqlite.rs) | `cargo run --locked --example sqlx_sqlite --features sqlx-sqlite` |

Next: [evaluate suitability](security.md) or choose a task above.

[#19]: https://github.com/sagikazarmark/cryptbox/issues/19
[#54]: https://github.com/sagikazarmark/cryptbox/issues/54
[#58]: https://github.com/sagikazarmark/cryptbox/issues/58
