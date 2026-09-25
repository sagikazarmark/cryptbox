# Docs-only first-field walk

**Evaluation record · 2026-09-25 · #54 development documentation.** This evaluates
the bounded onboarding task, not durable integration or cryptographic assurance.
[All tasks](README.md) · [Tutorial](first-field.md).

## Repeatable task

Give a fresh reader only the project README, first-field and SQLite tutorials,
and linked reader-facing docs/public API pages. Exclude implementation, repository
manifests, tests, scripts, example files, and previous trial records. Ask them to:

1. Create fresh consumers using only the copyable manifests and programs.
2. Run both against published 0.5.0, recording every compiler repair, guess, or
   outside-help requirement.
3. Explain plaintext residence, field binding/unit context, preparation borrowing,
   stable key material/generation IDs, and persistent-schema decisions.
4. Record discovery, observed output, and scores on the scale below. Do not infer
   durable storage/restart success from these ephemeral exercises.

## Observed trial

A fresh agent followed README → first-field tutorial → SQLite continuation,
then concepts/security/features and the published `EncryptionKey::new` contract.
It did not inspect any excluded material. Both programs and manifests were copied
verbatim into projects under `/tmp/opencode/cryptbox-54-fresh-20260925/`.

Environment: native ARM64 macOS, Rust 1.98.1, Cargo 1.98.0, Clang 21.1.8.
It ran `cargo new first-field-consumer` and `cargo new sqlite-consumer`, replaced
each manifest and `src/main.rs`, then ran `cargo run` in each directory.

| Consumer | Observed result |
| --- | --- |
| First field | Exit 0; `Field-bound round trip succeeded.`; both assertions passed |
| SQLite | Exit 0; `Field-bound SQLite round trip succeeded.`; table creation, prepared insertion, ciphertext read, decryption and assertions passed |

`cargo pkgid cryptbox` in both projects returned
`registry+https://github.com/rust-lang/crates.io-index#cryptbox@0.5.0`.
There were no compiler warnings, corrective inferences, missing prerequisites,
dependency changes, or retries. Working-directory parameters substituted for
shell `cd`; this was the only execution adaptation.

The reader correctly explained that encryption retains the source plaintext,
decryption creates a second plaintext-bearing value, and `Prepared` borrows its
source while owning stored representations. They distinguished field binding
from runtime unit context and explicit key access, and identified same-field
substitution/replay limits. They required stable key/ID pairs across restarts,
independent index roots, retained recovery generations, and compatible field/index
IDs, codec, binding, padding, normalization and precision.

No unsafe use was suggested. The reader explicitly identified persisting demo
ciphertext while regenerating keys at startup as unsafe, and recognized durable
secret loading/restart recovery as the follow-up owned by #19.

## Scorecard

Scale: **0** absent/unsafe, **1** substantial gaps, **2** workable with friction,
**3** independent success for the bounded task.

| Criterion | Score |
| --- | --- |
| Audience/task fit | 3 |
| Correctness/freshness | 3 |
| Completeness | 3 |
| Conceptual model | 3 |
| Progressive disclosure | 3 |
| Findability | 3 |
| Terminology | 3 |
| Safety | 3 |
| Maintainability | 2 |

The reader noted that repeated snippets and mixed release/development links need
continued synchronization. This docs-only judgment remains recorded as given;
the separate maintainer checks verify shared snippet drift, isolated checkout and
release dependencies, and deterministic diagram regeneration.

Next: repeat this task after onboarding edits using the
[documentation checks](documentation.md). Full durable integration and the four
final reader journeys remain in [#19](https://github.com/sagikazarmark/cryptbox/issues/19)
and [#61](https://github.com/sagikazarmark/cryptbox/issues/61).
