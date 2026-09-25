# Cold adoption walk

**Evaluation record · 2026-09-25 · #21 development documentation.** This records
the adoption-evaluator slice of [#51](https://github.com/sagikazarmark/cryptbox/issues/51),
not completion of the full consumer or operational journeys. [All tasks](README.md).

## Repeatable task

Give a fresh reader only the project README, rendered public crate/API pages,
authored reader-facing Markdown, and published examples. Exclude implementation,
tests, manifests, and previous trial notes. Ask:

> Evaluate storing confidential email with SQLx PostgreSQL. Decide suitability,
> identify protected/unprotected threats and review gates, select prerequisites,
> distinguish document versions/authority, and find first-success, integration,
> rotation, and security-review next steps. Record every guess or outside-help
> requirement. Do not infer end-to-end success without executing that journey.

For an unpublished branch, resolve explicitly labeled GitHub development links
to the matching checkout page, recording that this is not a live-site check.

## Observed walk

A fresh agent performed this task without implementation, tests, manifests, or
prior trial material. It read the rendered local crate landing and also fetched
the linked published 0.5.0 API. No code or database execution was performed.

| Decision | Observed discovery path | Result |
| --- | --- | --- |
| Suitability and maturity | README → security; crate landing → development security | Identified conditional database-disclosure protection, application/replay/row-substitution limits, and outstanding gates |
| Configuration | README → published feature reference; rendered crate landing features | Found Rust 1.85, std, entropy, SQLx backend/runtime/TLS responsibilities; published archive lacked new detail |
| Document authority | Either entry → task index | Correctly distinguished 0.5.0, formats 1/1, suite 1, historical v0.1; research and proposed policy not approval |
| Next tasks | README direct links; crate landing → index → destination | First round trip, stored-value tutorial, SQLite, rotation, and review materials within two links |
| Durable PostgreSQL | Entry → index → #19 | Incomplete journey correctly recognized; no invented runtime/TLS recipe or execution claim |

The initial qualitative scores (0 absent/unsafe, 1 substantial gaps, 2 workable
with friction, 3 independent success) were: audience fit **2**, freshness **2**,
completeness **1**, conceptual model **3**, progressive disclosure **3**,
findability **2**, terminology **2**, safety **2**, maintainability **2**. These
scores include friction from the unfinished downstream consumer paths; they
are not a cryptographic assurance rating or a claim of final acceptance.

## Corrections after the walk

- The new feature/platform detail was reachable only through rendered local
  rustdoc or a source link. It now has one [Markdown source](features.md),
  included directly in the crate landing, and direct links from README/index/
  security. No source inspection is needed to select prerequisites.
- The promoted SQLite example uses `Unbound`. The README/index now flag that
  choice and direct adopters to preserve field binding. The example rewrite
  remains owned by #19.
- The released changelog retained an `Unreleased` heading over padding and
  generalized migration. Inspection of the v0.5.0 release tag confirmed those
  entries shipped; the current changelog labels them as shipped by 0.5.0.
- The glossary now defines normalization and index precision; the concepts
  guide explains “sealed” as unavailable for application implementations.
- This record supplies the previously pending evidence destination.
- The subsequent Spec review caught a release distinction the initial walk
  missed: stored-value Serde support was added after v0.5.0 despite the unchanged
  checkout package version. The feature reference and navigation now label it
  unreleased, and the tutorial uses an explicit checkout dependency instead of
  claiming the published `0.5` dependency can enable `serde`.

Local link/anchor checks validate the corrected paths, including remapped
development rustdoc links. The corrected evaluator can reach suitability,
configuration, authority, and next-step destinations within two links from
either entry point. A full fresh-agent rescore is reserved for #61; the initial
scores above have not been silently upgraded after editing.

## Security-reference follow-up

**2026-09-25 · #52 development documentation.** A fresh reviewer completed a
docs-only walk before examining implementation, tests, manifests, or the diff.
The task was to reconstruct both cryptographic recipes and interpret padded
sizes and the proposed usage policy, recording missing inputs or unsafe guesses.

Discovery: README → [security review path](security.md#security-review-path) →
[wire-format reference](wire-format.md) → [proposed policy](suite-1-usage-policy.md).
The reviewer also followed reader-facing concepts, features, suite research, and
stored-value assurance links.

| Task | Observed result |
| --- | --- |
| Reconstruct encryption | Resolved root/derived lengths, both HKDF stages, salt, all label terminators, UUID bytes, context order, OS nonce, prefix, AAD, full tag, and authentication before unpadding/decoding |
| Reconstruct blind index | Resolved independent root, normalization input, length encoding, both HKDF stages, HMAC input, most-significant-bit truncation, and canonical stored representation |
| Check literal label lengths | Independently counted 24/27/25/28/30 bytes for salt/encryption/AAD/index-key/index-value labels, including NULs; all matched |
| Interpret padded boundaries | Distinguished application value, encoded `E`, padded `P`, and envelope `W`; reproduced empty, aligned, at-cap, over-cap, and fixed-padding overflow examples |
| Interpret policy status/accounting | Identified `P <= 1,048,576` as proposed and unenforced; resolved shared/historical-key counters, failed AEAD versus parse/codec failures, and unfinished reduction assumptions |

No missing facts, corrective guesses, or outside implementation help were needed.
Qualitative **task completeness: 3/3; safety: 3/3**, using the scale above.
The reviewer explicitly rejected interpretations that omit NULs, hash UUID text,
let stored metadata choose binding, reuse vector nonces, cap character counts,
ignore padding markers, or treat successful calls as policy approval.

Subsequent implementation review found the recipes consistent with current code.
Existing format/vector checks and the public padding suite pass, including the
new literal envelope-size cases. The full all-feature suite and doctests pass;
the existing server-dependent PostgreSQL test remains ignored. Rustdoc,
formatting, Clippy, typechecking, and local links also pass. The separate
standards review requested the table heading “Padding policy” rather than
“Profile”; that terminology correction was applied.

This is documentation-consistency evidence, not independent vector certification,
cryptographic review, policy acceptance, or completion of all four #51 journeys.
The outstanding security gates remain in the [security explanation](security.md#experimental-maturity).

## Remaining journeys

The subsequent [#54 docs-only first-field walk](first-field-walk.md) completed
the fresh-project and field-bound SQLite onboarding exercises. The historical
observations above describe the pre-#54 examples.

| Gap observed or explicitly deferred | Owner |
| --- | --- |
| Durable key loading, full PostgreSQL dependencies/runtime/TLS/schema, restart and search path | [#19](https://github.com/sagikazarmark/cryptbox/issues/19) |
| Complete adapter-test/diagnostics consumer recipe | [#56](https://github.com/sagikazarmark/cryptbox/issues/56) |
| Clear custom normalizer obligations (including the ambiguous “not include secrets” wording) and plaintext ownership | [#57](https://github.com/sagikazarmark/cryptbox/issues/57) |
| Fleet rollout, durable repeated sweeps, legacy search continuity, backup recovery | [#58](https://github.com/sagikazarmark/cryptbox/issues/58), [#55](https://github.com/sagikazarmark/cryptbox/issues/55), [#59](https://github.com/sagikazarmark/cryptbox/issues/59), [#60](https://github.com/sagikazarmark/cryptbox/issues/60) |
| Final live execution and all four fresh docs-only journeys | [#61](https://github.com/sagikazarmark/cryptbox/issues/61); coordinate PostgreSQL sweeps with [#42](https://github.com/sagikazarmark/cryptbox/issues/42) |

The reader did not guess runtime/TLS selections or an email normalization policy.
Those decisions still require the consumer/application guidance above. Existing
safe-use warnings do not turn incomplete integration or operations into completed
journeys. Next: follow the [maintenance procedure](documentation.md) when repeating
this walk after those tickets land.
