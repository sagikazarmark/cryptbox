# Four docs-only journeys: acceptance evidence

**Evaluation record · 2026-09-25 · development documentation.** Maintainer evidence
for [#61](https://github.com/sagikazarmark/cryptbox/issues/61), using the
[repeatable task briefs and reader boundary](acceptance.md). [All tasks](README.md).
Underlying contracts remain owned by the [canonical references](README.md#canonical-owners).

## Result and scope

At the recorded input snapshot, all four fresh readers completed their assigned tasks. Every journey scored **3
for completeness and safety**, with no unresolved unsafe-use or task-blocking
documentation finding. One non-blocking public-reference wording finding was
repaired and rechecked. Usability weaknesses remain visible in the scores below.

Those are historical trial observations, not a guarantee that later adversarial
review finds no gaps. The subsequent full-branch review reproduced inconsistent
writer/migration validation and a credential-bearing configuration error, and
found incomplete closure/preflight instructions and missing isolated Serde
coverage. See [review follow-up](#full-branch-review-follow-up). The initial scores
are retained as evidence rather than retroactively changed.

**#61 remains incomplete at the publication gate:** the external-link check
returns 404 for development pages not yet on GitHub `main`. Publish the branch
guidance and repeat that check before declaring published-journey acceptance.
Local remapping and successful consumer tasks do not waive this gate.

The input snapshot was `1b61cc32e7ed75f3892dfb5a53688522e32817de` plus the new task
brief. All release consumers used registry **`cryptbox = "=0.5.0"`**, not a local
patch. The readers used development Markdown and generated public API HTML;
labeled GitHub `main` links were resolved locally. This is a **prepublication
acceptance rehearsal**, not a claim that the live release archive already
contains these pages. It does not establish production approval, independent
vector certification or acceptance of the proposed usage policy.

Each reader had a fresh agent context and was instructed to exclude implementation,
library tests, root manifests, checker implementations, diffs and previous trial
results. No reader reported using those materials or requiring outside help.
Public example tests and consumer manifests printed in guides were allowed.
The coordinating maintainer added baseline comparisons afterward so previous
scores did not influence the readers.

### Observed environment

- Native `aarch64-apple-darwin`, Rust **1.98.1**, Cargo **1.98.0**, Clang **21.1.8**.
- OpenSSL **3.6.3**, Node **24.19.0**, Docker client/server **29.6.1**.
- Live integration: `postgres:18-trixie`, disposable loopback port **55461**;
  separate consumer processes and unchanged persisted roots/database on restart.
- Operations: separate SQLite database and independently generated keys per
  runbook. No external database or deployment data was used.
- Dagger **1.0.0-beta.14**, configured Rust **1.98-slim-trixie** and PostgreSQL 18;
  pinned Lychee **0.24.2** and Mermaid CLI **11.12.0** through existing checks.

Three readers initially tried Python for their own extraction/arithmetic/automation;
the environment's shim returned `tool 'python3' not found`. They used available
Node instead. Python is not a guide prerequisite. The integration reader also
corrected its own OpenSSL `-out` option ordering before provisioning; the guide's
redirection command was valid. No Rust/API compiler corrections were required.

## Adoption evidence

Discovery from README: security, first field, integration and operations each
take one link. From rendered crate landing: security and first field take one;
task index then integration/operations take two. The reader independently checked
both entry points, authority labels, feature/platform guidance and durable keys.

The reader created the exact first-field manifest/program in a fresh project and
ran `cargo run`. Output:

```text
Compiling cryptbox v0.5.0
Field-bound round trip succeeded.
```

Both documented assertions passed: authenticated decryption returned the email,
and encryption retained the original plaintext. The generated consumer lockfile
identified the registry dependency. No optional feature or database was needed.

The reader correctly distinguished `Encrypted` plaintext from stored `Ciphertext`,
binding context from key supply, ephemeral demonstration keys from durable roots,
and independent encryption/index roles. It identified persistent IDs, codec,
binding, padding mode, normalization and precision as migration-sensitive.
Suitability was limited to experimental application-layer field protection with
separate keys; application compromise, replay, same-field substitution, leakage,
row/tenant isolation and outstanding assurance gates were not obscured.

No undefined task-critical terms or API guesses remained. The durable continuation's
large multipurpose program reduced the progressive-disclosure score.

## Application-developer evidence

Discovery: README → searchable SQLx → testing/diagnostics and its public snippets;
README → concepts and authority. The reader materialized the published manifest,
program and PostgreSQL schema without consulting a checker. It used a dedicated
container name/port and preserved the native toolchain environment in the new shell.

Reproduce using [searchable SQLx sections 1–7](searchable-sqlx.md), with an unused
port and fresh key directory. The reader ran `cargo check --all-targets`,
`cargo build`, and `cargo tree -i cryptbox` before executing these commands:

| Command or task | Observed result |
| --- | --- |
| `init` | `Schema ready.` on live PostgreSQL |
| `put 1 ' Alice@Example.com '` | Prepared insert succeeded |
| `put-null 2`; `get 2` | `2: NULL`; both stored columns were NULL |
| `put 2 before@example.com`; `put 2 after@example.com` | Prepared update replaced both representations |
| Search before / AFTER | `Matches: []; rejected: 0.` / `Matches: [2]; rejected: 0.` |
| `put-null 2` | Cleared both columns |
| New shell/process, same roots/storage, generation 2: `get 1` | Original whitespace-preserving plaintext survived restart |
| `put 3 alice@example.com`; search ALICE | `Matches: [1, 3]; rejected: 0.` across E1/I1 and E2/I2 |
| Put bob at 4; `demo-false-candidate 4 3`; search ALICE | `Matches: [1, 3]; rejected: 1.`; row 4 still decrypted to bob |
| Repair row 4; search with generation 1 current | Both generations still found through readable probes |
| `cargo check --features macro-check` | Passed against the live schema |
| `macro-get 1`; `macro-get 2`; `macro-put 5 macro@example.com` | Plaintext, NULL and atomic macro write succeeded; search returned `[5]` |

Seven independent startup-failure cases exited 1 with empty stdout and sanitized
`key configuration` errors: missing directory, invalid hex, wrong length, absent
key-directory variable, absent generation, invalid generation and partial
independent selectors. `DATABASE_URL` was absent in these failing processes;
key loading failed before database configuration/access. Original configuration
still read row 1 afterward. No keys were regenerated to repair a failure.

The reader also typechecked and executed all three public testing recipes:

```text
test result: ok. 2 passed; 0 failed; 0 ignored
Automatic adapter round trip succeeded.
Automatic adapter round trip succeeded.
field_id=ca274e85-63c4-4f7d-a255-2dfecbfe5e25 field_name=user-email operation=decrypt error=authentication_failed
```

Local tests ran with two test threads; differing automatic-adapter fixtures ran
in separate processes. The reader identified static-context lifetime, whole-case
isolation requirements, allowlisted metadata and the danger of logging raw SQLx
error chains. Printed emails were synthetic observations, not deployment advice.
The reader stopped its disposable container after completion.

No task blocker remained. This trial exercised loopback non-TLS PostgreSQL and
live query macros, not deployment TLS or offline SQLx metadata generation.

## Operator evidence

Discovery: README → rotation/sweep/migration; rotation/sweep → retirement. Every
runbook linked its consumer prerequisites. The reader authored sequential Node
automation from those public instructions, with separate databases and a shared
build cache. It recorded **210 build/consumer commands, 20 expected nonzero exits
and zero unexpected failures**. Initial consumers were unmodified public sources.

One operator owned progress, with no background writers except the documented
conflict fixture. Unique immutable integer cursors and two-row pages were used.
NULL rows were excluded according to the maintenance fixture's documented policy.
Each build was preceded by `cargo check --no-default-features --features ...`.

### Staggered rollout and rollback

Reproduce the [rotation runbook](key-rotation.md) using `sqlite`:

- Unstaged B rejected the E2/I1 canary with `UnknownEncryptionKey`.
- A and B authenticated baseline/target canaries before encryption promotion.
  Row 103 used E2/I1 while row 104 still used E1/I1; both remained searchable.
- Before I2 staging, B rejected the E2/I2 canary with
  `canary index generation unavailable or mismatched`.
- After staging, B searched both index generations. The copied false token on
  row 108 was rejected while rows 101–107 matched.
- Restarted configurations verified all canaries. Compatible `staged/staged`
  rollback read E2 data and wrote row 109 under E1/I1. Re-promotion and repair
  produced `[101, 102, 103, 104, 105, 106, 107, 109]`, zero rejections.

This is the documented interleaving of independent CLI process configurations,
not evidence of a long-lived deployment's hot reload or membership barrier.

### Interruption, recovery, conflict and second sweep

Reproduce the [durable sweep walkthrough](reencryption-sweep.md#durable-postgresql-and-sqlite-walkthrough)
using `sqlite,maintenance`:

- `rotation-2`: checkpoint 20/stale 2. Writes-before-checkpoint process returned
  cursor 40, but a fresh process still loaded checkpoint 20. Replay reached 40
  with current 2/stale 0; fresh verification found four current rows.
- A deliberate stale write behind cursor made resume empty, yet fresh verification
  reported current 3/stale 1. Fresh run `rotation-2-repair-1` repaired it.
- Independently provisioned E3/I3 were staged and verified before promotion.
  `sweep-conflict rotation-3` returned `Conflicts: 1.`; the competing
  `concurrent@example.com` write survived and searched as `[10]`.
- New `rotation-3` batches converged all four rows. Authenticated/index audit
  passed; original-value search remained `[20, 30, 40]` during and after sweeping.
- Inadequate E2 configuration failed on E3; its separate failure-rehearsal
  checkpoint stayed `None`.

Interruption was an actual process exit after writes but before checkpoint,
as documented, not a power-loss durability experiment.

### Mixed formats and strict closure

Reproduce [legacy migration](legacy-migration.md) using `sqlite,legacy-migration`:

- Mixed search found `[10, 20, 30, 40, 50, 60]` with one rejection across seven
  rows. Strict plaintext reads failed as expected.
- Damaged previous-solution ciphertext caused authenticated recovery failure;
  progress stayed absent and lookup failed without partial output. Quarantine
  blocked lookup and closure until approved synthetic recovery.
- Checkpoint replay followed 20 → 40. Missing index row 50 and magic-collision
  row 60 stopped progress at 40; documented manual repairs enabled completion.
- Final state verification found seven current rows; closure reported
  `Closure verified: 7 authenticated, validated, indexed rows.`
- A deliberately inconsistent current token passed generation verification but
  failed closure's index audit. Atomic repair and both gates then passed.
- The reader retained recovery copies, physically removed the online legacy key
  and module, removed handler/dispatch and optional legacy manifest dependencies,
  and rebuilt with **`sqlite` only**. Strict reads/search passed; new row 80
  round-tripped. Migration commands were no longer available.

Manual strict cleanup worked on the first build but required edits in several
locations; this remains a maintainability weakness, not an uncompleted task.

### Backup-aware removal and isolated recovery

Reproduce [key retirement](key-retirement.md) using `sqlite,maintenance`:

- Captured E1/I1 rows 10/20 through `VACUUM INTO`; existing destination refused.
- Followed the prose prerequisite to restore **before online removal**, using
  separate preflight storage: readiness, reads, two-row audit and `[10, 20]`
  historical search passed.
- Staged readers; wrote E2/I2 rows 30/40; `retire-2` converged four rows. A false
  current token passed generation verification but failed the independent audit;
  repaired it and repeated both gates.
- Moved E1/I1 material out of the online directory. E2-only live audit/search
  passed; baseline canary and old both-readable configuration failed as expected.
- Restored the unchanged backup into another isolated database with E1/I1.
  Rows 10/20 decrypted and searched; post-backup row 30 was absent.
- E1 with **I2-only** still decrypted row 10 but search returned `[]`; the audit
  failed. Restoring I1 probes recovered `[10, 20]`. Live E2-only service still
  read row 30 and searched `[10, 20, 30]`.

The backup hash remained unchanged. No key destruction occurred. The reader
identified independent index recovery dependencies, schema/software retention,
legacy recovery custody and all-artifact disposition before destruction. A clean
live table cannot establish that old backups no longer need their keys.

The pre-removal rehearsal requires a forward jump to section 4 and back; this
contributed to the progressive-disclosure score. SQLite copying and directory
separation do not validate a production backup platform or access-control system.

## Security-review evidence

Discovery: README → security review → concepts, formats, suite research, proposed
policy and stored-value assurance; crate landing → custom profile/ownership;
public trait pages for codecs, normalizers, providers, binding and padding.

The reader reconstructed both full derivations without inspecting implementation:

- ASCII/NUL label lengths: salt **24**, encryption key **27**, AAD **25**, index
  key **28**, index value **30** bytes.
- UUIDs are decoded network-order bytes; integer lengths/precision big-endian.
  Independent 32-byte roots feed HKDF-SHA-256 Extract and 32-byte Expand.
- Ciphertext prefix **46**, nonce **24**, tag **16**, total `W = P + 62`.
  Binding bytes `00` or `01 || FieldId`; encryption info **46/62** and AAD
  **72/88** bytes for unbound/field-bound respectively.
- Index context **36/52**, info **64/80**, HMAC prefix including normalized-length
  field **74/90** bytes; deterministic normalization precedes HMAC-SHA-256.
  A 13-bit token is **21** bytes with final mask **0xf8**; unused bits clear.
- Ciphertext authenticates expected binding before unpadding/decoding. Index
  domain separation does not authenticate stored index metadata; candidate
  comparison alone does not receive stored metadata or guarantee search completeness.

Node arithmetic reproduced empty, aligned and cap boundaries: block-16 `E=16`
gives `P=32, W=94`; `E=1,048,575` gives `P=1,048,576, W=1,048,638`;
`E=1,048,576` gives `P=1,048,592`, over the **proposed** padded-byte cap.
Fixed padding of 1,048,576 cannot fit an encoded value of that same length.
The reader reproduced `L'=65,542` and the illustrated integrity term below
`2^-65`, while preserving the policy's unreviewed reduction assumptions and
unenforced status. The approximate annual rate implies a 365.25-day averaging
convention; this inference does not change the count budget.

The public custom-profile example was copied into a fresh consumer using the
guide's manifest. `cargo run`, `cargo test --locked` and `cargo tree --locked -i
cryptbox` confirmed the release and produced:

```text
Custom profile round trip and normalized lookup succeeded.
test result: ok. 5 passed; 0 failed; 0 ignored
```

The tests exercised normalized equality/rejection, sanitized sensitive-input
errors, historical/unknown/unavailable provider behavior and both `Secret`
ownership paths. The reader understood synchronous provider snapshots, immutable
ID/material mapping, sealed binding/padding, unavailable row/tenant binding,
borrowing/cloning lifetimes, growth-buffer obligations and erasure limits.
These checks do not prove physical erasure or independently certify vectors.

### Bounded correction

The public `EncryptionProfile` introduction called all associated types
persistent schema, overbroadly including `Keys`. It now names codec representation,
binding and padding presence, and explains that changing key-context implementation
alone does not change schema while required immutable key pairs must remain
resolvable. Explicit-provider APIs ignore that context. The affected public HTML
was rebuilt and the security reader repeated this decision after correction.

## Before/after scorecards

Each cell is **parent baseline → initial acceptance-trial score**. Baseline is #51's review
of `efd810efabebdcd01af218ecd502bda53211ad33`; reader scores are qualitative
judgments of these explicit briefs, not a controlled experiment or security metric.

| Criterion | Adoption | Integration | Operations | Security |
| --- | ---: | ---: | ---: | ---: |
| Audience/task fit | 2 → 3 | 2 → 3 | 1 → 3 | 2 → 3 |
| Correctness/freshness | 2 → 3 | 2 → 3 | 2 → 3 | 2 → 2 |
| Completeness | 1 → 3 | 1 → 3 | 1 → 3 | 2 → 3 |
| Conceptual model | 2 → 3 | 3 → 3 | 3 → 3 | 3 → 3 |
| Progressive disclosure | 1 → 2 | 2 → 2 | 2 → 2 | 2 → 3 |
| Findability | 1 → 3 | 2 → 3 | 2 → 3 | 1 → 3 |
| Terminology | 2 → 3 | 2 → 3 | 2 → 3 | 2 → 3 |
| Safety | 2 → 3 | 3 → 3 | 1 → 3 | 2 → 3 |
| Maintainability | 2 → 3 | 2 → 2 | 1 → 2 | 2 → 3 |

Security's initial final-trial freshness score was 2 for the wording finding.
After rereading the rebuilt public `EncryptionProfile` HTML, the same reader
confirmed that changing `Keys` alone needs no migration while required key pairs
must remain resolvable, and separately re-scored freshness **3/3**. The table
preserves the initial independent judgment. Remaining friction: the
large all-purpose consumer precedes basic CRUD, testing mixes reader and
maintainer instructions, and strict migration cleanup is manual. None blocked a
task or left an unsafe-use finding unresolved.

## Maintained-page audit

The audit covers root reader material and every reader-facing `docs/*.md` page.
Agent configuration, implementation/tests and generated build artifacts are not
reader pages. “Index” below means the maintained documentation task index;
its canonical-owner table supplies additional inbound links.

| Surface | Intended reader/task; primary role | Authority / canonical ownership | Inbound navigation |
| --- | --- | --- | --- |
| Project README | Evaluator orientation; explanation/landing | Development positioning and task discovery, release caveat | Repository entry; index |
| Generated crate landing/API | Developer exact contracts; reference | Checkout API, explicitly distinguishes release | README; index; guide API links |
| CONTEXT | All readers, vocabulary; explanation | Current canonical terms | Index; concepts |
| CHANGELOG | Release users, changes; reference | Historical release record | Index/version guide |
| `docs/README.md` | All readers, choose a task; navigation | Development index and ownership | README; crate landing; guide backlinks |
| `features.md` | Evaluator/developer prerequisites; reference | Shared source included in crate landing | README; index; security |
| `security.md` | Evaluator/reviewer; explanation | Experimental boundaries and unfinished gates | Both landings; index |
| `concepts.md` | Developer/reviewer mental model; explanation | Current relationships/ownership, glossary links | README; index; custom profile |
| `first-field.md` | New developer first success; tutorial | Published 0.5.0 setup | Both landings; index |
| `first-field-sqlite.md` | New developer storage; tutorial | Published 0.5.0, ephemeral fixture | First field; index |
| `searchable-sqlx.md` | Developer durable CRUD/search; tutorial | Published 0.5.0, canonical consumer source | README; index; first field |
| `stored-values.md` | Developer serialization/assurance; tutorial | Explicitly unreleased Serde; current assurance procedure | README; index; security |
| `testing.md` | Developer safe tests/diagnostics; how-to | Published consumer recipes plus labeled development checks | README; index; SQLx |
| `custom-profile.md` | Extension implementor; how-to | Published API, development obligations beside public traits | Index; crate landing; security |
| `key-rotation.md` | Operator fleet promotion; how-to | Published API, canonical readiness/lifecycle | README; index; SQLx |
| `reencryption-sweep.md` | Operator maintenance; how-to | Published API, run identity/progress/verification | README; index; rotation |
| `legacy-migration.md` | Operator adoption/closure; how-to | Published API, canonical mixed-format procedure | README; index; SQLx |
| `plaintext-migration.md` | Existing-link reader; how-to redirect | Explicitly redirects to canonical legacy migration | Index |
| `key-retirement.md` | Operator removal/restore; how-to | Published API, recovery inventory and retention | Index; rotation; sweep |
| `wire-format.md` | Reviewer format reconstruction; reference | Experimental format 1, provisional vectors | Index; security |
| `suite-evaluation.md` | Reviewer suite rationale; explanation | Dated research, not approval | Index; security |
| `suite-1-usage-policy.md` | Reviewer size/budget decisions; reference | Proposed, unenforced, not approval | Index; security; format |
| `spec.md` | Historical design reader; reference | Applicability banner, superseded API sketches | Index authority table |
| `documentation.md` | Maintainer checks/publication; how-to | Development tooling | README; index |
| `adoption-walk.md` | Maintainer earlier findings; reference record | Dated #21/#52 evidence, superseded final assessment here | Index; maintenance |
| `first-field-walk.md` | Maintainer onboarding evidence; reference record | Dated #54 bounded trial | Index; maintenance |
| `searchable-sqlx-walk.md` | Maintainer integration evidence; reference record | Dated #19 bounded trial | Index; SQLx; maintenance |
| `acceptance.md` | Maintainer rerun tasks; how-to protocol | Final briefs and evidence requirements | Index; maintenance |
| This page | Maintainer assess outcomes; reference record | Dated final evidence, not a runtime contract | Protocol; index; maintenance |

All main journeys meet the two-link target from both primary entry points.
Examples and snippets are reached through their owning tutorial or the example
index. Lifecycle, lookup and rotation diagrams have canonical Mermaid sources;
the lifecycle SVG is generated for rustdoc. Adjacent prose states ownership and
lookup/rollout boundaries. Mechanical checks below cover synchronization/rendering.

Version audit found explicit 0.5.0 API links and explicit development-only links
where that archive lacks newer guidance/Serde. Historical records describe their
own snapshots, not present gaps. Link success alone is not proof of release parity.

## Mechanical checks and reproduction

Maintainer automation is separate from the docs-only observations above. Use the
[documented local, GitHub Actions and Dagger paths](documentation.md). No hosted
Actions run is claimed by a local execution of its commands.

| Check | Result |
| --- | --- |
| `cargo check --locked --all-targets --all-features` | Passed |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `sh scripts/check-sqlx-features.sh` | All independent backend/migration checks passed |
| `sh scripts/check-rustdoc.sh` | Default/all-feature docs with denied warnings; README 1 and first-field 2 doctests passed |
| `dagger check cryptbox:docs` | All four checks passed: rustdoc, shared snippets/isolated consumers in checkout and published modes, local links/anchors, generated diagrams |
| `dagger check cryptbox:test:postgres` | Passed: live checkout/published consumers, rotation/sweep/migration, SQLx and migration PostgreSQL test targets including ignored server cases |
| `cargo test --locked --test profile_macro --all-features` | 3 passed after the public-reference correction |
| `cargo test --locked --all-targets --all-features` | Final full suite passed; 3 server-dependent tests ignored here and executed by the separate live Dagger check |
| `cargo test --locked --doc --all-features` | All 8 passed, including 3 compile-fail cases |
| CI's seven `cargo run --locked --example ...` commands | Key rotation, sweep, plaintext/legacy migration, blind indexes, stored values and SQLite all executed successfully |
| `dagger -c 'cryptbox 1.98-slim-trixie \| docs \| external-links'` | **Failed**, exit 2: 30 link occurrences return 404 for unpublished development destinations on GitHub `main`; 478 total, 179 unique, 111 OK, 337 excluded, 6 redirects |

The first two Dagger invocations hit the caller's 120-second timeout. Repeating
with a 20-minute allowance passed in 2m50s (docs) and 3m22s (PostgreSQL), with no
code/configuration workaround. Successful typechecks were never substituted for
the live execution results.

The external failures are the development task index, stored values, testing,
concepts/ownership, custom profile, first field and security pages linked from
the feature reference and public API docs. They resolve locally; the branch
has not made them available at their published destinations. No exclusion or
HTTP-success rule was broadened. See the
[external-check trace](https://dagger.cloud/sagikazarmark/traces/980398f88fa87febdb0e83ed6e7c248d).
This explicit scheduled/network check is separate from the deterministic PR
gate, but its publication limitation remains part of final acceptance.

After the correction and evidence pages were added, `dagger check cryptbox:docs`
passed all four checks again (2m3s), including the new pages' local anchors and
the rebuilt public API. Typechecking and the focused profile target were repeated
after the only Rust-file edit; the full suite ran once at the end.

GitHub Actions alignment was checked in `ci.yaml` (rustdoc, consumers, examples,
suite), `docs.yaml` (local plus scheduled/manual external links), and
`dagger.yaml` (Dagger checks including live PostgreSQL). These are executions of
the shared check paths locally, not hosted workflow run results.

## Two-axis code review

Reviewed the five-file change against the user-selected baseline `1b61cc3` with
independent Standards and Spec reviewers. Standards found no documented-rule
violation and one low-severity scorecard-labeling ambiguity: the table said
“final” while preserving the initial security score. The heading now explicitly
names the initial acceptance trial; the corrected 3/3 remains separately recorded.
Spec found no actionable omissions or incorrect behavior and confirmed that
published acceptance is honestly left pending. No runtime behavior changed.

## Full-branch review follow-up

The later review compared the full documentation effort (`efd810e` through
`ddb19d1`), rather than only the acceptance-record commit. Its corrections are:

- Missing/non-UTF-8 database configuration is mapped to a static category before
  connection, with a process-level regression containing a synthetic password.
- Writers, transitional recovery/reads, and closure share one whitespace-aware
  application validator. Regression cases cover accepted padded/case-varied
  values, rejection before invalid writes, and continued search/closure.
- Migration closure and maintenance use one paginated authenticated/application/
  index audit. The linked closure summary requires all quarantine, discriminator,
  inventory, provenance, consistency, and strict-reader cutover gates.
- Recovery preflight now has executable key-copy and separate restore commands.
  The checker exercises recovery before online removal and a fresh restore after
  removal while preserving the original backup.
- The stored-values manifest is shared with its guide and exercised in an
  isolated checkout-only consumer, without repository development dependencies.

These targeted regressions supplement the historical fresh-reader trials; they
do not by themselves constitute a new four-agent evaluation. Publication remains
pending: after this branch and its fixes reach `main`, run the external-link check,
repeat the affected reader briefs against the published destinations, and record
the actual results before closing #61. Do not remap remote failures or weaken the
link gate to turn a development rehearsal into published acceptance.

Follow-up verification on the corrected working tree:

| Check | Result |
| --- | --- |
| Shared snippet synchronization and standalone consumer Rust formatting | Passed |
| Focused checkout SQLite migration regression | Passed, including accepted whitespace-preserving writes and rejected invalid writes |
| Focused checkout SQLite recovery regression | Passed, including pre-removal preflight and a fresh post-removal restore |
| Isolated checkout stored-values consumer | Typecheck, execution, and Clippy passed using the guide's exact manifest |
| `dagger check cryptbox:docs cryptbox:test:postgres` | All five checks passed, including checkout/published consumers, diagrams, local links, rustdoc, and live PostgreSQL scenarios |
| `sh scripts/check-links.sh external` with Lychee 0.24.2 | Still blocked: 30 occurrences of unpublished development destinations on `main` return 404; 481 total, 182 unique, 112 OK, 339 excluded |

Next: rerun the [briefs](acceptance.md) with fresh readers after future changes,
preserving failures and limitations even when other checks pass.
