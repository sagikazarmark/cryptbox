# Repeat the four docs-only acceptance journeys

**Evaluation protocol · development documentation · #61.** For maintainers
checking the public consumer journeys in [#51](https://github.com/sagikazarmark/cryptbox/issues/51).
This page owns the final task briefs and evidence index, not the underlying API
contracts. [All tasks](README.md) · [Mechanical checks](documentation.md).

## Reader boundary and prerequisites

Start four fresh agents, one per brief below. Give each only the project README,
reader-facing `docs/*.md`, `CONTEXT.md`, generated public API HTML, published
examples and `docs/snippets/*`, plus the task and prerequisites. Exclude library
implementation, library tests, repository manifests, checker implementations,
diffs and previous evaluation records (including the results linked below). Do not
use rustdoc source links. Consumer manifests printed in guides are allowed.
Compiler feedback is allowed; record
every corrective inference. Maintainer automation results are separate evidence.

For a development checkout, resolve explicitly labeled GitHub `main` guidance
links to that checkout and use its generated public API HTML, recording that this
is a prepublication rehearsal, not proof that the live site contains these pages.
Use the exact published `cryptbox = "=0.5.0"` for release consumer tasks. The
stored-byte Serde continuation is explicitly unreleased.

Declared environment: native macOS/Linux; current stable Rust/Cargo, native C
compiler/linker and SDK; registry/network access; OpenSSL CLI; Bash or Zsh; Docker
with a disposable PostgreSQL 18 service and an unused loopback port. SQLite needs
no server. Each agent owns a separate temporary directory, database and key set;
never use application data. Generated public API pages are supplied before the
trial. Preserve the toolchain environment across process restarts. Agents may
create consumer projects and test them, but cannot use implementation inspection
to repair missing instructions. Record infrastructure limitations separately.

## Task briefs

### Adoption evaluator

Starting at README and independently at the rendered crate landing page, decide
whether confidential-email storage with SQLx PostgreSQL fits the threat model and
maturity. Identify unsuitable uses, outstanding gates, Rust/platform/entropy and
feature/runtime/TLS prerequisites, and current/proposed/historical authority.
Create a fresh consumer and execute the first field-bound round trip. Explain
plaintext versus stored types, unit context, independent durable keys and
persistent-schema decisions. Find the durable-storage continuation and the four
main journeys within two navigation links from both entry points.

### Application developer

Create a fresh consumer using the published manifest and program. Start live
PostgreSQL, provision independent stable roots, apply schema, typecheck and run
prepared inserts and updates, paired NULL storage, deferred authenticated reads,
all-generation probes and normalized candidate rejection. Exit and restart the
actual process with unchanged keys/data. Verify query macros and startup failures
as documented. Use the testing/diagnostics guidance to identify process isolation
and safe logging rules. Compilation alone cannot complete this task.

### Operator

Using the public consumer and runbooks, execute staggered reader staging,
independent encryption/index promotion and compatible rollback; interrupted and
resumed durable batches, replay before checkpoint, guarded concurrent writes,
fresh verification/recovery behind the cursor and a second rotation. Execute
mixed-format search, exceptional-row recovery and strict closure, rebuilding
without migration-only configuration. Capture a pre-rotation backup, converge
live storage, remove online historical keys, and restore/read/search separately
with recovery material. Explain why live convergence cannot authorize destruction.
SQLite is the documented backup rehearsal; use a fresh database per procedure.

### Security reviewer

Without implementation inspection, establish authority and unfinished gates;
distinguish parsing/generation checks, ciphertext authentication, index domain
separation and candidate comparison. Assess available binding, replay/substitution
limits, leakage and uniqueness. Reconstruct encryption/index derivations from
the format reference, including labels, lengths, byte order and truncation.
Recalculate padding-aware quantities and proposed limits. Review codec,
normalizer, provider and ownership/erasure contracts, and execute the documented
custom-profile consumer checks where practical. Do not turn documentation
consistency into independent vector certification or production approval.

## Required evidence

Each reader records discovery paths, undefined terms, guesses, compiler-driven
corrections, outside help, unsafe plausible choices, infrastructure limitations,
commands and actual outputs/completion. Score all nine criteria individually:
audience/task fit, correctness/freshness, completeness, conceptual model,
progressive disclosure, findability, terminology, safety and maintainability.
Use 0 absent/unsafe, 1 substantial gaps, 2 workable with friction, 3 independent
success. After collecting independent scores, the coordinating maintainer compares
them with the parent baseline; do not expose prior results to the fresh readers
or use totals to hide a blocker.
Completeness and safety must each reach 3 in every journey, with no unresolved
unsafe-use or task-blocking documentation finding. Repair bounded gaps and repeat
affected tasks; substantive blockers keep acceptance incomplete.

## Evidence and acceptance result

See the [2026-09-25 results, scorecards and maintained-page audit](acceptance-results.md).
These qualitative scores assess reader success, not cryptographic assurance.
