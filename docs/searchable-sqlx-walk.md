# Docs-only searchable SQLx integration walk

**Evaluation record · 2026-09-25 · #19 documentation.** This evaluates the
published-0.5.0 consumer journey, not cryptographic assurance or fleet operations.
[All tasks](README.md) · [Tutorial](searchable-sqlx.md).

## Repeatable task

Give a fresh reader only the project README, task index, first-field and searchable
SQLx tutorials, and linked reader-facing documentation/public API pages. Exclude
implementation, tests, repository manifests, scripts, snippet/example files and
past trial records. Provide native Rust/Cargo/linker, OpenSSL CLI, Docker and
network access as declared prerequisites. Ask them to:

1. Copy the tutorial's manifest, program and schemas into a fresh consumer using
   published CryptBox 0.5.0.
2. Provision independent durable encryption/index roots, then execute both live
   PostgreSQL and file-backed SQLite routes.
3. Insert/update, transition NULL in both directions, read explicit ciphertext,
   search across both generations after process restart, reject a controlled
   false candidate, and compile/execute nullable SQLx macro reads.
4. Check missing/malformed configuration fails, then recover with the original
   configuration without replacing keys.
5. Record every compiler repair, inference, outside-help requirement and unsafe
   plausible choice. Score the dimensions below; distinguish infrastructure
   failure from missing documentation.

## Observed first trial

A fresh agent read only the permitted Markdown pages and copied the embedded
manifest, full Rust program and both schemas using file-editing tools into
`/tmp/opencode/cryptbox-docs-only-20260925-fresh`. This substituted for `cargo new`
scaffolding; it made no application changes and consulted no excluded material.

Environment: ARM64 macOS, Rust 1.98.1, Cargo 1.98.0, Node 24.19.0, OpenSSL 3.6.3,
Docker Engine 29.6.1. It ran its own `postgres:18-trixie` service at host port
55429 instead of 55432, updating the URL consistently. The first `pg_isready`
returned `no response`; the documented retry reported `accepting connections`.

Each command was a separate application process. All successful application
commands exited 0, on **both backends**:

| Task | Observed output |
| --- | --- |
| Apply schema | `Schema ready.` |
| Insert row 1, create NULL row 2 | `Stored 1.`, `Stored 2.`, `2: NULL` |
| Update row 2 from before to after | `2: after@example.com` |
| Search removed email / updated email | `Matches: []; rejected: 0.` / `Matches: [2]; rejected: 0.` |
| Clear row 2 | `2: NULL` |
| Reload original roots in new shell, generation 2, read row 1 | Original ` Alice@Example.com ` including whitespace |
| Insert generation-2 row 3, search Alice | `Matches: [1, 3]; rejected: 0.` |
| Select generation 1 again and search | `Matches: [1, 3]; rejected: 0.` (staged generation covered) |
| Inject row-3 index into Bob's row 4, search Alice | `Matches: [1, 3]; rejected: 1.` |
| Read row 4, then restore its prepared write | `4: bob@example.com`; subsequent Alice lookup rejects zero candidates |
| Compile and run macro reads | Original row-1 plaintext; `2: NULL` |

`env -u DATABASE_URL cargo check` and its SQLite feature variant passed without
a database at build time. Macro checks used the live schema and selected URL;
`cargo check --features macro-check` and
`cargo check --no-default-features --features sqlite,macro-check` passed.

With `DATABASE_URL` unset, invoking each compiled backend binary with a missing
directory, absent key-directory variable, 64 non-hex characters, a short `00`
root, absent generation selector or selector `3` exited 1 with sanitized
`key configuration` errors. Thus key validation failed before database
configuration was consumed. Restoring the original configuration read row 1.

No copied-code compiler repair was needed. One harness adaptation failed: using
`env -i` for restart removed the native SDK environment, producing
`unable to find sdk: 'macosx'` / `library not found for -liconv`. Restarting through
`zsh -f`, retaining the working toolchain environment while explicitly reloading
application variables, succeeded without code or SDK changes. The PostgreSQL
container was stopped and its removal confirmed after execution.

## Documentation improvements and targeted rerun

The first trial identified implicit native linker/SDK prerequisites, indirect
README discovery, repeated SQLite feature-flag translation, and missing copyable
malformed-key fixtures. The tutorial now names the native prerequisites, README
links directly to it, per-backend `consumer()` helpers unify the CRUD commands,
and temporary invalid-key fixtures preserve provisioned roots.

The same docs-only reader reran the updated SQLite write/update/NULL, new-shell
restart, both-generation lookup, false-candidate restoration and negative-fixture
commands. All expected successes/failures matched; quoting preserved the original
whitespace. It found **no remaining task-blocking or safety finding**. This was a
targeted rerun; PostgreSQL evidence remains from the initial complete trial.

Remaining minor friction: SQLite substitutes two explicitly labeled alternatives
in the restart block (URL and helper); the complete dual-backend program remains
long. The copyable `not-hex` fixture tests malformed input but also has wrong length;
the first trial independently exercised 64 invalid characters.

## Scorecard

Scale: **0** absent/blocking, **1** substantial gaps, **2** workable with friction,
**3** independent success for this bounded task. These are reader judgments.

| Criterion | First trial | After targeted rerun |
| --- | --- | --- |
| Audience/task fit | 3 | 3 |
| Correctness/freshness | 3 | 3 |
| Completeness | 2 | 3 |
| Conceptual model | 3 | 3 |
| Progressive disclosure | 2 | 3 |
| Findability | 2 | 3 |
| Terminology | 3 | 3 |
| Safety | 3 | 3 |
| Maintainability | 2 | 2 |
| **Total** | **23/27** | **26/27** |

The maintained [consumer runner](testing.md#durable-searchable-consumer) separately
checks shared source/manifests, checkout and published dependencies, actual
database execution and process boundaries. Next: repeat this reader task after
integration edits using the [documentation checks](documentation.md).
