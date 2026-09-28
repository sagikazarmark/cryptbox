# Development and documentation checks

## Local checks

Use Rust, cargo-hack 0.6.45, Node.js 18+, and Docker for database/diagram checks.
The development shell includes cargo-hack; otherwise install it with
`cargo install cargo-hack --version 0.6.45 --locked`.
Run from the repository root:

```sh
cargo fmt --all --check
cargo check --locked --all-targets --all-features
cargo hack test --locked --feature-powerset --depth 2
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
node scripts/doc-snippets.mjs
cargo test --locked --all-targets --all-features
cargo test --locked --doc
cargo test --locked --doc --all-features
```

The README and first-field tutorial are included under `cfg(doctest)` in
`src/lib.rs`, so their Rust snippets run with the crate's documentation tests.
Dagger's Rust module checks API docs with warnings denied across default,
no-default, individual, and all features. Its test matrix includes doctests and
uses `--feature-powerset --depth 2` to cover individual features and pairs, including
`migrate,sqlx-postgres` and `migrate,sqlx-sqlite` independently. These matrices are
configured by `hack.doc` and `hack.test` in `Cargo.toml`; GitHub Actions runs the
same test matrix. The separate all-target, all-feature test run covers the full
feature set together.
Run `dagger check rust:doc rust:test` for both matrices.

The `cryptbox-derive` workspace package is outside the default members, so the
commands above reach it only through `cryptbox`'s `derive` feature. Its compiler
diagnostics (trybuild) and expansion snapshots (macrotest) need
[cargo-expand](https://github.com/dtolnay/cargo-expand) 1.0.126
(`cargo install cargo-expand --version 1.0.126 --locked`):

```sh
cargo clippy --locked -p cryptbox-derive --all-targets -- -D warnings
cargo test --locked -p cryptbox-derive
```

Refresh the snapshots after an intended change with `TRYBUILD=overwrite` or
`MACROTEST=overwrite`, then review the diff. Dagger runs them as
`dagger check cryptbox:test:derive`.

Process-level scenarios are Rust integration tests in `tests/e2e.rs`, included in
the ordinary all-feature test run. They cover durable rotation, sweep restart,
mixed-format migration and closure, backup recovery, SQLx macros, and sanitized
diagnostics. Basic API behavior remains in the existing integration tests and
example tests. To focus a scenario:

```sh
cargo test --locked --test e2e --all-features sqlite_rotation
cargo test --locked --test e2e --all-features sqlite_migration
```

The `examples/searchable` workspace package builds the sample application against
the local library. Its app-specific features allow tests to rebuild with SQLx
macros or without legacy migration support. The `tests/fixtures/app` package
contains the automatic-adapter and diagnostics fixtures. Executables are copied
into each scenario's temporary directory; keys and databases persist across child processes and are
removed afterwards. Builds share `target/e2e` (under `CARGO_TARGET_DIR` if set).
These fixture-driven tests are checkout-only and excluded from the crate archive.

### Live PostgreSQL

Dagger supplies a disposable PostgreSQL service and runs the live tests and
E2E scenarios, including cases ignored by ordinary `cargo test`:

```sh
dagger check cryptbox:test:postgres
dagger check
```

With your own disposable service, use a database role allowed to create and drop
its test schemas (`CREATE` on the database). Set `DATABASE_URL` and run:

```sh
cargo test --locked --test e2e --no-default-features --features migrate,sqlx-postgres -- --include-ignored
```

Each PostgreSQL scenario creates and removes its own schema. Recovery uses SQLite
database copies. These scenarios modify their test database.

### Live Restate

The `tests/restate` workspace package runs a service against a real
`restate-server`. It suspends and replays after a `ctx.set` and a call carrying
`Sealed<F>`, and checks that sealing outside `ctx.run` is a journal mismatch.
It needs Rust 1.92 and a Unix host. Dagger runs it with the server binary from
the Restate image:

```sh
dagger check cryptbox:test:restate
```

Otherwise, name a server binary, or a running server that can reach the test
endpoint (a container reaches it at `host.docker.internal`; set
`RESTATE_ENDPOINT_HOST` to change it):

```sh
RESTATE_SERVER_BIN=/path/to/restate-server cargo test --locked -p cryptbox-restate-e2e -- --ignored
RESTATE_ADMIN_URL=http://127.0.0.1:9070 RESTATE_INGRESS_URL=http://127.0.0.1:8080 \
  cargo test --locked -p cryptbox-restate-e2e -- --ignored
```

## Editing shared sources

- Edit the README quickstart directly; it is independent of the first-field
  tutorial and checked by doctests.
- `docs/features.md` is included directly in rustdoc.
- Edit runnable sources under `examples/` or `docs/snippets/`, then run
  `node scripts/doc-snippets.mjs --write` to refresh marked excerpts. Keep excerpts
  small; link complete programs rather than embedding them.
- Complete demonstrations live in example directories with a README explaining
  how to run, inspect, and adapt them. Keep example-specific SQL and modules there.
  The searchable README's excerpts are checked against its adjacent `main.rs`.
- Mermaid sources are in `docs/diagrams/`. The lifecycle SVG is included in
  rustdoc; regenerate and validate diagrams with:

```sh
docker run --rm --user "$(id -u):$(id -g)" --entrypoint sh \
  -v "$PWD:/data" -w /data \
  ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.12.0@sha256:bad64c9d9ad917c8dfbe9d9e9c162b96f6615ff019b37058638d16eb27ce7783 \
  scripts/check-diagrams.sh write
```

Omit `write` to check regeneration. The Markdown-only rotation and trust-boundary
diagrams are rendered for validation without committing SVG copies.

## Links and publication

Dagger uses the shared Lychee module and discovers `lychee.toml` automatically:

```sh
dagger check lychee:check
```

This checks workspace links, including external URLs, as part of `dagger check`.

Describe the API and behavior directly, without crate-version labels or
unreleased-status commentary. Use `latest` for API links on docs.rs; dependency
versions belong in runnable manifests. Format and suite IDs change only when
their contracts change.

## Writing for the reader's task

Use [Diátaxis](https://diataxis.fr/compass/) to clarify the reader need served by a
page or section:

- **Tutorial:** guide a learning exercise with a reliable path and observable results.
- **How-to:** help a reader accomplish a bounded task in their own application.
- **Explanation:** develop understanding of a question, its reasons, and trade-offs.
- **Reference:** describe exact contracts that readers consult while working.

Difficulty does not determine the form: an advanced exercise is still a tutorial.
Keep introductory concepts separate from exhaustive contracts, and give optional
tutorial branches a clear completion point. An automated test scenario is a
rehearsal, not a manual walkthrough. When linking a next step, check that its
prerequisites match the data and configuration left by the preceding exercise.

The documentation index follows reader journeys; it is not a mandatory reading
order. Security and reference should be directly accessible at every stage.
Improve pages [incrementally](https://diataxis.fr/how-to-use-diataxis/) rather than
creating empty categories or a separate page for every change of subject.

Keep one maintained explanation per fact, with brief point-of-use warnings where
needed. Run relevant automated checks; for materially changed instructions, have
an unfamiliar reader attempt the affected task and record blockers in the PR.
Research, review results, and unfinished work belong in issues/PRs, not recurring
documentation reports.

Historical reader trials are frozen at the pre-consolidation revision:
[adoption](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/adoption-walk.md),
[first field](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/first-field-walk.md),
[SQLx](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/searchable-sqlx-walk.md),
and [acceptance results and follow-up](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/acceptance-results.md).
They retain their recorded limitations; archiving them does not close the
[publication follow-up](https://github.com/sagikazarmark/cryptbox/issues/61).
