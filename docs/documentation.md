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

Process-level scenarios are Rust integration tests in `tests/e2e.rs`, included in
the ordinary all-feature test run. They cover durable rotation, sweep restart,
mixed-format migration and closure, backup recovery, SQLx macros, and sanitized
diagnostics. Basic API behavior remains in the existing integration tests and
example tests. To focus a scenario:

```sh
cargo test --locked --test e2e --all-features sqlite_rotation
cargo test --locked --test e2e --all-features sqlite_migration
```

The unpublished `tests/fixtures/app` package builds the documented CLI against the
local library. Its app-specific features allow tests to rebuild with SQLx macros
or without legacy migration support. Executables are copied into each scenario's
temporary directory; keys and databases persist across child processes and are
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

## Editing shared sources

- `docs/features.md` is included directly in rustdoc.
- Edit runnable sources under `examples/` or `docs/snippets/`, then run
  `node scripts/doc-snippets.mjs --write` to refresh marked excerpts. Keep excerpts
  small; link complete programs rather than embedding them.
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

At release, update package/version labels and docs.rs links together; verify each
destination exists in that release. Label development-only features at their use.
Format and suite IDs change only when their contracts change.

Each page should serve one task or reference contract. Keep one maintained
explanation per fact, with brief point-of-use warnings where needed. Run relevant
automated checks; for materially changed instructions, have an unfamiliar reader
attempt the affected task and record blockers in the PR. Research, review results,
and unfinished work belong in issues/PRs, not recurring documentation reports.

Historical reader trials are frozen at the pre-consolidation revision:
[adoption](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/adoption-walk.md),
[first field](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/first-field-walk.md),
[SQLx](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/searchable-sqlx-walk.md),
and [acceptance results and follow-up](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/acceptance-results.md).
They retain their recorded limitations; archiving them does not close the
[publication follow-up](https://github.com/sagikazarmark/cryptbox/issues/61).
