# Contributing

## Checks

Use Rust, [cargo-hack](https://github.com/taiki-e/cargo-hack) 0.6.45, and Docker
for the database checks. Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo hack test --locked --feature-powerset --depth 2
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
```

`dagger check` runs the same matrices, the live PostgreSQL tests, and the link
check.

The README is included under `cfg(doctest)`, so its Rust snippets run as
doctests. `docs/features.md` is included in the crate documentation.

## Derive macros

`cryptbox-derive` is outside the default workspace members. Its trybuild and
macrotest snapshots need [cargo-expand](https://github.com/dtolnay/cargo-expand)
1.0.126:

```sh
cargo test --locked -p cryptbox-derive
```

Refresh snapshots after an intended change with `TRYBUILD=overwrite` or
`MACROTEST=overwrite`, then review the diff.

## End-to-end scenarios

`tests/e2e.rs` runs the process-level scenarios (rotation, sweep restart,
migration, backup recovery, SQLx macros, diagnostics) against the fixture app in
`tests/fixtures/app` and the `examples/searchable` package. Focus one with:

```sh
cargo test --locked --test e2e --all-features sqlite_rotation
```

## Live PostgreSQL

`dagger check cryptbox:test:postgres` runs the live tests against a disposable
server. To use your own, set `DATABASE_URL` to a database whose role may create
and drop schemas, and run:

```sh
cargo test --locked --test e2e --no-default-features --features migrate,sqlx-postgres -- --include-ignored
```

These tests modify the database.
