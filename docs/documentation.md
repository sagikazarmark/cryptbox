# Development and documentation checks

## Local checks

Use Rust, Node.js 18+, Docker for database/diagram checks, and Lychee 0.24.2.
Run from the repository root:

```sh
cargo fmt --all --check
cargo check --locked --all-targets --all-features
sh scripts/check-sqlx-features.sh
cargo clippy --locked --all-targets --all-features -- -D warnings
sh scripts/check-rustdoc.sh
node scripts/doc-snippets.mjs
node scripts/check-consumers.mjs checkout
node scripts/check-consumers.mjs published
sh scripts/check-links.sh local
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
```

The consumer runner builds isolated projects with their declared dependencies.
`checkout` tests this tree; `published` tests exact 0.5.0 and excludes unreleased
Serde support. To focus a recipe, append its name, for example:

```sh
node scripts/check-consumers.mjs checkout custom-profile
node scripts/check-consumers.mjs checkout stored-values
node scripts/check-testing-consumers.mjs checkout
node scripts/check-searchable-consumer.mjs checkout sqlite
```

### Live PostgreSQL

Dagger supplies a disposable PostgreSQL service and runs the live tests and
consumer scenarios, including cases ignored by ordinary `cargo test`:

```sh
dagger check cryptbox:docs
dagger check
```

With your own disposable service, use a database role allowed to create and drop
its test schemas (`CREATE` on the database). Set `DATABASE_URL` and run
`node scripts/check-searchable-consumer.mjs checkout postgres` (or `published`).
Append `sweep` or `migration` for the corresponding scenario. SQLite additionally
supports `recovery`. These scenarios modify their test database.

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

`sh scripts/check-links.sh local` checks files and anchors offline, remapping this
repository's `blob/main/` links to the checkout. Use `external` to check live URLs;
CI runs that network-dependent check separately. Without a local Lychee install:

```sh
docker run --rm --entrypoint sh -v "$PWD:/work" -w /work \
  lycheeverse/lychee:0.24.2 scripts/check-links.sh local
```

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
