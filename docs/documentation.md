# Maintain and check documentation

**How-to · development tooling.** Preserve the [canonical owners](README.md#canonical-owners)
when editing a contract. [All tasks](README.md).

The [feature/platform reference](features.md) is included directly in `src/lib.rs`
with `include_str!`, so its Markdown and rendered crate versions have one source.

## Local checks

From the repository root, with Rust, Node.js **18 or newer**, Docker, and Lychee
**0.24.2** available:

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

Install the pinned Lychee release binary or run the same container as CI:

```sh
docker run --rm --entrypoint sh -v "$PWD:/work" -w /work \
  lycheeverse/lychee:0.24.2 scripts/check-links.sh local
```

`check-rustdoc.sh` builds default and all-feature API documentation with warnings
denied, then compiles/runs the README and first-field Rust blocks against a
default-feature library build. Testing-guide sources run through their declared
consumer manifests below. The manifest retains `missing_docs`, Clippy `all`/`pedantic` (including
documentation lints), and denied broken intra-doc links, and additionally denies
`rustdoc::missing_crate_level_docs`. The docs.rs all-feature build exposes gated
items; availability is documented on their pages and in the crate feature table
without requiring unstable rustdoc features.

### Shared consumer examples and diagrams

Edit `examples/first_field.rs` or `examples/custom_profile.rs` (the marked regions),
`examples/sqlx_sqlite.rs`, the stored-values manifest under `docs/snippets/`, or
the durable consumer source/schema/manifests under `docs/snippets/searchable*`, or
the application-testing sources/manifests under `docs/snippets/testing-*`. Run
`node scripts/doc-snippets.mjs --write` to update the landing/tutorial snippets.
The crate landing includes the generated Markdown directly. The check mode
rejects drift; no required example is marked `ignore`.

`check-consumers.mjs` creates isolated temporary Cargo projects using only those
manifests and public example sources. The checkout-only stored-values recipe
uses its exact path-dependency manifest in a sibling-checkout layout; run
`node scripts/check-consumers.mjs checkout stored-values` to focus it. It checks,
runs, and lints the program with just `serde` enabled on CryptBox and the declared
consumer dependencies. Published mode excludes this unreleased feature.
For the release-compatible recipes, `checkout` patches the advertised
dependency to this checkout, while `published` downloads exact 0.5.0. Both check
and execute the examples; the first-field tests also check cross-field rejection.
The custom-profile tests check codec/normalizer behavior, sanitized failures,
exact-generation lookup, historical reads, unavailable providers, and `Secret`
ownership paths. Run `node scripts/check-consumers.mjs checkout custom-profile`
(or `published`) for a focused typecheck, execution, tests, and Clippy pass.
Its direct `zeroize` dependency is declared in `docs/snippets/custom-profile.toml`.
Neither inherits repository dev-dependencies. Temporary projects are removed;
build artifacts are cached under `target/consumers`. Consumer resolution is fresh,
so compatible dependency updates are exercised; each run locks before execution.

The same runner checks the local-provider, automatic-adapter, and diagnostics
recipes with their own dependencies. Run
`node scripts/check-testing-consumers.mjs checkout` (or `published`), optionally
followed by `local`, `automatic`, or `diagnostics`, for focused checks. Local
cases run concurrently; automatic cases each own a process; diagnostics assert
exact stdout and empty stderr. See the [testing guide](testing.md). Format these
sources with `rustfmt --edition 2024 docs/snippets/testing-*.rs` before refreshing
shared blocks.

The same script runs the durable SQLite consumer. Its focused runner is
`node scripts/check-searchable-consumer.mjs checkout sqlite` (or `published`).
Use `postgres` with a disposable `DATABASE_URL` for live PostgreSQL; Dagger's
existing PostgreSQL check runs both modes. See [execution coverage](testing.md#durable-searchable-consumer).
Format the standalone consumer with `rustfmt --edition 2024 docs/snippets/searchable.rs`
before updating shared blocks. The lookup and fleet-rotation diagrams' canonical
sources are `docs/diagrams/lookup.mmd` and `docs/diagrams/rotation.mmd`, embedded
by the snippet script; they are Markdown-only and need no separate rustdoc SVG.
The diagram check still renders both to validate their Mermaid syntax.
The searchable runner includes the staggered rollout/rollback fixture on both
backends through the same existing CI/Dagger entry points.
Append `sweep` to that focused command for the durable maintenance scenario in
`scripts/check-sweep-consumer.mjs`. It exercises new CLI processes for bounded
batches, durable progress, replay, fresh verification/recovery and a second
rotation. The full consumer checks include it on SQLite; Dagger's PostgreSQL
check executes it against the same service for both dependency modes.
Append `migration` for `scripts/check-migration-consumer.mjs` and the optional
`docs/snippets/migration.rs` module. This extends the same database infrastructure
through mixed-format search, failed recovery, exceptional-row repair and strict
closure, including a rebuild without the legacy handler/key or migration features.
It also checks that whitespace-preserving writes remain readable/searchable during
migration and closure, while invalid application values are rejected before writes.
The [migration guide](legacy-migration.md) owns the procedure; keep its commands
and expected outcomes aligned with this CLI acceptance check.
Append `recovery` with the `sqlite` backend for
`scripts/check-recovery-consumer.mjs`: a pre-rotation database copy, a recovery
rehearsal before online removal, and a second isolated historical-key restore/search
after online key removal. It uses SQLite `VACUUM INTO`
through SQLx and needs no additional backup utility. Both dependency modes run
in the full consumer checks; [key retirement](key-retirement.md) owns this procedure.

The lifecycle's canonical source is `docs/diagrams/lifecycle.mmd`. The snippet
script embeds it in Markdown, and pinned Mermaid CLI produces the committed SVG
included inline in rustdoc (no remote image request or library dependency).
Generate it with:

```sh
docker run --rm --user "$(id -u):$(id -g)" --entrypoint sh \
  -v "$PWD:/data" -w /data \
  ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.12.0@sha256:bad64c9d9ad917c8dfbe9d9e9c162b96f6615ff019b37058638d16eb27ce7783 \
  scripts/check-diagrams.sh write
```

Omit `write` to check byte-for-byte regeneration. The image pins Chromium/fonts
and the configuration fixes Mermaid IDs. GitHub Actions and Dagger run the same
snippet, consumer, and diagram checks (`cryptbox:docs:consumers` and
`cryptbox:docs:diagrams`).

`check-links.sh local` checks local file destinations and Markdown anchors
deterministically with `--offline`. It checks root Markdown, every reader-facing
`docs/*.md`, and source Rust files parsed as Markdown to discover authored web
links. Rustdoc resolves Rust intra-doc links separately. The index also links
every maintained reader-facing page and example.

Absolute links to this repository's `blob/main/` pages are remapped to the
checkout in local mode, including their fragments. This checks development
rustdoc destinations before publication; external mode checks the actual URLs
and may correctly report new pages as 404 until the branch reaches `main`.

The input scope excludes generated `target/` output, tests, and agent workflow
configuration under `docs/agents/` and `AGENTS.md` from the reader-page inventory
(the root glob still checks any present `AGENTS.md` links). Code blocks are not
link prose: Lychee's verbatim extraction is disabled, avoiding sample emails,
database URLs, and historical pseudocode. Authored links surrounding historical
material are checked. PDF resource URLs are checked but their section/page
fragments are stripped, because Lychee cannot extract PDF anchors. There are no
host-wide exclusions or blanket acceptance of HTTP errors/rate limits.

## GitHub Actions and Dagger

GitHub Actions runs local links on pushes/PRs and external links every Monday
and on manual dispatch. External URLs are deliberately separate from the
deterministic PR gate. To reproduce the network check locally:

```sh
sh scripts/check-links.sh external
```

Dagger uses the same scripts, configuration, and Lychee container:

```sh
dagger check cryptbox:docs
dagger -c 'cryptbox 1.98-slim-trixie | docs | external-links'
```

`dagger check` also includes the existing Rust checks, doctests, runnable examples,
and [live PostgreSQL round-trip and sweep checks](testing.md#live-postgresql-sweep-checks).
The network-dependent external check is an explicit
function, not an `@check`, so it does not make every PR depend on remote sites.
Investigate failures rather than broadening exclusions to silence them.

## Publication and reader checks

For each release, update crate-version labels and explicit docs.rs links together
with the package version. Verify the destination actually exists in that release
archive; docs.rs source browsing can show a directory page for a missing file,
so HTTP success alone is insufficient. A development-only guide must be labeled
as development and linked to the repository, not invented in an old archive.
Keep format and suite IDs unchanged unless those contracts actually change.
Keep useful old headings/redirect pages when moving procedures.

Before publishing, repeat the [cold adoption walk](adoption-walk.md). Check both
entry points, including the rendered crate page, and record any inference or
outside help needed. Repeat the [first-field docs-only task](first-field-walk.md)
when editing onboarding and the [integration trial](searchable-sqlx-walk.md) when
editing durable SQLx guidance. This link gate does not
claim to compile every Markdown code block. Existing doctests and examples stay
enabled. Repeat the [four-journey acceptance protocol](acceptance.md) for the final
gate in [#61](https://github.com/sagikazarmark/cryptbox/issues/61); preserve individual
outcomes and limitations as in the [recorded results](acceptance-results.md).

Next: use the [task index](README.md) to verify discovery after an edit.
