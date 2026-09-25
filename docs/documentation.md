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
denied, then compiles/runs the README, first-field, and testing-guide Rust blocks against a
default-feature library build. The manifest retains `missing_docs`, Clippy `all`/`pedantic` (including
documentation lints), and denied broken intra-doc links, and additionally denies
`rustdoc::missing_crate_level_docs`. The docs.rs all-feature build exposes gated
items; availability is documented on their pages and in the crate feature table
without requiring unstable rustdoc features.

### Shared consumer examples and diagrams

Edit `examples/first_field.rs` (the marked region) or `examples/sqlx_sqlite.rs`,
and the consumer manifests under `docs/snippets/`. Run
`node scripts/doc-snippets.mjs --write` to update the landing/tutorial snippets.
The crate landing includes the generated Markdown directly. The check mode
rejects drift; no required example is marked `ignore`.

`check-consumers.mjs` creates isolated temporary Cargo projects using only those
manifests and public example sources. `checkout` patches the advertised
dependency to this checkout, while `published` downloads exact 0.5.0. Both check
and execute the examples; the first-field tests also check cross-field rejection.
Neither inherits repository dev-dependencies. Temporary projects are removed;
build artifacts are cached under `target/consumers`. Consumer resolution is fresh,
so compatible dependency updates are exercised; each run locks before execution.

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
when editing onboarding. Further durable integration is owned by
[#19](https://github.com/sagikazarmark/cryptbox/issues/19); this link gate does not
claim to compile every Markdown code block. Existing doctests and examples stay
enabled. The four final docs-only journeys are owned by
[#61](https://github.com/sagikazarmark/cryptbox/issues/61).

Next: use the [task index](README.md) to verify discovery after an edit.
