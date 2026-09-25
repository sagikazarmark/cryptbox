# Maintain and check documentation

**How-to · development tooling.** Preserve the [canonical owners](README.md#canonical-owners)
when editing a contract. [All tasks](README.md).

The [feature/platform reference](features.md) is included directly in `src/lib.rs`
with `include_str!`, so its Markdown and rendered crate versions have one source.

## Local checks

From the repository root, with Rust and Lychee **0.24.2** available:

```sh
cargo fmt --all --check
cargo check --locked --all-targets --all-features
sh scripts/check-sqlx-features.sh
cargo clippy --locked --all-targets --all-features -- -D warnings
sh scripts/check-rustdoc.sh
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
denied, then compiles/runs the README and testing-guide Rust blocks against a
default-feature library build. The manifest retains `missing_docs`, Clippy `all`/`pedantic` (including
documentation lints), and denied broken intra-doc links, and additionally denies
`rustdoc::missing_crate_level_docs`. The docs.rs all-feature build exposes gated
items; availability is documented on their pages and in the crate feature table
without requiring unstable rustdoc features.

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
outside help needed. The complete consumer tutorial/snippet harness is owned by
[#54](https://github.com/sagikazarmark/cryptbox/issues/54) and
[#19](https://github.com/sagikazarmark/cryptbox/issues/19); this link gate does not
claim to compile every Markdown code block. Existing doctests and examples stay
enabled. The four final docs-only journeys are owned by
[#61](https://github.com/sagikazarmark/cryptbox/issues/61).

Next: use the [task index](README.md) to verify discovery after an edit.
