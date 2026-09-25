#!/bin/sh
# Run from the repository root. The same invocation is used in CI and Dagger.
set -eu

case "${1:-local}" in
    local)
        # Release rustdoc must use absolute web links. Validate development
        # destinations against this checkout even before they are published.
        set -- --offline --remap \
            "^https://github.com/sagikazarmark/cryptbox/blob/main/ file://$(pwd)/"
        ;;
    external) set -- --scheme https --scheme http ;;
    *) printf 'Usage: sh scripts/check-links.sh [local|external]\n' >&2; exit 2 ;;
esac

# Rust files are parsed as Markdown to include authored rustdoc web links.
# Rust intra-doc references are resolved separately by cargo doc.
# PDF fragments name sections/pages that an HTML/Markdown checker cannot parse.
lychee --config lychee.toml --default-extension md \
    --remap '(https?://[^#]+\.pdf)#\S+ $1' \
    "$@" '*.md' 'docs/*.md' 'src/**/*.rs'
