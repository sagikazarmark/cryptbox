#!/bin/sh
set -eu

# Run inside the pinned Mermaid CLI container (see docs/documentation.md).
output=$(mktemp -d)
trap 'rm -rf "$output"' EXIT
/home/mermaidcli/node_modules/.bin/mmdc -i docs/diagrams/lifecycle.mmd -o "$output/lifecycle.svg" \
    -c docs/diagrams/config.json -p /puppeteer-config.json -b transparent
if [ "${1:-check}" = write ]; then
    cp "$output/lifecycle.svg" docs/diagrams/lifecycle.svg
else
    cmp docs/diagrams/lifecycle.svg "$output/lifecycle.svg"
fi
