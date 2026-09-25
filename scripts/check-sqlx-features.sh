#!/bin/sh
set -eu

# Keep each backend independent: an all-feature build can hide missing gates.
for features in sqlx-postgres sqlx-sqlite migrate,sqlx-postgres migrate,sqlx-sqlite; do
    cargo check --locked --all-targets --no-default-features --features "$features"
done
