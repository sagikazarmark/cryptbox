#!/bin/sh
set -eu

export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings"
cargo doc --locked --no-deps --no-default-features
cargo doc --locked --no-deps --all-features

# Compile and execute the landing demonstration and the relocated testing
# recipe with only the default library features, rather than dev-only features.
cargo build --locked --no-default-features
target_dir="${CARGO_TARGET_DIR:-target}"
for page in README.md docs/first-field.md docs/testing.md; do
    rustdoc --edition 2024 --test "$page" \
        --extern "cryptbox=$target_dir/debug/libcryptbox.rlib" \
        -L "dependency=$target_dir/debug/deps"
done
