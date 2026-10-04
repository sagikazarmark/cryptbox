//! Pins each derive's expansion to the manual impl it stands for.
//!
//! Requires `cargo-expand`. Create or update snapshots with `MACROTEST=overwrite`;
//! otherwise a missing snapshot fails instead of being written.

#[test]
fn derives_expand_to_their_manual_impls() {
    if std::env::var_os("MACROTEST").is_some() {
        macrotest::expand("tests/expand/*.rs");
    } else {
        macrotest::expand_without_refresh("tests/expand/*.rs");
    }
}
