//! Pins each derive's expansion to the manual impl it stands for.
//!
//! Requires `cargo-expand`, so it is ignored by default: run it with
//! `cargo test -p cryptbox-derive --test expand -- --ignored`. Create or update
//! snapshots with `MACROTEST=overwrite`; otherwise a missing snapshot fails
//! instead of being written.

#[test]
#[ignore = "requires cargo-expand"]
fn derives_expand_to_their_manual_impls() {
    if std::env::var_os("MACROTEST").is_some() {
        macrotest::expand("tests/expand/*.rs");
    } else {
        macrotest::expand_without_refresh("tests/expand/*.rs");
    }
}
