//! Compiler diagnostics for invalid derive input.

#[test]
fn invalid_derives_fail_with_spanned_errors() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
