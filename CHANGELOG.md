# Changelog

## Unreleased

- Add the opt-in `serde` feature for explicit stored-byte serialization of
  ciphertext and blind indexes (not included in the published 0.5.0 crate).

- Add task-oriented adoption guidance, document authority and version distinctions,
  shared feature/platform reference, and reproducible documentation link checks.

## 0.5.0

The following entries were shipped by 0.5.0 but retained an `Unreleased` heading
in that release's changelog. This heading correction does not introduce new API
or format changes.

- Add per-profile ISO/IEC 7816-4 padding with `NoPadding`, `PadToBlock`, and
  `PadToLength` policies. Manual `EncryptionProfile` implementations must add
  `type Padding`; `profile!` defaults to `NoPadding`, so existing stored data
  remains unchanged unless padding is explicitly enabled.
- Generalize the opt-in migration facility from plaintext adoption to legacy
  formats through `LegacyFormat`. `RowState::Plaintext` is now
  `RowState::Legacy`, `SweepReport::plaintext` is now `SweepReport::legacy`, and
  `MaybeEncrypted::is_plaintext` is now `MaybeEncrypted::is_legacy`.
- Defer decoding non-envelope bytes until a `MaybeEncrypted` decrypt call. A
  legacy codec error now occurs during decryption instead of `from_bytes` or
  SQLx `Decode`.
