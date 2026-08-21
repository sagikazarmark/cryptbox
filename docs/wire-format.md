# Experimental Wire Format

This document records the provisional v0.1 formats implemented by CryptBox.
They are not stable protocol commitments and must receive focused cryptographic
review plus independently generated vectors before a production release.

All identifiers use their 16-byte RFC UUID network-order representation. All
multibyte integers are unsigned big-endian values.

## Encryption Suite 1

Suite ID `1` combines:

- HKDF-SHA-256 for per-binding operational-key derivation;
- XChaCha20-Poly1305 with a 32-byte key, 24-byte OS-random nonce, and full 16-byte tag;
- the exact envelope metadata and expected binding as authenticated data.

Applications cannot compose or register arbitrary primitives. New encryption
uses suite 1; unknown suites are rejected before authentication because their
construction is unavailable.

### Binding

```text
Unbound:             00
FieldBound(FieldId): 01 || field_id[16]
```

The profile supplies the expected binding. The envelope does not select whether
decryption is bound or unbound.

### Envelope

```text
offset  size  field
0       4     43 42 58 00 ("CBX" + NUL)
4       1     format version = 01
5       1     suite ID = 01
6       16    KeyId
22      24    XChaCha20 nonce
46      N     ciphertext
46+N    16    Poly1305 tag
```

The minimum envelope is 62 bytes and represents empty plaintext. Ciphertext
leaks plaintext length exactly, plus this fixed overhead.

Exact domain labels include the terminating NUL byte:

```text
HKDF salt:      "cryptbox/hkdf-sha256/v1\0"
key info label: "cryptbox/encryption-key/v1\0"
AAD label:      "cryptbox/envelope-aad/v1\0"
```

```text
key_info = key_info_label
        || format_version
        || suite_id
        || key_id
        || binding

aad = aad_label || envelope[0..46] || binding
```

HKDF performs RFC 5869 extract-and-expand using the 32-byte root key and derives
a 32-byte operational key. Wrong binding, modified metadata, nonce, ciphertext,
or tag all fail authentication. An unknown `KeyId` is reported before
authentication because no key is available.

The implementation uses the RustCrypto HKDF and HMAC crates and enables HMAC,
SHA-256, and Poly1305 zeroization support. This erases keyed digest state,
buffered hash input, and direct HMAC outputs on drop. CryptBox also immediately
erases the HKDF extract output and holds derived keys and returned MACs in
zeroizing buffers. As with other Rust cryptography implementations, transient
crate- and compiler-generated stack copies remain part of the targeted
zeroization and compiler review boundary.

### Provisional Envelope Vector

```text
root key:   1111111111111111111111111111111111111111111111111111111111111111
KeyId:      11111111-2222-4333-8444-555555555555
binding:    00
plaintext:  6372797074626f7820766563746f72 ("cryptbox vector")
nonce:      000102030405060708090a0b0c0d0e0f1011121314151617
envelope:   43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f1011121314151617c5ecf67a1ebf136378025485a1e4b961044c53838d7bf1c05cc81b81ae89d5
```

The vector is generated and consumed in separate tests, but it has not yet
been cross-checked against an independent implementation.

The corresponding field-bound vector uses the same root key, `KeyId`,
plaintext, and nonce with `FieldId 12345678-1234-4234-8234-1234567890ab`:

```text
binding:    01123456781234423482341234567890ab
envelope:   43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d
```

## Blind-Index Format 1

Format 1 combines HKDF-SHA-256, HMAC-SHA-256, and explicit most-significant-bit
truncation. Root blind-index keys must be independent from encryption keys.

```text
offset  size          field
0       1             format version = 01
1       16            IndexKeyId
17      2             retained bit count
19      ceil(bits/8)  truncated HMAC
```

Valid precision is 1 through 256 bits. For non-byte-aligned precision, unused
low bits in the final byte are zero and noncanonical stored values are rejected.

Exact domain labels include the terminating NUL byte:

```text
key info label: "cryptbox/blind-index-key/v1\0"
MAC label:      "cryptbox/blind-index-value/v1\0"
```

```text
header = format_version || index_key_id || bits_be
context = header || binding || index_id
key_info = key_info_label || context
mac_input = MAC_label || context || normalized_length_be_u64 || normalized_bytes
```

### Provisional Blind-Index Vector

```text
root key:     2222222222222222222222222222222222222222222222222222222222222222
IndexKeyId:   aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
IndexId:      abcdefab-cdef-4def-8def-abcdefabcdef
FieldId:      12345678-1234-4234-8234-1234567890ab
binding:      01123456781234423482341234567890ab
bits:         13
normalized:   6e6f726d616c697a6564406578616d706c652e636f6d ("normalized@example.com")
stored value: 01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0
```

The final byte `e0` has its three unused low bits cleared. This vector has not
yet been cross-checked against an independent implementation.
