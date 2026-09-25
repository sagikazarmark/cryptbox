# Experimental Wire Format

**Reference · current experimental formats.** [All tasks and versions](README.md).

This document records ciphertext format **1**, blind-index format **1**, and
encryption suite ID **1**, implemented by crate **0.5.0**. The original design
generation called “v0.1” is a separate historical label.
They are not stable protocol commitments and must receive focused cryptographic
review plus independently generated vectors before a production release.

Next: follow the [security review path](security.md#security-review-path) for
suite research, proposed policy, and outstanding gates.

All identifiers use their 16-byte RFC UUID network-order representation. All
multibyte integers are unsigned big-endian values.
In the recipes, `||` concatenates raw bytes, `\0` is one NUL byte (`00`), and
slice endpoints are exclusive. Quoted labels are ASCII bytes, without quotes;
UUID strings and hexadecimal displays must be decoded, not hashed as text.

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

The minimum envelope is 62 bytes and represents empty AEAD plaintext. For an
unpadded profile, ciphertext leaks encoded plaintext length exactly plus this
fixed overhead. A padded profile reveals its padded bucket length instead.
Suite 1 rejects AEAD plaintext longer than `274,877,906,880` bytes on encryption
and payloads implying a longer plaintext on parsing/decryption (RFC 8439's
functional limit). The smaller [proposed operational cap](suite-1-usage-policy.md#plaintext-maximum)
is not library-enforced.

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

### Encryption recipe

Inputs are an independent 32-byte encryption root, its immutable 16-byte
`KeyId`, the expected profile binding, and AEAD plaintext bytes (encoded and
optionally padded as below). Encode `format_version` and `suite_id` as single
bytes `01`; encode `KeyId` and any `FieldId` as 16 UUID network-order bytes.
The binding is exactly `00` for `Unbound`, or `01 || field_id[16]` for
`FieldBound`. Rust names and field diagnostic names are not inputs.

1. Construct `key_info` in the order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, root_key)` (32-byte PRK), then
   `operational_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   The salt is the literal 24-byte `cryptbox/hkdf-sha256/v1\0`; it is neither
   absent nor the nonce. The key-info label is 27 bytes including its NUL.
2. Generate a fresh 24-byte nonce from the operating-system random source for
   each encryption, failing if randomness is unavailable. The fixed nonces in
   the vectors are test inputs only, not a supported application nonce policy.
3. Construct the 46-byte prefix from magic, version, suite, `KeyId`, and nonce
   using the offset table. Form `aad = aad_label || prefix || binding` using
   the 25-byte label including NUL. AAD is 72 bytes unbound or 88 bytes
   field-bound. The binding comes from the expected profile, not stored metadata.
4. Seal the complete AEAD plaintext with XChaCha20-Poly1305 using the 32-byte
   operational key, nonce, and AAD. Append the ciphertext (same length as AEAD
   plaintext) and the full 16-byte tag to the prefix. No text encoding, tag
   truncation, or additional delimiters are applied.

For decryption, structurally validate the envelope, resolve only its exact
`KeyId`, reconstruct the key and AAD with the **expected** binding, and verify
the tag before returning any plaintext. Only after authentication may a typed
profile remove padding and decode. Wrong binding or changes to supported
metadata, nonce, ciphertext, or tag fail authentication. Malformed/unsupported
envelopes and unknown keys can fail before authentication. Successful decryption
does not establish freshness or row identity.

### Plaintext padding

Profiles may apply ISO/IEC 7816-4 padding to encoded plaintext before passing
it to the encryption suite. Padding appends one `80` byte followed by `00`
bytes to the selected block or fixed length. Removal scans backward over zero
bytes, requires the `80` marker, and strips it. It does not depend on the block
size or fixed length that produced the padding.

For encoded length `E`, `NoPadding` passes through `E` bytes;
`PadToBlock<N>` (`N >= 2`) produces `N * ceil((E + 1) / N)` bytes; and
`PadToLength<N>` (`N >= 1`) produces exactly `N` bytes, rejecting `E >= N`
because the marker must fit. An aligned block input receives a whole extra
block, and even an empty padded input contains a marker. The byte-level
`encrypt`/`decrypt` functions do not apply or remove profile padding.
See the [size definitions and boundary examples](suite-1-usage-policy.md#plaintext-maximum)
for the proposed cap on **padded AEAD plaintext**, not application-value size.

The envelope does not record whether padding is enabled or which parameters
were used, and its format version remains unchanged. Enabling or disabling
padding is therefore a persistent-schema change requiring migration. Changing
the parameters of an already-padded profile does not prevent old ciphertext
from decrypting. Re-encryption rewrites authenticated plaintext with the
profile's current padding parameters.

For `"cryptbox vector"` under `PadToBlock<16>`, the padded plaintext and
corresponding deterministic test envelope are:

```text
padded plaintext: 6372797074626f7820766563746f7280
envelope:         43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f1011121314151617c5ecf67a1ebf136378025485a1e4b9368a9985aacb04ff8f7b6a677d9665a9ba
```

### Key and buffer lifetime

The implementation uses the RustCrypto HKDF and HMAC crates and enables HMAC,
SHA-256, and Poly1305 zeroization support. This erases keyed digest state,
buffered hash input, and direct HMAC outputs on drop. CryptBox also immediately
erases the HKDF extract output and holds derived keys and returned MACs in
zeroizing buffers. As with other Rust cryptography implementations, transient
crate- and compiler-generated stack copies remain part of the targeted
zeroization and compiler review boundary.
Working plaintext is held in zeroizing buffers, including on authentication
failure. Padding allocates its target buffer before copying so growth does not
abandon a plaintext allocation. Encryption borrows the original application
value; erasing temporary encoded/padded buffers does not erase that value or
application-owned copies. See the [security boundary](security.md#threats-and-unsuitable-uses).

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
HKDF salt:      "cryptbox/hkdf-sha256/v1\0"
```

```text
header = format_version || index_key_id || bits_be
context = header || binding || index_id
key_info = key_info_label || context
mac_input = MAC_label || context || normalized_length_be_u64 || normalized_bytes
```

### Blind-index recipe

Inputs are an independent 32-byte blind-index root (never an encryption root),
its immutable `IndexKeyId`, the expected binding, logical `IndexId`, retained
bit count, and normalized bytes. `IndexKeyId`, `IndexId`, and any `FieldId` are
each 16 UUID network-order bytes. The version is one byte `01`; `bits_be` is
a two-byte unsigned big-endian count in `1..=256`. The binding is exactly `00`
for `Unbound`, or `01 || field_id[16]` for `FieldBound`.

1. Run the application's deterministic normalizer for this logical index.
   There is no built-in case folding, Unicode normalization, or text encoding
   at this layer. Use identical normalization for writes, probes, and candidate
   comparisons. Normalized bytes are independent of the encryption codec and
   padding. Their length is a **byte count**, encoded as unsigned big-endian
   `u64` (eight bytes); a length that cannot fit is invalid.
2. Construct the 19-byte `header`, then `context`, then `key_info` in the exact
   order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, blind_index_root)` (32-byte PRK), then
   `index_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   The salt is the literal 24-byte `cryptbox/hkdf-sha256/v1\0` including NUL;
   the key-info label is 28 bytes including NUL. No nonce is used.
3. Compute the full 32-byte `HMAC-SHA256(index_key, mac_input)` with the 30-byte
   MAC label including NUL. Concatenation adds no separators or terminators
   beyond those explicitly shown; in particular, normalized bytes have no
   implicit NUL terminator.
4. Retain the first `ceil(bits / 8)` digest bytes, keeping the most-significant
   `bits` bits. If `r = bits mod 8` is nonzero, AND the final byte with
   `(ff << (8 - r)) & ff`. Append this canonical truncated digest to `header`.
   The stored representation is exactly `19 + ceil(bits / 8)` bytes, with no
   encryption envelope, nonce, or additional tag.

Structural parsing rejects unsupported versions, precision outside `1..=256`,
incorrect total length (including trailing bytes), or nonzero unused low bits.
A typed `BlindIndex<Spec>` additionally requires the stored precision to equal
`Spec::BITS`. Binding, `IndexId`, and normalization are not stored and must be
supplied by the application schema. These inputs domain-separate derivation;
parsing the representation does not authenticate it or prove consistency with
ciphertext. Index hits remain candidates requiring authenticated decryption
and normalized plaintext comparison.

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
