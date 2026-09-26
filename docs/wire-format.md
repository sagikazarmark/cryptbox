# Wire Format

CryptBox stores encrypted values as binary **envelopes**: public metadata followed
by encrypted bytes and an authentication tag. Searchable fields may also have a
separate **blind index**, a deterministic lookup value derived from normalized
plaintext. This document defines both stored representations and the recipes
needed to reproduce them.

| Format | Format version | Suite ID |
| --- | --- | --- |
| [Ciphertext](#envelope) | 1 | [1](#encryption-suite-1) |
| [Blind index](#blind-index-format-1) | 1 | — |

> [!WARNING]
> **These wire formats are under development.**
>
> Although they are in reasonably good
> shape, there are no commitments to stability or backward compatibility, and
> they may change. **Use them at your own risk.**
>
> No cryptography review has been conducted yet. A focused review and independently
> generated test vectors are still required.

## Versions and identifiers

The ciphertext envelope carries three identifiers with different jobs:

- **Format version** identifies the envelope structure: how its bytes are parsed.
- **Suite ID** identifies the complete encryption construction: how keys are
  derived, bytes are encrypted, and metadata is authenticated.
- **`KeyId`** identifies the encryption-key generation: which root key the
  provider must supply to decrypt this value. The ID is public; key material is
  never stored in the envelope.

Format version `1` and suite ID `1` are separate identifiers that happen to have
the same value. They identify separate parts of the protocol. Rotating keys
changes the key generation used for new values;
it does not change the format or suite.

Blind indexes have their own format version and `IndexKeyId`. Their format
defines the derivation construction directly, so they have no separate suite ID.

## Encoding and notation

The format layouts and cryptographic recipes below use these conventions:

- UUID identifiers use their 16-byte RFC UUID network-order representation.
- Multibyte integers are unsigned big-endian values.
- Byte literals such as `01`, `80`, and `ff` are hexadecimal.
- `||` concatenates raw bytes.
- `\0` is one NUL byte (`00`).
- Slice endpoints are exclusive.
- Quoted labels are ASCII bytes, without quotes.
- UUID strings and hexadecimal displays represent raw bytes; decode them before
  use rather than hashing their text representation.

## Encryption Suite 1

An encryption suite is a complete recipe, rather than just a cipher name.
Agreeing on XChaCha20-Poly1305 alone would not tell another implementation which
key to use or which metadata to authenticate. A suite fixes those choices together
so that a reader can reconstruct exactly the same operation as the writer.

`1` is CryptBox's identifier for the construction defined below. It combines:

- **HKDF-SHA-256** derives a 32-byte operational key from the root key, separating
  its use by format, suite, key generation, and binding. The root key is not used
  directly to encrypt values.
- **XChaCha20-Poly1305** encrypts the plaintext and produces a full 16-byte
  authentication tag. Each encryption uses a fresh 24-byte OS-random nonce, stored
  alongside the ciphertext so decryption can reproduce the operation.
- **Authenticated metadata** ties the encrypted bytes to the exact envelope
  prefix and expected binding. This additional authenticated data (**AAD**) is
  covered by the tag without itself being encrypted.

This is authenticated encryption with associated data (**AEAD**): decryption
returns plaintext only if authentication succeeds. Suite 1 is currently the only
suite CryptBox writes or reads. Suites are built into the library; applications
cannot register their own combinations. An unknown suite ID is rejected before authentication
because the reader has no construction with which to verify it.

### Binding

A binding identifies the expected cryptographic domain of a value. For example,
binding an email field to a stable `FieldId` prevents its ciphertext from being
accepted under a different field's binding, even when both use the same root key.
Field binding identifies a logical field, not a particular row or tenant.

The binding is encoded as:

```text
Unbound:             00
FieldBound(FieldId): 01 || field_id[16]
```

The profile supplies the expected binding; it is not stored in the envelope.
This makes the application decide where a value belongs, rather than allowing
stored bytes to select their own binding. `Unbound` explicitly omits field
identity, but still authenticates the envelope metadata and encrypted bytes.

Codec identity/version and padding policy are also absent. The application
schema must supply these to interpret the plaintext after authentication.

### Envelope

Ciphertext format 1 starts with a 22-byte header containing the magic bytes,
format version, suite ID, and `KeyId`. The suite determines the remaining layout.
For suite 1, the nonce extends that header to a 46-byte prefix:

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

There is no embedded payload-length field: the enclosing storage or transport
must supply the envelope boundary. Within that boundary, the last 16 bytes are
the tag and the bytes between the prefix and tag are the encrypted payload.
The prefix is readable without a key, but remains untrusted until authentication.

The minimum envelope is 62 bytes and represents empty AEAD plaintext. For an
unpadded profile, ciphertext leaks encoded plaintext length exactly plus this
fixed overhead. A padded profile reveals its padded bucket length instead.
See [size semantics and enforcement](#size-semantics-and-enforcement) for exact
encoded, padded, and stored lengths and the suite's functional limit.

### Key derivation and authenticated data

Fixed labels keep cryptographic operations for different purposes distinct,
even when other inputs overlap. These labels are protocol bytes, not descriptive
names that an implementation can change. Each includes its terminating NUL byte:

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
optionally padded as below). Use the encoding conventions and binding bytes
above, with `format_version = 01` and `suite_id = 01`. Rust names and field
diagnostic names are not inputs.

1. Construct `key_info` in the order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, root_key)` (32-byte PRK), then
   `operational_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   Use the fixed HKDF salt above, not the nonce.
2. Generate a fresh 24-byte nonce from the operating-system random source for
   each encryption, failing if randomness is unavailable. The fixed nonces in
   the vectors are test inputs only, not a supported application nonce policy.
3. Construct the 46-byte prefix from magic, version, suite, `KeyId`, and nonce
   using the offset table. Form `aad = aad_label || prefix || binding`.
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

Encryption preserves payload length, so padding lets a profile hide the exact
encoded length by expanding it to a block boundary or fixed target. Suite 1 does
not require padding; it can encrypt any byte length within its size limit.

Profiles that enable padding use ISO/IEC 7816-4 padding before passing encoded
plaintext to the encryption suite. Padding appends one `80` byte followed by as
many `00` bytes as needed to reach the selected block or fixed length. Removal
scans backward over zero bytes, requires the `80` marker, and strips it. It does not depend on the block
size or fixed length that produced the padding.

For encoded length `E`, `NoPadding` passes through `E` bytes;
`PadToBlock<N>` (`N >= 2`) produces `N * ceil((E + 1) / N)` bytes; and
`PadToLength<N>` (`N >= 1`) produces exactly `N` bytes, rejecting `E >= N`
because the marker must fit. An aligned block input receives a whole extra
block, and even an empty padded input contains a marker. The byte-level
`encrypt`/`decrypt` functions do not apply or remove profile padding.

The envelope does not record whether padding is enabled or which parameters
were used, and its format version remains unchanged. Enabling or disabling
padding is therefore a persistent-schema change requiring migration. Changing
the parameters of an already-padded profile does not prevent old ciphertext
from decrypting. Re-encryption rewrites authenticated plaintext with the
profile's current padding parameters.

### Size semantics and enforcement

All lengths are byte counts, not character counts or Rust memory sizes:

| Quantity | Definition |
| --- | --- |
| `E`: encoded bytes | Codec output before padding. `Utf8` counts UTF-8 bytes: `"é"` has `E = 2`. |
| `P`: AEAD plaintext | Encoded bytes after padding, including the marker and zero fill when enabled. `NoPadding` gives `P = E`. |
| `W`: envelope bytes | Complete binary ciphertext: 46-byte prefix, `P` ciphertext bytes, 16-byte tag. `W = P + 62`; excludes text encoding, database framing, and separate indexes. |

Padding boundary examples (ASCII input, one encoded byte per character):

| Padding policy | `E` | Padding bytes | `P` | `W` | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `NoPadding` | 0 | 0 | 0 | 62 | Accepted |
| `NoPadding` | 16 | 0 | 16 | 78 | Exact length preserved |
| `PadToBlock<16>` | 0 | 16 | 16 | 78 | Empty input still padded |
| `PadToBlock<16>` | 15 | 1 | 16 | 78 | Marker fills block |
| `PadToBlock<16>` | 16 | 16 | 32 | 94 | Marker starts next block |
| `PadToLength<16>` | 0 | 16 | 16 | 78 | Empty input uses entire target |
| `PadToLength<16>` | 15 | 1 | 16 | 78 | Largest fitting input |
| `PadToLength<16>` | 16 | — | — | — | `PaddingOverflow`: marker cannot fit |

Suite 1 enforces RFC 8439's functional maximum `P <= 274,877,906,880`
(`(2^32 - 1) * 64`) on encryption and rejects parsed/decrypted payloads implying
a larger `P`, with `MessageTooLong`. Padding/envelope size arithmetic is checked;
fixed padding rejects `E >= N` with `PaddingOverflow`. This is an algorithmic
ceiling, not a recommended field size. Applications must choose smaller limits
appropriate to their workloads; see [application responsibilities](security.md#application-responsibilities).

For an application-selected padded cap `L`, `NoPadding` permits `E <= L`;
`PadToBlock<N>` permits `E <= N * floor(L / N) - 1` if at least one block fits;
`PadToLength<N>` requires `N <= L` and `E <= N - 1`. Bound encoding and compute
padded size with checked arithmetic before allocating/encrypting. Bound incoming
binary envelopes to `W <= L + 62` before copying/decrypting, and bound decoding
expansion separately. Current padding parameters do not cap historical reads:
unpadding accepts a valid marker independently of the original block/target size.
A size check is not authentication.

### Key and buffer lifetime

See [plaintext and key ownership](ownership.md) for
buffer lifetimes and erasure obligations.

### Provisional Envelope Vector

These fixed inputs and expected outputs help check byte-for-byte compatibility.
The first vector encrypts unpadded plaintext with `Unbound`:

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

The padded vector uses the same root key, `KeyId`, nonce, and unbound binding as
the first vector, with `"cryptbox vector"` padded under `PadToBlock<16>`:

```text
padded plaintext: 6372797074626f7820766563746f7280
envelope:         43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f1011121314151617c5ecf67a1ebf136378025485a1e4b9368a9985aacb04ff8f7b6a677d9665a9ba
```

## Blind-Index Format 1

A blind index supports equality-style lookup without decrypting every stored
value. Normalization gives values the application considers equivalent the same
bytes—for example, by lowercasing text for a case-insensitive index. For a given
index policy and key generation, the same normalized bytes produce the same
index bytes. Unlike randomized ciphertext, this deliberately
reveals equality and frequency information.

Format `1` defines both the stored layout and the derivation recipe:
HKDF-SHA-256 derives an index-specific key, HMAC-SHA-256 computes a keyed digest
of the normalized value and its context, and truncation retains only the selected
number of most-significant bits. Fewer retained bits mean more false candidates.
Root blind-index keys must be independent from encryption keys.

### Stored layout

```text
offset  size          field
0       1             format version = 01
1       16            IndexKeyId
17      2             retained bit count
19      ceil(bits/8)  truncated HMAC
```

`IndexKeyId` identifies the root-key generation, while the retained bit count
records the index precision. Valid precision is 1 through 256 bits, giving a total
stored length of 20 through 51 bytes. For non-byte-aligned precision, unused low
bits in the final byte are zero and noncanonical stored values are rejected.

### Key derivation and index input

The logical `IndexId` distinguishes indexes, such as two differently normalized
projections of the same field. It is separate from `IndexKeyId`: one identifies
the index's meaning, the other its key generation. `IndexId`, binding, and
normalization come from the application schema and are not stored in the index.

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
encoded using the UUID convention above, and binding uses the same encoding as
encryption. The version is one byte `01`; `bits_be` is a two-byte unsigned
big-endian count in `1..=256`.

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
   Use the fixed HKDF salt above. No nonce is used, so derivation is deterministic.
3. Compute the full 32-byte `HMAC-SHA256(index_key, mac_input)`. Concatenation adds
   no separators or terminators beyond those explicitly shown; in particular,
   normalized bytes have no implicit NUL terminator.
4. Retain the first `ceil(bits / 8)` digest bytes, keeping the most-significant
   `bits` bits. If `r = bits mod 8` is nonzero, AND the final byte with
   `(ff << (8 - r)) & ff`. Append this canonical truncated digest to `header`.
   The stored representation is exactly `19 + ceil(bits / 8)` bytes, with no
   encryption envelope, nonce, or additional tag.

Structural parsing rejects unsupported versions, precision outside `1..=256`,
incorrect total length (including trailing bytes), or nonzero unused low bits.
A typed `BlindIndex<Spec>` additionally requires the stored precision to equal
`Spec::BITS`. Parsing checks structure only; it does not authenticate the stored
metadata or prove consistency with ciphertext. Because truncation allows different
values to share an index, index hits remain candidates requiring authenticated
decryption and normalized plaintext comparison. See the
[verified search workflow](searchable-sqlx.md) for using these bytes in a query.

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
