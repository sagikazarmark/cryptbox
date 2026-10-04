# Wire format

CryptBox stores encrypted values as binary **envelopes**: public metadata followed
by encrypted bytes and an authentication tag. Searchable values may also have a
separate **blind index**, a deterministic lookup value derived from normalized
plaintext. This document defines both stored representations and the recipes
needed to reproduce them.

| Format | Format version | Suite ID |
| --- | --- | --- |
| [Ciphertext](#envelope) | 2 | [1](#encryption-suite-1) |
| [Blind index](#blind-index-format-2) | 2 | — |

> [!NOTE]
> **Ciphertext format 2 and blind-index format 2 are stable.** Every later
> release reads them. A later construction gets a new suite ID or format version
> and is read alongside these; nothing here changes in place.
>
> The formats have not had an independent cryptographic audit. The vectors below
> were reproduced outside this crate; see [security](security.md).

## Versions and identifiers

The ciphertext envelope carries three identifiers with different jobs:

- **Format version** identifies the envelope structure: how its bytes are parsed.
- **Suite ID** identifies the complete encryption construction: how keys are
  derived, bytes are encrypted, and metadata is authenticated.
- **`KeyId`** identifies the encryption-key generation: which root key the
  keyring must hold to decrypt this value. The ID is public; key material is
  never stored in the envelope.

Format version `2` and suite ID `1` are separate identifiers that identify
separate parts of the protocol. Rotating keys
changes the key generation used for new values; it does not change the format
or suite.

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

## Encryption suite 1

An encryption suite is a complete recipe, rather than just a cipher name.
Agreeing on XChaCha20-Poly1305 alone would not tell another implementation which
key to use or which metadata to authenticate. A suite fixes those choices together
so that a reader can reconstruct exactly the same operation as the writer.

`1` is CryptBox's identifier for the construction defined below. It combines:

- **HKDF-SHA-256** derives a 32-byte operational key from the root key, separating
  its use by format, suite, key generation, and context. The root key is not used
  directly to encrypt values.
- **XChaCha20-Poly1305** encrypts the plaintext and produces a full 16-byte
  authentication tag. Each encryption uses a fresh 24-byte OS-random nonce, stored
  alongside the ciphertext so decryption can reproduce the operation.
- **Authenticated metadata** ties the encrypted bytes to the exact envelope
  prefix and expected context. This additional authenticated data (**AAD**) is
  covered by the tag without itself being encrypted.

This is authenticated encryption with associated data (**AEAD**): decryption
returns plaintext only if authentication succeeds. Suite 1 is currently the only
suite CryptBox writes or reads. Suites are built into the library; applications
cannot register their own combinations. An unknown suite ID is rejected before
authentication because the reader has no construction with which to verify it.

### Context

An envelope binds its value to a **context**: bytes that key derivation and the
AAD both take, which are never stored, and an 8-byte **context fingerprint**
that the header stores. The envelope interprets neither, so a reader always
supplies the context it expects. A sealed value's context is its
[seal context](#seal-context).

### Seal context

A value's context starts with its seal's stable `SealId`, so an email seal's
ciphertext is not accepted under a different seal, even when both use the same
root key. A `Context`, the second parameter of
`Sealed<F, C>`, adds parts after it: a record's field, `InRecord<Id>`, adds the
record ID, so a field's value is not accepted in another row. See
[ADR-0005](adr/0005-runtime-binding-is-the-core.md),
[ADR-0008](adr/0008-records-declare-their-fields-seals.md),
[ADR-0011](adr/0011-a-binding-is-the-seal-and-the-record.md), and
[ADR-0012](adr/0012-a-record-is-a-context-layer-over-a-seal.md).

```text
seal_context = seal_id[16] || count[2] || part*

part         = kind[1] || len[4] || value[len]
```

- `seal_id` is the seal's 16-byte UUID. There is no leading tag or type byte:
  the context starts with the seal ID.
- `count` is the number of parts, as an unsigned 16-bit integer: `0000` for a
  standalone value, `Sealed<F>`, and `0001` for a record's field. The record ID
  is the only part today.
- `kind` is the part's [kind code](#record-id-kinds), which names both the part
  and how its value is encoded. Codes `01` and `02` belong to the record ID, and `03` is
  reserved; a later kind of part would take codes of its own, so parts of
  different contexts never share a code.
- `len` is the value's length as an unsigned 32-bit byte count, so every value
  is length-prefixed, and `value` is its `len` bytes.
- Parts would appear in ascending order of their kind codes, each part at most
  once, so a context has exactly one encoding. The fingerprint lists its kind
  codes in the same order.

The seal ID has a fixed length, `count` says how many parts follow, and each
part carries its own length, so a context parses one way only: different
contexts never share bytes.

The reader supplies the expected context, from the type of the sealed value and,
for a record's field, the record ID the row stores; it is not stored in the
envelope. This
makes the application decide where a value belongs, rather than allowing stored
bytes to select their own context.

#### Record ID kinds

Record ID kinds are fixed and canonical. There is no bytes or text kind, and
code `03` is reserved: no released version writes it.

| Kind | Code | Value bytes |
| --- | --- | --- |
| uuid | `01` | 16 raw UUID bytes |
| i64 | `02` | 8 bytes, big-endian two's complement |

Every record ID carries its kind code, so the same bytes under different kinds,
such as an `i64` and its 8 big-endian bytes, never collide.

#### Context fingerprint

The context fingerprint names the kind of context, never its values, because
the header is stored in plaintext:

```text
fingerprint label: "cryptbox/context-fingerprint/v1\0"

fingerprint = SHA-256(fingerprint_label || count[2] || kind[1]*)[0..8]
```

- `fingerprint_label` is the 32 ASCII bytes above, including the terminating
  NUL. It separates the fingerprint from every other hash of these bytes.
- `count` is the context's part count, exactly as in the context: `0000` or
  `0001`.
- `kind` is each part's kind code, in the context's order; the values and their
  lengths are left out. A standalone value's fingerprint therefore hashes the
  label and `0000` alone, and a record field's the label, `0001`, and its
  record ID's kind code.
- `[0..8]` keeps the first 8 bytes of the 32-byte digest.

The label and `count` have fixed lengths, and `count` says how many one-byte
kind codes follow, so different kinds of context never hash the same bytes.
These fingerprints are fixed permanently:

| Context | Fingerprint |
| --- | --- |
| A standalone value | `502de8fcfb838c80` |
| A record's field with a UUID record ID | `f130f332c1aa00ec` |
| A record's field with an `i64` record ID | `af72b9c5219cf83b` |

For seal `12345678-1234-4234-8234-1234567890ab` and the `i64` record `7`, the
context is:

```text
123456781234423482341234567890ab000102000000080000000000000007

123456781234423482341234567890ab  seal_id
0001                              count: one part
02                                kind: i64 record ID
00000008                          len: 8 bytes
0000000000000007                  value: 7
```

#### Reader rules

The fingerprint is diagnostic only. The reader always takes the expected context
from its own seal and context, never from the envelope:

1. After structural parsing, and before any key lookup or AEAD work, compare the
   envelope's fingerprint with the fingerprint of the reader's context. Any
   difference reports `ContextMismatch`, such as a record field's value read as
   a standalone value.
2. Otherwise, decrypt with the reader's context. Another seal ID or record ID
   under a matching fingerprint fails authentication.

The fingerprint is part of the authenticated prefix. Changing it to match
another kind of context still fails authentication.

Codec identity and version are also absent: the application schema must supply
them to interpret the plaintext after authentication. Whether the payload is
padded is recorded in the envelope flags; padding parameters are not.

### Envelope

Ciphertext format 2 starts with a fixed 31-byte header containing the magic
bytes, format version, suite ID, flags, `KeyId`, and the
[context fingerprint](#context). The suite determines the
remaining layout. For suite 1, the nonce extends that header to a 55-byte
prefix:

```text
offset  size  field
0       4     43 42 58 00 ("CBX" + NUL)
4       1     format version = 02
5       1     suite ID = 01
6       1     flags
7       16    KeyId
23      8     context fingerprint
31      24    XChaCha20 nonce
55      N     ciphertext
55+N    16    Poly1305 tag
```

The magic and format version are the only bytes every format shares. Readers
check the version as soon as the magic is present, before the length, so an
envelope of a later format is reported as unsupported even if its header is
shorter.

Flag bit `01` records that the AEAD plaintext is [padded](#plaintext-padding).
All other bits are reserved and must be zero; readers reject an envelope with a
reserved bit set before authentication. The flags are part of the
authenticated prefix, so changing them fails authentication.

There is no embedded payload-length field: the enclosing storage or transport
must supply the envelope boundary. Within that boundary, the last 16 bytes are
the tag and the bytes between the prefix and tag are the encrypted payload.
The prefix is readable without a key, but remains untrusted until authentication.

The minimum envelope is 71 bytes and represents empty AEAD plaintext. For an
unpadded value, ciphertext leaks encoded plaintext length exactly plus this
fixed overhead. A padded value reveals its padded bucket length instead.
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
        || context

aad = aad_label || prefix || context
```

`prefix` is the whole suite prefix, including the context fingerprint:
`envelope[0..55]`.

### Encryption recipe

Inputs are an independent 32-byte encryption root, its immutable 16-byte
`KeyId`, the expected context, and AEAD plaintext bytes (encoded and
optionally padded as below), and whether it is padded. Use the encoding
conventions and context above, with `format_version = 02` and
`suite_id = 01`. Rust type names and database names are not inputs.

1. Construct `key_info` in the order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, root_key)` (32-byte PRK), then
   `operational_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   Use the fixed HKDF salt above, not the nonce.
2. Generate a fresh 24-byte nonce from the operating-system random source for
   each encryption, failing if randomness is unavailable. The fixed nonces in
   the vectors are test inputs only, not a supported application nonce policy.
3. Construct the 55-byte prefix from magic, version, suite, flags, `KeyId`,
   context fingerprint, and nonce using the offset table. Set flag bit `01`
   exactly when the AEAD plaintext is padded. Form
   `aad = aad_label || prefix || context`.
4. Seal the complete AEAD plaintext with XChaCha20-Poly1305 using the 32-byte
   operational key, nonce, and AAD. Append the ciphertext (same length as AEAD
   plaintext) and the full 16-byte tag to the prefix. No text encoding, tag
   truncation, or additional delimiters are applied.

For decryption, structurally validate the envelope, compare its context fingerprint
with the expected one (for a seal context, under the [reader rules](#reader-rules)), resolve only its exact `KeyId`,
reconstruct the key and AAD with the **expected** context, and verify
the tag before returning any plaintext. Only after authentication is padding
removed, when the authenticated flag is set, and the value decoded; the reader's
current padding policy never decides whether to remove padding. A wrong context
or changes to supported metadata, flags, nonce, ciphertext, or tag fail
authentication. Malformed/unsupported envelopes, a different context fingerprint, and
unknown keys can fail before authentication. Successful decryption does not
establish freshness or row identity.

### Plaintext padding

Encryption preserves payload length, so padding lets a seal hide the exact
encoded length by expanding it to a block boundary or fixed target. Suite 1 does
not require padding; it can encrypt any byte length within its size limit.

Padded values use ISO/IEC 7816-4 padding before the encoded plaintext is passed
to the encryption suite. Padding appends one `80` byte followed by as many `00`
bytes as needed to reach the selected block or fixed length. Removal scans
backward over zero bytes, requires the `80` marker, and strips it. It does not
depend on the block size or fixed length that produced the padding.

For encoded length `E`, `Padding::NONE` passes through `E` bytes;
`Padding::block(N)` (`N >= 2`) produces `N * ceil((E + 1) / N)` bytes; and
`Padding::length(N)` (`N >= 1`) produces exactly `N + 1` bytes, rejecting `E > N`:
it hides lengths up to `N`, and the marker takes the extra byte. An aligned block input receives a whole extra
block, and even an empty padded input contains a marker.

The writer sets the padded flag exactly when it applies padding, and a reader
removes padding exactly when the authenticated flag is set. The reader's current
padding policy is not consulted, so padded bytes are never returned with their
marker, and an unpadded value ending in `80` or `80 00` never loses those bytes.
A seal's padding policy therefore describes only how new values are written: it
can be enabled, disabled, or resized without making stored values unreadable.
Re-encryption rewrites the payload and flag with the seal's current policy.

The block size or fixed length is not recorded. Changing only those parameters
is not visible in the envelope, so re-encryption applies them only to values it
rewrites for another reason.

### Size semantics and enforcement

All lengths are byte counts, not character counts or Rust memory sizes:

| Quantity | Definition |
| --- | --- |
| `E`: encoded bytes | Codec output before padding. `Utf8` counts UTF-8 bytes: `"é"` has `E = 2`. |
| `P`: AEAD plaintext | Encoded bytes after padding, including the marker and zero fill when enabled. `Padding::NONE` gives `P = E`. |
| `W`: envelope bytes | Complete binary ciphertext: 55-byte prefix, `P` ciphertext bytes, 16-byte tag. `W = P + 71`; excludes text encoding, database framing, and separate indexes. |

Padding boundary examples (ASCII input, one encoded byte per character):

| Padding policy | `E` | Padding bytes | `P` | `W` | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `Padding::NONE` | 0 | 0 | 0 | 71 | Accepted |
| `Padding::NONE` | 16 | 0 | 16 | 87 | Exact length preserved |
| `Padding::block(16)` | 0 | 16 | 16 | 87 | Empty input still padded |
| `Padding::block(16)` | 15 | 1 | 16 | 87 | Marker fills block |
| `Padding::block(16)` | 16 | 16 | 32 | 103 | Marker starts next block |
| `Padding::length(16)` | 0 | 17 | 17 | 88 | Empty input uses entire target |
| `Padding::length(16)` | 16 | 1 | 17 | 88 | Largest fitting input |
| `Padding::length(16)` | 17 | — | — | — | `PaddingOverflow` |

Suite 1 limits `P` to `274,877,906,879` bytes, one byte below RFC 8439's functional
maximum `(2^32 - 1) * 64`, which the reference implementation's AEAD rejects. It
enforces the limit on encryption and rejects parsed/decrypted payloads implying a
larger `P`, with `MessageTooLong`. Padding/envelope size arithmetic is checked;
fixed padding rejects `E > N` with `PaddingOverflow`. This is an algorithmic
ceiling, not a recommended value size. Applications must choose smaller limits
appropriate to their workloads; see
[application responsibilities](security.md#application-responsibilities).

For an application-selected padded cap `L`, `Padding::NONE` permits `E <= L`;
`Padding::block(N)` permits `E <= N * floor(L / N) - 1` if at least one block fits;
`Padding::length(N)` requires `N + 1 <= L` and `E <= N`. Bound encoding and compute
padded size with checked arithmetic before allocating/encrypting. Bound incoming
binary envelopes to `W <= L + 71` before copying/decrypting, and bound decoding
expansion separately. Current padding parameters do not cap historical reads:
unpadding accepts a valid marker independently of the original block/target size.
A size check is not authentication.

### Key and buffer lifetime

See [ownership and erasure](guide.md#ownership-and-erasure) for buffer lifetimes and erasure
obligations.

### Envelope vectors

These fixed inputs and expected outputs help check byte-for-byte compatibility.
The first vector encrypts unpadded plaintext (flags `00`) bound to
`SealId 12345678-1234-4234-8234-1234567890ab` alone, so its header carries the
standalone value's fingerprint:

```text
root key:    1111111111111111111111111111111111111111111111111111111111111111
KeyId:       11111111-2222-4333-8444-555555555555
context:     123456781234423482341234567890ab0000
fingerprint: 502de8fcfb838c80
plaintext:   6372797074626f7820766563746f72 ("cryptbox vector")
nonce:       000102030405060708090a0b0c0d0e0f1011121314151617
envelope:    4342580002010011111111222243338444555555555555502de8fcfb838c80000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e30624c444239c62d73be5eac7459c548f
```

The padded vector uses the same root key, `KeyId`, context, and nonce as the
first vector, with `"cryptbox vector"` padded under `Padding::block(16)` and
flags `01`:

```text
padded plaintext: 6372797074626f7820766563746f7280
envelope:         4342580002010111111111222243338444555555555555502de8fcfb838c80000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e3c5bd94437a46143e4373c11bdfdfbc47b4
```

Both decrypt to `"cryptbox vector"` whatever the reader's padding policy. The
vectors are generated and consumed in separate tests, and were computed
independently as described under the record vector below.

### Record vector

This vector uses the root key, `KeyId`, `SealId`, plaintext, and nonce above,
unpadded, with the [seal context](#seal-context) of the `i64` record `7`, whose
context fingerprint is `af72b9c5219cf83b`:

```text
context:  123456781234423482341234567890ab000102000000080000000000000007
envelope: 4342580002010011111111222243338444555555555555af72b9c5219cf83b000102030405060708090a0b0c0d0e0f10111213141516173270eb8abb2f33a5b07fed7df8e4f670ee1d691d5adf05262912af97de476a
```

The fingerprints, contexts, and all three envelopes above were computed
independently of the implementation from the recipes above: in Python, with
an RFC 5869 HKDF written over HMAC-SHA-256 and libsodium's XChaCha20-Poly1305,
checked against the `cryptography` package's ChaCha20-Poly1305 over a
separately written HChaCha20. They were reproduced again with Node.js and
OpenSSL's HKDF and ChaCha20-Poly1305, over another separately written
HChaCha20.

## Blind-index format 2

A blind index supports equality-style lookup without decrypting every stored
value. Normalization gives values the application considers equivalent the same
bytes—for example, by lowercasing text for a case-insensitive index. For a given
index policy and key generation, the same normalized bytes produce the same
index bytes. Unlike randomized ciphertext, this deliberately reveals equality
and frequency information.

Format `2` defines both the stored layout and the derivation recipe:
HKDF-SHA-256 derives an index-specific key, HMAC-SHA-256 computes a keyed digest
of the normalized value and its context, and truncation retains only the selected
number of most-significant bits. Fewer retained bits mean more false candidates.
Root blind-index keys must be independent from encryption keys.

### Stored layout

```text
offset  size          field
0       1             format version = 02
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
projections of the same seal. It is separate from `IndexKeyId`: one identifies
the index's meaning, the other its key generation. `IndexId` and normalization
come from the application schema, and the index context from the seal; none
of them is stored in the index.

Exact domain labels include the terminating NUL byte:

```text
key info label: "cryptbox/blind-index-key/v1\0"
MAC label:      "cryptbox/blind-index-value/v1\0"
HKDF salt:      "cryptbox/hkdf-sha256/v1\0"
```

```text
header = format_version || index_key_id || bits_be
context = header || seal_context || index_id
key_info = key_info_label || context
mac_input = MAC_label || context || normalized_length_be_u64 || normalized_bytes
```

### Index context

A blind index is derived under its **index context**: the seal ID alone, as a
standalone [seal context](#seal-context), `seal_id || 0000`. The record is left
out, because a query cannot know the row, so every value of one seal shares it,
and equal values derive equal indexes under the same key. Separate blind-index
roots, such as one per tenant, derive unrelated indexes.

The normalizer's name (`BlindIndexSpec::NORMALIZER`) and the seal's codec ID
are **not** part of index key derivation: only the `IndexId` names the index.
Changing an index's normalization under the same `IndexId` derives different
bytes for the same value with the same key, so stored indexes silently stop
matching their probes; nothing fails to parse. Only a schema manifest snapshot
(`schema::Manifest`), which lists each index's normalizer, catches the change.
Give changed normalization a new `IndexId`, and derive its indexes again.

This is deliberate, and fixed with index format 2. Deriving under the name
would not detect anything: changed rules under an unchanged name still derive
different bytes, and a bumped name would only make stale indexes miss under
another label. It would make renaming a normalizer re-derive every index.

### Blind-index recipe

Inputs are an independent 32-byte blind-index root (never an encryption root),
its immutable `IndexKeyId`, the expected [index context](#index-context),
logical `IndexId`, retained bit count, and normalized bytes. `IndexKeyId`,
`IndexId`, and any `SealId` are encoded using the UUID convention above, and
`seal_context` is the encoded index context. The version is one byte `02`; `bits_be`
is a two-byte unsigned big-endian count in `1..=256`.

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
Format `1` indexes were derived under an earlier context encoding, so they are
rejected as unsupported rather than silently matching nothing; derive them
again.
A typed `BlindIndex<Spec>` additionally requires the stored precision to equal
`Spec::BITS`. Parsing checks structure only; it does not authenticate the stored
metadata or prove consistency with ciphertext. Because truncation allows different
values to share an index, index hits remain candidates requiring authenticated
decryption and normalized plaintext comparison. See the
[verified search example](../examples/searchable/README.md) for using these bytes in a query.

### Blind-index vectors

All three vectors share these inputs and differ only in the retained bit count:

```text
root key:     2222222222222222222222222222222222222222222222222222222222222222
IndexKeyId:   aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
IndexId:      abcdefab-cdef-4def-8def-abcdefabcdef
SealId:       12345678-1234-4234-8234-1234567890ab
context:      123456781234423482341234567890ab0000
normalized:   6e6f726d616c697a6564406578616d706c652e636f6d ("normalized@example.com")
```

```text
bits:         256
stored value: 02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee0100887b39ac8e4b85234adcd87e67b61b0bb4277c21fbe68df317109bd22ef64ed3

bits:         64
stored value: 02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee0040e20160c5ea7a01a3

bits:         13
stored value: 02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000de800
```

The 256-bit vector keeps the whole HMAC, so it checks every derivation step
at full strength. The 64-bit one is byte-aligned truncation. In the 13-bit one,
the final byte `00` has its three unused low bits cleared; it pins only 13
bits, so it checks the masking rather than the derivation. The bit count is
part of `header`, and so of the index key, so a shorter index is not a prefix
of a longer one.

The blind-index vectors were computed from the recipe above independently of
the implementation: in Python, with an RFC 5869 HKDF written over HMAC-SHA-256,
and again with Node.js and OpenSSL's HKDF and HMAC.

## Text form

The envelope and the blind index are binary. Where they must be text, as in
JSON, CryptBox writes their exact bytes as **unpadded base64url**: the URL- and
filename-safe alphabet of
[RFC 4648, section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5)
(`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`), with no `=` padding, no line breaks, and
no other characters. The text form adds nothing to the bytes and is not
authenticated; the bytes it decodes to are parsed as usual.

The `serde` feature writes this form for human-readable formats, and raw bytes
for binary formats. A reader decodes it strictly. It rejects:

- `=` padding, even where the padded form would be correct;
- the standard alphabet's `+` and `/`;
- whitespace and any other character outside the alphabet;
- nonzero unused bits in the final character, so each byte string has exactly
  one text form.

A human-readable reader also accepts the bytes as an array of integers.

The [unpadded envelope vector](#envelope-vectors), as text:

```text
Q0JYAAIBABEREREiIkMzhERVVVVVVVVQLej8-4OMgAABAgMEBQYHCAkKCwwNDg8QERITFBUWFzqOBYgDci9WsP_J7Lu34wYkxEQjnGLXO-Xqx0WcVI8
```
