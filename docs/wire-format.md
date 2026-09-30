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

> [!WARNING]
> **These wire formats are experimental.** They may change without backward
> compatibility.
>
> No cryptography review has been conducted yet. A focused review and independently
> generated test vectors are still required.

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
cannot register their own combinations. An unknown suite ID is rejected before
authentication because the reader has no construction with which to verify it.

### Binding

A binding identifies the expected cryptographic domain of a value. Every value is
bound to a stable `SealId`, so an email seal's ciphertext is not accepted under
a different seal, even when both use the same root key. A seal declares its
binding **declaration**: a fixed set of parts, each with a part ID (a UUID) and a
value kind; which of them form its **keys view**, the parts key custody follows;
and, when it binds a record, the record ID's kind. The declaration is persistent
schema. The **values**, such as a tenant ID and a record ID, are supplied at each
call. See [ADR-0005](adr/0005-runtime-binding-is-the-core.md),
[ADR-0008](adr/0008-records-declare-their-fields-seals.md), and
[ADR-0009](adr/0009-scopes-have-views.md).

Every binding uses one layout:

```text
binding = seal_id[16] || count[2] || part*

part    = part_id[16] || kind[1] || len[4] || value[len]
```

- `count` is the number of parts, as an unsigned 16-bit integer.
- Parts are sorted by part ID in ascending byte order, whatever order the seal
  declares them in. Declared part IDs are unique and never the nil UUID.
- A record is one more part, bound only, under the nil part ID, so it always
  sorts first. Its kind is the record ID's kind.
- `len` is an unsigned 32-bit byte count. Every value is length-prefixed, so
  `"ab", "c"` and `"a", "bc"` encode differently.
- There is no leading tag or type byte: the binding starts with the seal ID.

The **empty declaration** has no parts and no record. Its binding is the seal ID
followed by `0000`: an unscoped binding, which identifies a seal alone, not a
particular row or tenant.

The seal supplies the expected binding; it is not stored in the envelope.
This makes the application decide where a value belongs, rather than allowing
stored bytes to select their own binding.

Value kinds are fixed and canonical. There is no text kind:

| Kind | Code | Value bytes |
| --- | --- | --- |
| uuid | `01` | 16 raw UUID bytes |
| i64 | `02` | 8 bytes, big-endian two's complement |
| bytes | `03` | raw bytes, as given |

Every part and record value carries its kind code, so the same bytes under
different kinds, such as an `i64` and its 8 big-endian bytes, never collide.
A value of a part in the keys view can't be empty.

#### Binding fingerprint

Every binding has a 64-bit **binding fingerprint**, and every envelope's header
carries it. It covers the part IDs and kinds, a record's part included, and
which parts are in the keys view, but never values, because the header is
stored in plaintext:

```text
fingerprint label: "cryptbox/binding-fingerprint/v1\0"

fingerprint = SHA-256(fingerprint_label
                      || count[2]
                      || (part_id[16] || kind[1] || role[1])*)[0..8]
```

Parts are sorted by part ID as in the binding, so part order does not change
the fingerprint, and a record's part comes first with the nil part ID and role
`03`. A part's role code says whether it is in the keys view:

| Role | Code | Part |
| --- | --- | --- |
| keys | `01` | in the keys view: it scopes key custody, and is the unit you shred |
| bound only | `03` | any other part, the record's included |

Code `02` was the retired `index` role and is no longer written: a blind index
names its own [index scope](#index-binding). Roles are included because changing
the keys view alters custody, so it is a migration even though the binding bytes
don't change. The empty declaration's fingerprint is `65640fc8333534b9`. A record's
kind is part of the declaration, so a value read with a record ID of another kind
reports `BindingMismatch`.

#### Presets

Two ready-made scopes fix their declarations permanently:

- `()`, the empty scope, has no parts. Without a record it is the empty
  declaration, so its binding is `seal_id || 0000`. With an `i64` record, as
  `Recorded<(), i64>`, it binds the record alone; that declaration's fingerprint
  is `76081b730530f822`.
- `Tenant` has one part: part ID `1e8306bf-3135-4570-831c-6732f92550e9`, kind
  bytes. A seal over it takes `Tenant` as its keys view, so its role is `keys`.
  A tenant ID is non-empty opaque bytes; a UUID tenant is
  its 16 bytes. Without a record, its binding fingerprint is `9b73125a52bc08d1`.
  For seal `12345678-1234-4234-8234-1234567890ab` and tenant `acme`, the
  binding is:

  ```text
  123456781234423482341234567890ab00011e8306bf31354570831c6732f92550e9030000000461636d65
  ```

#### Reader rules

The fingerprint is diagnostic only. The reader always takes the expected declaration
from its own seal, never from the envelope:

1. After structural parsing, and before any key lookup or AEAD work, compare the
   envelope's fingerprint with the fingerprint of the reader's declaration. A
   unscoped reader expects the empty declaration's fingerprint. Any difference
   reports `BindingMismatch`.
2. Otherwise, decrypt with the binding built from the reader's declaration and the
   caller's values. Different part or record values under a matching declaration fail
   authentication.

The fingerprint is part of the authenticated prefix. Changing it to match
another declaration that has the same binding bytes, such as another keys view, still
fails authentication.

Codec identity and version are also absent: the application schema must supply
them to interpret the plaintext after authentication. Whether the payload is
padded is recorded in the envelope flags; padding parameters are not.

### Context

An envelope binds its value to a **context**: bytes that key derivation and the
AAD both take, which are never stored, and an 8-byte **context fingerprint**
that the header stores. The envelope interprets neither, so a reader always
supplies the context it expects. For a sealed value, the context bytes are its
[binding](#binding)'s encoding and the context fingerprint is its
[binding fingerprint](#binding-fingerprint).

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
with the expected one (for a binding, under the [reader rules](#reader-rules)), resolve only its exact `KeyId`,
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
`Padding::length(N)` (`N >= 1`) produces exactly `N` bytes, rejecting `E >= N`
because the marker must fit. An aligned block input receives a whole extra
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
| `Padding::length(16)` | 0 | 16 | 16 | 87 | Empty input uses entire target |
| `Padding::length(16)` | 15 | 1 | 16 | 87 | Largest fitting input |
| `Padding::length(16)` | 16 | — | — | — | `PaddingOverflow`: marker cannot fit |

Suite 1 limits `P` to `274,877,906,879` bytes, one byte below RFC 8439's functional
maximum `(2^32 - 1) * 64`, which the reference implementation's AEAD rejects. It
enforces the limit on encryption and rejects parsed/decrypted payloads implying a
larger `P`, with `MessageTooLong`. Padding/envelope size arithmetic is checked;
fixed padding rejects `E >= N` with `PaddingOverflow`. This is an algorithmic
ceiling, not a recommended value size. Applications must choose smaller limits
appropriate to their workloads; see
[application responsibilities](security.md#application-responsibilities).

For an application-selected padded cap `L`, `Padding::NONE` permits `E <= L`;
`Padding::block(N)` permits `E <= N * floor(L / N) - 1` if at least one block fits;
`Padding::length(N)` requires `N <= L` and `E <= N - 1`. Bound encoding and compute
padded size with checked arithmetic before allocating/encrypting. Bound incoming
binary envelopes to `W <= L + 71` before copying/decrypting, and bound decoding
expansion separately. Current padding parameters do not cap historical reads:
unpadding accepts a valid marker independently of the original block/target size.
A size check is not authentication.

### Key and buffer lifetime

See [plaintext and key ownership](ownership.md) for buffer lifetimes and erasure
obligations.

### Provisional envelope vectors

These fixed inputs and expected outputs help check byte-for-byte compatibility.
The first vector encrypts unpadded plaintext (flags `00`) bound to
`SealId 12345678-1234-4234-8234-1234567890ab` alone, so its header carries the
empty declaration's fingerprint:

```text
root key:    1111111111111111111111111111111111111111111111111111111111111111
KeyId:       11111111-2222-4333-8444-555555555555
context:     123456781234423482341234567890ab0000
fingerprint: 65640fc8333534b9
plaintext:   6372797074626f7820766563746f72 ("cryptbox vector")
nonce:       000102030405060708090a0b0c0d0e0f1011121314151617
envelope:    434258000201001111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e330da90830136eec9273c8315c1f22b7b
```

The padded vector uses the same root key, `KeyId`, context, and nonce as the
first vector, with `"cryptbox vector"` padded under `Padding::block(16)` and
flags `01`:

```text
padded plaintext: 6372797074626f7820766563746f7280
envelope:         434258000201011111111122224333844455555555555565640fc8333534b9000102030405060708090a0b0c0d0e0f10111213141516173a8e058803722f56b0ffc9ecbbb7e3c5e74a10b924aec9355f18b42c5b131fa0
```

Both decrypt to `"cryptbox vector"` whatever the reader's padding policy. The
vectors are generated and consumed in separate tests, and were computed
independently as described under the scoped vectors below.

### Provisional scoped vectors

These vectors use the root key, `KeyId`, `SealId`, plaintext, and nonce above,
unpadded, with a [binding](#binding) of two parts:

```text
part 11111111-1111-1111-1111-111111111111  uuid   keys        33333333-3333-3333-3333-333333333333
part 22222222-2222-2222-2222-222222222222  bytes  bound only  77732d31 ("ws-1")
```

Without a record, the binding fingerprint is `3c607e5f83c2ec23`:

```text
context:  123456781234423482341234567890ab00021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31
envelope: 43425800020100111111112222433384445555555555553c607e5f83c2ec23000102030405060708090a0b0c0d0e0f101112131415161760a4cae4f6c4caea7d60b573050315f837bb12b7e3f475cf7c866e358f4a14
```

With the `i64` record `7`, bound first as the nil part, the binding fingerprint is
`5d608899e74caec9`:

```text
context:  123456781234423482341234567890ab000300000000000000000000000000000000020000000800000000000000071111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31
envelope: 43425800020100111111112222433384445555555555555d608899e74caec9000102030405060708090a0b0c0d0e0f10111213141516174f25a5c9a5434209ef7a02cea389bf869eddf936d6b19486820d8406e8db7b
```

The fingerprints, bindings, and all four envelopes above were computed
independently of the implementation from the recipes above, with a separate
HKDF, HChaCha20, and ChaCha20-Poly1305 construction. They have not yet been
cross-checked against a third-party implementation.

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
come from the application schema, and the index binding from each call; none
of them is stored in the index.

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

### Index binding

A blind index is derived under its **index binding**: the seal's binding
restricted to the parts of the index's **index scope**, which holds every `keys`
part of the seal's scope. The seal's other parts and the record are left out,
because a query knows its index scope but not the row. The index binding uses
the [binding](#binding) encoding:

- It is the seal ID, then the index scope's parts sorted by part ID.
- With no parts, it is the empty binding, as for the empty scope.

Two bindings that agree on the index scope's values share the index binding, so
their indexes of the same value are equal. The key source receives the seal's
keys view, projected from the index scope.

### Blind-index recipe

Inputs are an independent 32-byte blind-index root (never an encryption root),
its immutable `IndexKeyId`, the expected [index binding](#index-binding),
logical `IndexId`, retained bit count, and normalized bytes. `IndexKeyId`,
`IndexId`, and any `SealId` are encoded using the UUID convention above, and
`binding` is the encoded index binding. The version is one byte `02`; `bits_be`
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
Format `1` indexes were derived under an earlier binding encoding, so they are
rejected as unsupported rather than silently matching nothing; derive them
again.
A typed `BlindIndex<Spec>` additionally requires the stored precision to equal
`Spec::BITS`. Parsing checks structure only; it does not authenticate the stored
metadata or prove consistency with ciphertext. Because truncation allows different
values to share an index, index hits remain candidates requiring authenticated
decryption and normalized plaintext comparison. See the
[verified search example](../examples/searchable/README.md) for using these bytes in a query.

### Provisional blind-index vector

```text
root key:     2222222222222222222222222222222222222222222222222222222222222222
IndexKeyId:   aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
IndexId:      abcdefab-cdef-4def-8def-abcdefabcdef
SealId:      12345678-1234-4234-8234-1234567890ab
binding:      123456781234423482341234567890ab0000
bits:         13
normalized:   6e6f726d616c697a6564406578616d706c652e636f6d ("normalized@example.com")
stored value: 02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000de800
```

The final byte `00` has its three unused low bits cleared.

### Scoped blind-index vector

The same inputs, for a seal bound to the `Tenant` preset with tenant `acme`.
The index binding is the seal's `Tenant` binding without a record:

```text
binding:      123456781234423482341234567890ab00011e8306bf31354570831c6732f92550e9030000000461636d65
stored value: 02aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d8b88
```

Both blind-index vectors were computed from the recipe above independently of
the implementation, with a separate HKDF and HMAC construction. They have not
yet been cross-checked against a third-party implementation.
