# CryptBox Encryption-Suite Evaluation

**Research date:** 2026-08-21

**Question:** Is CryptBox Suite 1, HKDF-SHA-256 per-binding key derivation plus
XChaCha20-Poly1305 with random 24-byte nonces and authenticated envelope
metadata/binding, the best fit for randomized application-layer database-field
encryption with long-lived root keys, multiple processes, key rotation, and
persistent ciphertext?

## Executive recommendation

**Keep Suite 1 for the experimental release.** It is a sound fit for
CryptBox's stateless, multi-process encryption model and is the best
implementation-ready default among the Rust options evaluated here. CryptBox
generates the nonce inside the crypto core from the operating system CSPRNG, so
callers cannot accidentally supply a counter or repeat a nonce. A 192-bit
random nonce makes accidental collision negligible at any credible database
volume, without cross-process coordination. The existing RustCrypto
`chacha20poly1305` crate has also received a security audit with no significant
findings.[rustcrypto-chacha-011]

**Suite 1 is defensible for production after focused review, but the repository
is correct not to call it production-ready now.** Production should be gated on
independent suite/envelope vectors, review of the HKDF/HMAC and AAD
composition, an explicit key-usage policy, parser/failure testing, supported
target review, and continued use of a supported RustCrypto release. The current
dependency is `chacha20poly1305 = "0.11.0"`, which is the current stable line;
RustCrypto applies security updates only to its most recent release.
[cargo][rustcrypto-chacha-011][rustcrypto-security]

**AES-256-GCM-SIV is the strongest alternative to keep under consideration.**
It has a final CFRG-consensus RFC and turns accidental nonce reuse from a
catastrophic event into equality leakage for the repeated nonce. That property
is valuable for VM rollback, broken randomness, or future APIs that accept
caller-supplied nonces. It is not the preferred active suite today because
RustCrypto explicitly says its `aes-gcm-siv` crate itself has never been
audited, even though important dependencies were audited.[rfc8452][rustcrypto-gcm-siv]
If CryptBox funds or obtains a focused audit of that implementation, it would
be a reasonable Suite 2 and could become the active production suite where
nonce-fault tolerance or AES policy matters.

**Do not replace Suite 1 with ordinary AES-GCM using random 96-bit nonces.** Its
standards and hardware-acceleration story are excellent, but a single repeated
key/nonce pair compromises confidentiality and the authentication key. Its
short nonce also imposes a much lower random-nonce message budget.[rfc5116]

No additional modern candidate is clearly superior overall. XAES-256-GCM is
the closest AES analogue to XChaCha20-Poly1305, but it remains non-misuse-
resistant and its RustCrypto implementation is a release candidate with no
audit or constant-time guarantee. Ascon-AEAD128 is now a NIST standard and is
attractive for constrained devices, but it has a 128-bit nonce, is not
nonce-misuse-resistant, and its RustCrypto crate is version 0.1.0 and
unaudited.[c2sp-xaes][rustcrypto-xaes][nist-ascon][rustcrypto-ascon]

## Scope and threat-model fit

CryptBox protects plaintext against database reads, dumps, backups, snapshots,
detached volumes, and other storage compromise. It requires authenticated
modification detection and, for field-bound profiles, cross-field substitution
protection.[spec-threat] This is randomized application-layer encryption, not
disk encryption and not searchable encryption; blind indexes are a separate,
leakier construction.

Important limits of the threat model remain independent of suite choice:

- Application-process compromise while keys are live is out of scope.
- Field binding does not stop copying Alice's ciphertext to Bob's value in the
  same logical field.[spec-binding]
- None of the compared AEADs supplies replay or rollback protection. An
  attacker can restore an older authentic ciphertext unless a higher layer
  authenticates record identity and version/state.
- Ciphertext length is visible. Suite 1 adds a fixed 62-byte minimum envelope
  and otherwise reveals plaintext length exactly.[wire]
- A retained historical key intentionally keeps its old ciphertext readable.
  Rotation is not revocation and is not crypto-shredding.

The database-field use case strongly favors a stateless randomized nonce over
a global counter. RFC 5116 notes that multiple encryptors sharing a key must
coordinate unique nonces and that counters used with long-lived keys need
crash-safe nonvolatile state.[rfc5116] CryptBox's in-core random generation
avoids that distributed state-management system. The tradeoff is reliance on
the OS CSPRNG and the AEAD's random-nonce collision margin.

## What Suite 1 implements

The inspected implementation and provisional format agree:

- A root key is 32 random bytes with an opaque 16-byte `KeyId`.
- HKDF-SHA-256 derives a 32-byte operational key from the root for each tuple
  `(format version, suite ID, KeyId, binding domain)`.
- Binding is canonical and sealed: unbound is `00`; field-bound is `01 ||
  FieldId[16]`.[binding]
- Encryption obtains a fresh 24-byte nonce with `getrandom::fill` for every
  operation.[crypto-seal]
- XChaCha20-Poly1305 uses a full 16-byte tag.
- AAD is a domain label followed by the complete 22-byte header, nonce, and
  expected binding. Thus magic, version, suite ID, key ID, nonce, and binding
  all affect authentication.[crypto-aad][wire]
- The payload maximum is 274,877,906,880 bytes, matching the RFC 8439 limit of
  `2^32 - 1` 64-byte ChaCha blocks.[crypto-limits][rfc8439]
- Decryption selects exactly the key and suite named by the envelope, while
  authentication detects a modified readable `KeyId`, wrong field, nonce,
  ciphertext, or tag.[crypto-open][crypto-tests]
- Suite and key identifiers make historical decryption and future suite
  migration possible without rewriting all rows at rotation time.

The HKDF use is structurally appropriate. RFC 5869 defines extract-then-expand
and says `info` is specifically intended to bind output key material to
application and context identifiers. It also permits salt reuse; a fixed
protocol-specific salt is independent of the uniformly random root key. For a
strong random root key, extract is conservative rather than necessary.[rfc5869]

The implementation uses the maintained RustCrypto `hkdf` and `hmac` crates on
their current 0.13 release lines. The `hmac` zeroization feature and SHA-256
zeroization support erase keyed state, buffered input, and direct HMAC outputs
on drop; CryptBox also explicitly erases the extracted pseudorandom key and
retains derived outputs in zeroizing buffers. Transient crate- and
compiler-generated stack copies remain in the targeted zeroization review
boundary. The included RFC 5869 test covers one HKDF vector; it is not an
independent test of the complete CryptBox composition.[crypto-hkdf][wire]

## Nonce analysis

For `q` independent uniform `n`-bit nonces under one operational key, the
approximate probability of at least one collision while the probability is
small is:

```text
q(q - 1) / 2^(n + 1)
```

The relevant key for this calculation is the derived per-binding operational
key, not merely the root key. Reusing the same random nonce in two different
bindings or key generations is harmless because HKDF produces different AEAD
keys. The total root-key risk is the sum of the risks across its derived keys.
Unbound encryption is the largest single nonce domain because all unbound
values under one root generation share one operational key.

### Suite 1

The XChaCha draft gives a 50% collision point near `2^96` messages and a
conservative `2^-32` collision-risk budget of `2^80` messages under one key.
It was designed specifically so stateless implementations can safely use
random nonces.[xchacha-draft] Libsodium likewise recommends XChaCha20-Poly1305
when interoperability is not a concern and says random 192-bit nonces are safe,
while still warning never to reuse a nonce with one key.[libsodium-xchacha]

XChaCha20-Poly1305 is **not** nonce-misuse-resistant. Repetition of the complete
192-bit nonce under one operational key repeats the underlying subkey/nonce,
with the same fundamental stream-cipher and one-time-Poly1305-key failure as
ChaCha20-Poly1305. Its safety comes from making accidental full-nonce collision
extraordinarily unlikely, not from making reuse benign.

### 96-bit random nonces

With a 96-bit random nonce, about `2^32` messages already produce collision
risk around `2^-33`, and the 50% collision point is around `2^48` messages.
This is the key distinction between ordinary AES-GCM and AES-GCM-SIV:

- For AES-GCM, collision is catastrophic. RFC 5116 says it exposes the XOR of
  plaintexts, permits recovery of the internal hash key, and makes subsequent
  forgeries trivial.[rfc5116]
- For AES-GCM-SIV, RFC 8452 says reuse leaks only whether plaintext and AAD are
  identical for that nonce. It still recommends random nonces rather than
  intentional reuse.[rfc8452]

Multiple processes therefore make random AES-GCM a poor default, but they do
not disqualify random AES-GCM-SIV.

## Candidate comparison

| Candidate | Nonce/collision and misuse behavior | Standard and interoperability | Rust implementation maturity | Performance and limits | Persistent-format fit | Review burden |
|---|---|---|---|---|---|---|
| **Suite 1: HKDF-SHA-256 + XChaCha20-Poly1305** | 192-bit random nonce; about `2^80` messages per derived key for collision risk near `2^-32`; catastrophic if a full key/nonce pair actually repeats | HKDF is RFC 5869 and ChaCha20-Poly1305 is RFC 8439; XChaCha is an expired IETF draft, not a final standard. It has interoperable implementations including libsodium | Current RustCrypto crate documents one NCC Group audit with no significant findings, and CryptBox uses the current 0.11 release line | Fast and constant-time-oriented in portable software; optional AVX2. Per-message max about 256 GiB. CryptBox also pays HKDF-SHA-256 and allocation costs per field | Excellent. 24-byte nonce + 16-byte tag; current suite payload overhead 40 bytes and complete envelope overhead 62 bytes | Moderate: labels, AAD, format, and expired XChaCha specification need focused review; underlying crates are comparatively strong |
| **AES-256-GCM** | 96-bit nonce must be unique. One repeat is catastrophic. Random nonces are unsuitable for an effectively unbounded long-lived key without a low cap; coordinated counters add distributed state | Strongest standards/compliance position: NIST SP 800-38D and standards-track RFC 5116; broad interoperability and hardware/HSM support | RustCrypto `aes-gcm` documents one NCC Group audit with no significant findings and constant-time-oriented hardware/portable backends | Usually fastest on AES-NI/VAES/ARMv8 AES + carryless-multiply hardware; portable fallback exists. `P_MAX = 2^36 - 31` bytes. Aggregate block and forgery limits still require policy | Compact: 12-byte nonce + 16-byte tag; 50-byte minimum in the current envelope shape | Low primitive-spec burden, high nonce-system burden. Random use does not match CryptBox's long-lived/multi-process goal; counters would require a new reliable subsystem |
| **AES-256-GCM-SIV** | 96-bit nonce; misuse-resistant rather than collision-resistant. Reuse leaks equality for the repeated nonce instead of destroying key-wide security. Random nonce is recommended | Final CFRG-consensus RFC 8452 with IANA AEAD ID and vectors; not an IETF Standards Track or NIST mode | RustCrypto says the crate itself has never been audited; AES and POLYVAL dependencies were included in the AES-GCM audit | Two-pass encryption. RFC measurements report multikilobyte decryption within 5% of GCM and encryption near two-thirds GCM speed. `P_MAX = A_MAX = 2^36` bytes | Excellent and 12 bytes smaller than Suite 1: 12-byte nonce + 16-byte tag; 50-byte minimum | Lower construction-spec burden than XChaCha, but currently higher Rust implementation-assurance burden. Must never release unauthenticated plaintext during two-pass decryption |
| **AES-256-SIV (CMAC-SIV)** | Nonce-misuse-resistant. Without a nonce it is deterministic and leaks equality on every repeat, which is not CryptBox's desired randomized mode. RFC 5297 recommends at least 128 random nonce bits when randomized | Final informational RFC 5297 with IANA AEAD IDs and vectors; established but less common than GCM | RustCrypto says no audit has ever been performed and constant-time behavior has not been thoroughly assessed | Two-pass CMAC then CTR and slower than high-throughput modes. AES-256-SIV needs a 64-byte composite key. RFC recommends at most `2^48` distinct invocations per key | Viable with a stored 16-byte random nonce and 16-byte SIV/tag; would need HKDF to derive 64 bytes. Deterministic use is unsuitable | Higher than GCM-SIV: unaudited implementation, larger key schedule, older/more complex S2V interface, and no benefit over GCM-SIV for this use case |
| **XAES-256-GCM** | 192-bit random nonce and the same `2^80`/`2^-32` collision budget as XChaCha; explicitly not misuse-resistant or key-committing | C2SP specification built from NIST KDF/CMAC/AES-GCM components, but not itself an RFC or NIST standard | RustCrypto is `0.1.0-rc.3`; documentation says no audit and no constant-time guarantee | AES-GCM profile plus three AES-256 calls per operation, one amortizable; about 64 GiB max plaintext | Same 24-byte nonce + 16-byte tag overhead as Suite 1 | Too high today. It does not improve Suite 1's misuse behavior and is materially less mature in Rust |

Sources for the table are the algorithm specifications and official crate
documentation.[rfc5869][rfc8439][xchacha-draft][rfc5116][nist-gcm][rfc8452][rfc5297][c2sp-xaes][rustcrypto-chacha-011][rustcrypto-aes-gcm][rustcrypto-gcm-siv][rustcrypto-aes-siv][rustcrypto-xaes]

### Key/message limits need operational interpretation

Functional maximum message lengths are not safe lifetime quotas. Security
degrades with total blocks, messages, failed verification attempts, number of
keys, and the selected acceptable attacker advantage. The current CFRG AEAD
limits draft stresses that applications must select explicit targets and that
multi-key deployments require multi-key bounds. For ChaCha20-Poly1305 it gives
an integrity bound dependent on failed forgery attempts and message length,
not a flat "128-bit authentication" claim.[aead-limits]

This matters to CryptBox in three ways:

1. A full 128-bit tag does not by itself prove a flat 128-bit forgery margin at
   arbitrary volume. The design specification's requirement for "at least
   128-bit authentication strength" should be made concrete as a usage and
   attacker-advantage policy before production.[spec-suite]
2. Per-binding HKDF separation reduces the volume seen by each operational
   key, but the unbound domain can still aggregate all unbound fields.
3. Failed decryption attempts matter. If database contents are attacker-
   controlled, applications should rate-limit or otherwise bound repeated
   authentication attempts and should not turn failures into an unrestricted
   online oracle.

RFC 8452 supplies unusually useful long-lived-key examples. With uniformly
random nonces and attacker advantage bounded at `2^-32`, it gives limits of
`2^32` messages up to 8 GiB, `2^48` messages up to 32 MiB, or `2^64` messages
up to 128 KiB. These are more than sufficient for database fields, while
tolerating nonce collisions rather than assuming they never occur.[rfc8452]
AES-SIV instead recommends no more than `2^48` distinct invocations under one
key because of CMAC/S2V collision considerations.[rfc5297]

## Standards and interoperability

XChaCha's main weakness is documentary, not a known break. The final XChaCha
draft expired in 2020 and explicitly has no formal standing. RustCrypto says no
authoritative XChaCha20-Poly1305 specification exists, though interoperable
libraries and protocols provide "rough consensus and running code."
[xchacha-draft][rustcrypto-chacha-latest] Libsodium recommends it only when
interoperability with other libraries is not a concern.[libsodium-xchacha]

CryptBox already uses a private versioned envelope and adds its own HKDF and
AAD rules, so changing to AES does not make the complete stored format an
external standard. It would only make the AEAD component easier to reproduce
with generic crypto libraries. A complete independent CryptBox implementation
is required in every case.

AES-GCM has the broadest compliance and HSM availability. That can override
other criteria for a regulated deployment, but a compliant implementation does
not solve distributed nonce uniqueness. AES-GCM-SIV has a much stronger final
specification than XChaCha but is not a NIST mode. XAES-256-GCM aims to compose
NIST-approved components and retain the performance profile of GCM, but the
construction and Rust crate are too new to displace Suite 1.[c2sp-xaes]

## Hardware and portable performance

For database fields, fixed per-operation overhead and key derivation are likely
to matter more than bulk throughput. CryptBox currently performs HKDF-SHA-256,
constructs AAD, copies plaintext into a zeroizing buffer, and initializes an
AEAD for every field operation. Benchmarks over representative 20-byte,
200-byte, and multi-kilobyte values on supported production CPUs are more
useful than bulk cipher benchmarks.

The expected platform ordering is nevertheless clear:

- AES-GCM is normally the throughput leader on CPUs with AES and carryless-
  multiplication instructions. RustCrypto supports AES-NI/VAES on x86 and AES
  intrinsics on AArch64 with runtime detection and a constant-time fixsliced
  software fallback.[rustcrypto-aes][rustcrypto-aes-gcm]
- AES-GCM-SIV uses the same acceleration but requires two encryption passes
  and per-nonce key derivation. Its RFC reports encryption at about two-thirds
  GCM and decryption within about 5% for multikilobyte messages; small database
  fields can have a larger fixed-cost gap.[rfc8452]
- XChaCha20-Poly1305 is a strong portable choice without AES hardware. RFC 8439
  reports ChaCha20 around three times faster than AES in software-only settings,
  and RustCrypto provides portable and AVX2 paths.[rfc8439][rustcrypto-chacha-011]
- AES-SIV is two-pass and CMAC's dependency chain makes it less parallel than
  polynomial hashes. RFC 5297 explicitly trades throughput for nonce-robustness.
  It offers no clear performance or assurance advantage over GCM-SIV here.[rfc5297]

RustCrypto cautions that its ChaCha/Poly1305, GCM, and GCM-SIV portable paths
assume constant-time multiplication. Certain 32-bit PowerPC CPUs and some
non-ARM microcontrollers have variable-time multiplication and are unsuitable.
CryptBox should state its reviewed target set rather than claiming portable
constant time on every architecture.[rustcrypto-chacha-011][rustcrypto-aes-gcm][rustcrypto-gcm-siv]

## Persistent format and rotation

The existing envelope is well structured for persistent ciphertext:

```text
magic || format_version || suite_id || key_id || suite_payload
```

The clear `KeyId` enables direct historical-key lookup, and authenticating it
prevents ordinary key-generation substitution. The `suite_id` permits old
suites to remain decrypt-only while new writes move to another suite. This is
the right shape for both key rotation and algorithm migration.[wire][spec-format]

Recommendations for format stability:

- Never redefine Suite ID 1. Freeze it as the exact current labels, HKDF input,
  binding encoding, 24-byte nonce, ciphertext/tag ordering, and limits.
- Add any AES-GCM-SIV construction under a new suite ID. Its payload can be
  `nonce[12] || ciphertext || tag[16]`, reducing fixed overhead by 12 bytes.
- AES-SIV would need a new suite definition and 64-byte HKDF output for the
  AES-256 variant. Do not silently concatenate independently labeled keys
  without specifying and reviewing the exact derivation.
- Keep old suite code available for decryption until all persistent rows and
  backups governed by the retention policy have migrated. Dependency upgrades
  must retain compatibility vectors for old suites.
- Publish vectors for empty, short, and boundary-length plaintext; unbound and
  field-bound domains; every authenticated metadata field; and independent
  implementations. Current vectors are explicitly provisional and have not
  been independently cross-checked.[wire]

The format does not provide formal key commitment merely because `KeyId` is in
the KDF and AAD. Under the current threat model, root keys are trusted,
independently random material and the application chooses one exact key before
decryption, so conventional authentication is an appropriate design target.
If future providers permit adversarially selected keys, password-derived keys,
or ambiguous multi-recipient decryption, key commitment needs separate review;
RFC 9771 specifically lists key rotation and envelope encryption among its
applications.[rfc9771]

## Production review gates

Suite 1 should not lose its `EXPERIMENTAL` designation until all of these are
complete:

1. **Independent vectors:** reproduce XChaCha output against libsodium or
   another independent implementation, then independently implement the exact
   CryptBox HKDF, AAD, binding, and envelope vectors.
2. **Composition review:** review the fixed HKDF salt, all labels including NUL
   terminators, `info` encoding, binding injectivity, AAD encoding, key-ID use,
   error behavior, and the authenticate-before-use boundary.
3. **Maintained primitive implementation (complete):** the hand-written
   restricted HMAC/HKDF was replaced with RustCrypto crates without changing
   the RFC 5869, envelope, or blind-index vectors.
4. **Supported dependency line:** remain on the current RustCrypto release line
   and regenerate cross-version compatibility tests for future major upgrades.
   RustCrypto's policy only supports its latest release.[rustcrypto-security]
5. **Usage policy:** define maximum plaintext/AAD length appropriate to a
   database field, encryption count per `(KeyId, binding)`, total failed
   decryption attempts, acceptable attacker advantage, and a conservative
   rotation trigger. The 256 GiB primitive limit is not an appropriate field
   limit.
6. **Randomness policy:** permit only reviewed `getrandom` targets and fail
   closed. The crate assumes the OS supplies high-quality cryptographically
   secure randomness and documents target-specific early-boot caveats and
   dangerous opt-in/custom backends.[getrandom]
7. **Adversarial parsing:** fuzz malformed lengths and every envelope byte;
   verify uniform authentication failure for wrong binding/ciphertext/tag;
   retain distinct unsupported-version/suite and unknown-key operational
   errors without exposing plaintext or secrets.
8. **Failure handling:** verify no unauthenticated plaintext escapes on every
   error path and that callers cannot continue using partially decrypted data.
9. **Targeted side-channel review:** cover the supported architectures,
   zeroization boundaries, compiler behavior, and denial-of-service effects of
   attacker-controlled oversized or repeated ciphertext.
10. **Threat-model documentation:** prominently retain same-field row
    substitution, replay/rollback, length leakage, process compromise, and
    blind-index leakage as explicit non-goals.
11. **Cryptographic agility drill:** implement a test-only second suite or a
    migration fixture to demonstrate that old ciphertext remains decryptable
    and that `needs_reencryption` drives a safe suite/key migration.

## Final verdict

Suite 1 is not uniquely "best" in the abstract. AES-256-GCM-SIV has the better
failure mode if nonce generation fails, and AES-GCM has better compliance and
hardware ecosystem support. For CryptBox as implemented, however, nonce
generation is centralized inside the library, a 192-bit random nonce removes
cross-process coordination, the stored envelope already absorbs the larger
nonce, and the relevant RustCrypto implementation has the strongest audit
position of the nonce-safe choices.

Therefore:

- **Experimental release:** keep Suite 1 and keep it clearly labeled
  experimental.
- **Production after review:** yes, Suite 1 is defensible and a reasonable
  default after the production gates above are satisfied.
- **Production today:** no; the repository's current warning is warranted.
- **Next suite to investigate:** AES-256-GCM-SIV, contingent on a focused Rust
  implementation audit and representative benchmarks.
- **Candidate to avoid as the default:** random-nonce AES-256-GCM.
- **No clearly superior extra candidate:** XAES-256-GCM and Ascon-AEAD128 do
  not currently improve the combined nonce behavior, Rust maturity,
  interoperability, performance portability, and review burden.

## Primary sources

Only specifications, official project documentation/source, and this
repository were used for substantive claims.

[aead-limits]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-12
[binding]: ../src/binding.rs
[c2sp-xaes]: https://c2sp.org/XAES-256-GCM
[cargo]: ../Cargo.toml
[crypto-aad]: ../src/crypto.rs
[crypto-hkdf]: ../src/crypto.rs
[crypto-limits]: ../src/crypto.rs
[crypto-open]: ../src/crypto.rs
[crypto-seal]: ../src/crypto.rs
[crypto-tests]: ../tests/crypto.rs
[getrandom]: https://docs.rs/getrandom/0.4.3/getrandom/
[libsodium-xchacha]: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
[nist-ascon]: https://csrc.nist.gov/pubs/sp/800/232/final
[nist-gcm]: https://csrc.nist.gov/pubs/sp/800/38/d/final
[rfc5116]: https://www.rfc-editor.org/rfc/rfc5116.html
[rfc5297]: https://www.rfc-editor.org/rfc/rfc5297.html
[rfc5869]: https://www.rfc-editor.org/rfc/rfc5869.html
[rfc8439]: https://www.rfc-editor.org/rfc/rfc8439.html
[rfc8452]: https://www.rfc-editor.org/rfc/rfc8452.html
[rfc9771]: https://www.rfc-editor.org/rfc/rfc9771.html
[rustcrypto-aes]: https://docs.rs/aes/latest/aes/
[rustcrypto-aes-gcm]: https://docs.rs/aes-gcm/latest/aes_gcm/
[rustcrypto-aes-siv]: https://docs.rs/aes-siv/latest/aes_siv/
[rustcrypto-ascon]: https://docs.rs/ascon-aead128/latest/ascon_aead128/
[rustcrypto-chacha-011]: https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/
[rustcrypto-chacha-latest]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
[rustcrypto-gcm-siv]: https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/
[rustcrypto-security]: https://github.com/RustCrypto/AEADs/blob/master/SECURITY.md
[rustcrypto-xaes]: https://docs.rs/xaes-256-gcm/latest/xaes_256_gcm/
[spec-binding]: spec.md#93-security-properties-of-binding
[spec-format]: spec.md#15-ciphertext-envelope
[spec-suite]: spec.md#16-cipher-suite-selection
[spec-threat]: spec.md#4-threat-model
[wire]: wire-format.md
[xchacha-draft]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
