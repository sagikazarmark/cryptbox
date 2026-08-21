# Suite 1 Operational Usage Policy

**Research date:** 2026-08-21

**Status:** Proposed policy for production review. The numeric limits in this
document are CryptBox recommendations, not limits prescribed by the cited
standards. This document addresses the operational-policy review gate tracked
by issue 15.[issue-15]

## Executive policy

For Suite 1, an application should apply all of these limits:

| Quantity | Warning threshold | Hard limit or action |
|---|---:|---:|
| Plaintext in one database field | application-defined below the limit | `1,048,576` bytes (`1 MiB`) |
| Encryptions for one `(KeyId, binding)` | 75% of `2^32` | fewer than `2^32` |
| Encryptions for one root `KeyId`, summed across bindings | 75% of `2^36` | fewer than `2^36` |
| Age of a current root key | 9 months | replace for new writes before 1 year |
| Failed Suite 1 AEAD decryptions, deployment-wide | any sustained or unexplained failures | at most `2^20 - 1` over the accounting lifetime |
| Authenticated-encryption attacker advantage | n/a | target at most `2^-64` over one deployment |

Start rotation when the first warning threshold is reached: warning age,
warning count for any binding, or warning total for the root. A root key must
stop being used for new encryption before its one-year anniversary, before any
binding reaches `2^32` encryptions, or before its root total reaches `2^36`
encryptions. Historical keys may remain decrypt-only as required by
data-retention policy.[spec-rotation]

The unbound domain is one binding value. Consequently, every unbound
encryption under a `KeyId` shares the same operational key and the same
`2^32` counter. Field-bound values use separate operational keys, but still
contribute to the root's `2^36` total.[wire-binding][crypto-kdf]

These are policy ceilings, not safe points at which to start planning. A
deployment that cannot reliably count usage or complete rotation before a hard
limit must use lower local limits.

## What primary sources require

The source requirements and observations relevant to this policy are:

- RFC 8439 requires a nonce to differ for every invocation with one
  ChaCha20-Poly1305 key. It defines a `274,877,906,880`-byte functional
  plaintext maximum and a 16-byte authentication tag. The functional maximum
  follows from the 32-bit block counter; it is not an operational field-size
  recommendation.[rfc8439-aead]
- The expired XChaCha draft constructs XChaCha20-Poly1305 by deriving a subkey
  from the first 16 nonce bytes, then applying RFC 8439 ChaCha20-Poly1305 with
  the remaining 8 bytes. It says 192-bit random nonces reach approximately 50%
  collision probability after `2^96` messages and approximately `2^-32`
  collision probability at a conservative `2^80` messages under one key.
  The draft has no formal IETF standing.[xchacha-construction][xchacha-nonces]
- RFC 5869 says HKDF `info` binds derived key material to application- and
  context-specific information and can prevent deriving the same material in
  different contexts. Suite 1 includes version, suite, `KeyId`, and binding in
  `info`, so `(KeyId, binding)` identifies the operational-key domain for these
  counters.[rfc5869-info][crypto-kdf]
- The CFRG AEAD-limits draft distinguishes strict functional input limits from
  security limits caused by repeated key use. It requires an application to
  choose an attacker-advantage target and to count protected messages and
  rejected forgeries against limits derived for its message size. It says AE
  security, covering confidentiality and integrity together, should normally
  be the basis for limits.[aead-intro][aead-calculation]
- For ChaCha20-Poly1305, the draft gives the multi-key bound
  `AEA <= v * (L' + 1) / 2^103`, where `L'` is the maximum AAD-plus-plaintext
  length in 16-byte Poly1305 blocks and `v` is total failed AEAD decryption
  invocations plus one across all keys. Its confidentiality bound is
  `CA <= (o + q) / 2^247`, with a technical ceiling near `q = 2^100`.
  Here `o` is offline adversary work and `q` is protected messages across all
  keys.[aead-chacha-multi]
- The AEAD-limits draft notes that some protocols naturally limit `v` to one
  by terminating after an authentication failure. TLS 1.3 likewise treats a
  record-protection failure as a fatal `bad_record_mac` alert. These are
  precedents for failing closed, not direct requirements on stored database
  ciphertext.[aead-single-examples][tls-failure]
- NIST SP 800-57 Part 1 Rev. 5 Sections 5.3.1 through 5.3.6 describe
  cryptoperiod selection as a risk decision affected by usage volume,
  compromise consequences, rekeying cost, and key lifetime. Its rough Table 1
  gives symmetric master keys an originator usage period of about one year and
  symmetric data-encryption keys at most two years.[nist-cryptoperiod]

Neither RFC 8439, RFC 5869, the XChaCha draft, nor NIST specifies a `1 MiB`
database-field limit, the `2^32`/`2^36` counters, or a `2^-64` CryptBox target.
Those are the conservative recommendations derived below.

## Derivation of the proposed limits

### Attacker-advantage target

Use a deployment-wide authenticated-encryption advantage target of:

```text
AEA <= 2^-64
```

This is an operational probability target, not a claim that the 128-bit tag or
256-bit key has only 64 bits of primitive strength. Following the AEAD-limits
draft's suggested split, allocate at most `2^-65` to confidentiality and at
most `2^-65` to integrity.[aead-calculation]

The scope is all Suite 1 keys accepted by one independently keyed deployment,
including historical decrypt-only keys. Separate deployments with independent
root keys have separate budgets. Merely rotating the current root does not
reset the deployment-wide failed-decryption count because historical keys
remain accepted.

### Plaintext maximum

Set the database-field plaintext maximum to:

```text
P_policy = 2^20 = 1,048,576 bytes
```

This is about `2^18` times smaller than RFC 8439's functional maximum. A Suite
1 envelope then occupies at most `1,048,638` bytes because the format adds 62
bytes.[wire-envelope]

The limit is a policy judgment with three benefits:

- It is large enough for ordinary scalar, JSON, and modest binary database
  fields without presenting the 256 GiB primitive limit as normal usage.
- It bounds per-operation allocation and authentication work. The current
  implementation copies plaintext into a working buffer and then copies the
  resulting ciphertext into the returned envelope; decryption similarly copies
  the payload before authentication.[crypto-seal][crypto-open]
- It gives a concrete maximum `L'` for the integrity calculation. Suite 1 AAD
  is at most 88 bytes for a field-bound value: the 25-byte AAD label, 46-byte
  envelope prefix, and 17-byte binding. Therefore:

```text
L' = ceil(1,048,576 / 16) + ceil(88 / 16)
   = 65,536 + 6
   = 65,542 Poly1305 blocks
```

Applications should choose a smaller profile-specific maximum where their data
model permits it. Both encryption and decryption must reject the policy limit
before allocating attacker-controlled sizes. The implementation currently
enforces only RFC 8439's functional maximum, so this recommendation still
requires an application or library enforcement point.[crypto-limit]

### Failed-decryption budget

Limit the deployment to at most `2^20 - 1 = 1,048,575` failed Suite 1 AEAD
decryptions. The draft defines `v` as failures plus one, so this keeps
`v <= 2^20`. With the maximum field size:

```text
IA <= v * (L' + 1) / 2^103
   <= 2^20 * 65,543 / 2^103
   ~= 6.7770 * 10^-21
   ~= 2^-66.9998
   < 2^-65
```

This budget is global across processes, tenants, bindings, current keys, and
retained historical keys. Every invocation that reaches AEAD verification and
returns an authentication failure consumes one unit, including repeated checks
of the same ciphertext. Parse failures, unsupported suites, and unknown
`KeyId`s do not enter this cryptographic `v`, because no AEAD verification
occurs, but they still require ordinary denial-of-service rate limits.

Operational handling should be stricter than the lifetime ceiling:

- Do not expose decryption as an unauthenticated generic network oracle.
- Permit at most one automatic AEAD attempt for a stored value in one
  operation. Quarantine or mark a value after failure; do not retry it in a
  loop.
- Rate-limit by caller and tenant, alert on bursts, and maintain a durable
  deployment-wide total.
- Treat unexpected failures of database-resident ciphertext as corruption or
  an active attack. At the hard limit, stop attacker-influenced decryptions and
  require incident response; rotating only the write key does not restore the
  spent budget.

If a deployment cannot maintain a trustworthy global lifetime count, it must
allocate smaller durable sub-budgets to services or tenants whose sum is no
greater than `2^20 - 1`.

### Encryption counts and nonce collisions

For `q` independent uniform 192-bit nonces under one operational key, the
birthday approximation is:

```text
Pr[collision] ~= q(q - 1) / 2^193
```

At the proposed per-binding hard limit:

```text
q_binding < 2^32
Pr[collision for one binding] < 2^-129
```

For one root, let `q_i` be usage of binding `i`, `q_max < 2^32`, and
`Q_root = sum(q_i) < 2^36`. The union bound across derived operational keys is:

```text
sum(q_i(q_i - 1)) / 2^193
  < q_max * Q_root / 2^193
  < 2^32 * 2^36 / 2^193
  = 2^-125
```

Thus field binding separates nonce domains, while the root cap bounds their
aggregate risk. Unbound encryption has only one `q_i` and therefore reaches the
per-binding cap directly. The proposed counts are vastly below the XChaCha
draft's illustrative `2^80` messages for collision probability around
`2^-32`; this margin is intentional.[xchacha-nonces]

The AEAD-limits draft's ChaCha20 confidentiality bound is also non-limiting at
these volumes. Deployment-wide Suite 1 encryption must remain below its
technical `q = 2^100` ceiling. For illustration, even `2^32` consecutive root
generations each exhausted at `2^36` encryptions total only `2^68` messages.
Assuming offline work `o <= 2^128`, the cited bound is then approximately
`CA = 2^-119`, before separately adding random-nonce collision probability.

Count every encryption invocation that reaches nonce generation, including
reencryption, retries whose output is discarded, and operations lost to a
crash. In a multi-process deployment, counters must be durable and shared.
Range leasing is acceptable only if the entire leased range is charged when
issued, so a crash can overcount but never undercount.

### Rotation triggers

Replace the current root for new writes at the earliest of:

- 9 months, as the planned warning point, with cutover before 1 year;
- 75% of `2^32` encryptions in any one binding;
- 75% of `2^36` encryptions summed across the root's bindings.

At a full year, the count limits correspond to sustained averages of about 136
encryptions per second in one binding and 2,178 encryptions per second across
the root. Capacity planning must use peak and projected traffic, not these
averages. A deployment expected to cross a warning threshold should rotate
earlier or shorten its routine schedule.

The one-year trigger uses NIST's rough symmetric-master-key period as a
conservative operational analogue because a Suite 1 root derives many data
keys. It is not a mathematical consequence of XChaCha20-Poly1305, and it does
not make Suite 1 NIST-approved. Root age also does not determine when a
decrypt-only historical key can be destroyed; retention, backups, migration,
and legal requirements determine that separately.[nist-cryptoperiod]

## Combined budget check

Under the proposed limits and assumptions:

| Contribution | Upper bound |
|---|---:|
| ChaCha20-Poly1305 integrity, all accepted keys | approximately `2^-66.9998` |
| Random-nonce collision, one binding | less than `2^-129` |
| Random-nonce collision, one root | less than `2^-125` |
| Random-nonce collision across `2^32` root generations | less than `2^-93` |
| ChaCha20 confidentiality with `q <= 2^68`, `o <= 2^128` | approximately `2^-119` |

Their sum remains below `2^-66`, leaving at least a factor-of-four margin below
the `2^-64` target. The failed-decryption term dominates. This calculation does
not include compromise of root keys, failure of the operating-system random
source, implementation bugs, side channels, or weaknesses in the underlying
primitives.

## Caveats and review questions

- The AEAD-limits document is an active Internet-Draft, not an RFC, and its
  bounds can change. The policy should be recalculated when the draft changes
  or becomes an RFC.[aead-status]
- Its concrete ChaCha20-Poly1305 analysis is stated for the RFC 8439 AEAD with
  96-bit nonce randomization. Suite 1 uses the XChaCha reduction and fully
  random 192-bit nonces. Applying the ChaCha bound conditional on no complete
  nonce collision, then adding the 192-bit birthday risk, is a conservative
  engineering interpretation rather than a published concrete
  XChaCha20-Poly1305 proof. Production review should confirm this treatment and
  account for HChaCha20 PRF advantage.
- The multi-key analysis models operational keys as independent and uniformly
  distributed. Applying it to Suite 1 also relies on HKDF-SHA-256 making
  distinct binding-derived keys computationally independent. Production review
  should confirm that reduction for the exact Suite 1 `info` construction.
- The XChaCha specification is expired and has no formal IETF standing. Its
  nonce-volume discussion is informative rather than a standards requirement.
- The `2^-64` target should be reconciled with the design specification's
  phrase "at least 128-bit authentication strength." A full 128-bit tag is a
  primitive parameter; no repeatedly used AEAD retains flat `2^-128` forgery
  probability at arbitrary message size and verification volume.[spec-suite]
- The `1 MiB` choice is an application policy judgment. Deployments needing
  larger values should use blob/file encryption with independently reviewed
  chunking, or recalculate `L'` and the failed-decryption budget rather than
  silently raising this field limit.
- Exact global counters add distributed state to an otherwise stateless
  encryption API. The production design still needs to choose whether
  enforcement belongs in CryptBox, a key-provider service, storage adapters,
  or deployment tooling.

## Primary sources

Only specifications, official publications, the originating issue, and this
repository were used for substantive claims.

[aead-calculation]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-12#section-5
[aead-chacha-multi]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-12#section-7.2
[aead-intro]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-12#section-1
[aead-single-examples]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits-12#section-6.6
[aead-status]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-limits/12/
[crypto-kdf]: ../src/crypto.rs#L224-L247
[crypto-limit]: ../src/crypto.rs#L249-L256
[crypto-open]: ../src/crypto.rs#L326-L351
[crypto-seal]: ../src/crypto.rs#L259-L293
[issue-15]: https://github.com/sagikazarmark/cryptbox/issues/15
[nist-cryptoperiod]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
[rfc5869-info]: https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2
[rfc8439-aead]: https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8
[spec-rotation]: spec.md#13-encryption-key-rotation
[spec-suite]: spec.md#16-cipher-suite-selection
[tls-failure]: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2
[wire-binding]: wire-format.md#binding
[wire-envelope]: wire-format.md#envelope
[xchacha-construction]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2
[xchacha-nonces]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.1
