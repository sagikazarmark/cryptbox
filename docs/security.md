# Threat model and security boundaries

CryptBox encrypts selected application values before storage.
**It is not production-ready.** Ciphertext format 2,
blind-index format 2, and suite 1 remain experimental; version numbers and passing
tests do not indicate security approval. [Documentation](README.md).

## Trust boundary and assumptions

<!-- BEGIN SHARED: trust-boundary -->

```mermaid
flowchart TB
    subgraph trusted["Trusted application boundary"]
        K["Keyrings: independent encryption and index roots"]
        A["Application: plaintext, fields, authorization"]
        C["CryptBox: encode, encrypt, authenticate, decode"]
        K --> C
        A <--> C
    end
    C -->|"Ciphertext and optional blind indexes"| S["Untrusted storage, snapshots and backups"]
    S -->|"Untrusted bytes and query candidates"| C
```

<!-- END SHARED: trust-boundary -->

Confidentiality assumes keys and plaintext-bearing artifacts remain separate from
compromised storage. Trust the application, its key resolution, dependencies, and operating
system: root keys must be cryptographically random, encryption and index roots
independently generated, and each generation ID permanently paired with the same
material. IDs are public metadata; generate them independently of key bytes.
Seals supply persistent schema, including their binding declaration. Binding values and
record IDs are only as trustworthy as their source: take them from verified claims
or an authorized request, never from the stored row. The exception is a
`Record`'s record ID, which is read from the row and checked by opening every
seal bound to the record; a record whose seals bind none gets no check.
Secure OS randomness and a compatible target are required; see [platform constraints](features.md#platforms-and-tested-configurations).

## Threats and unsuitable uses

| Attacker capability | Protection or limitation |
| --- | --- |
| Read dumps, snapshots, backups, or detached volumes | Selected values remain confidential under the assumptions above. Other columns, IDs, and metadata remain visible. |
| Modify stored ciphertext | Authenticated decryption rejects tampering. Parsing alone does not authenticate; malformed formats or unknown keys may fail earlier. |
| Copy ciphertext to another seal | Authentication rejects a seal with a different seal ID. A different binding declaration reports `BindingMismatch`. |
| Copy ciphertext to another tenant, org, or workspace | Authentication rejects other bound values of a seal that declares them, including a record's bound columns changed in place. A seal without bound values cannot tell tenants apart. |
| Copy ciphertext between rows of the same seal | Authentication rejects another record of a seal that binds one. For a seal without a record, substitution among rows of the same bound values can succeed. |
| Return a whole row in place of another | Every value in it opens, because each is bound to that row's own record ID. A `Record` opens as the record it is: when you asked for one record by ID, compare the opened ID with it. |
| Restore an older authentic value | No replay, rollback, or freshness protection. |
| Observe sizes, indexes, and queries | Unpadded length reveals encoded length; padding reveals a bucket or fixed target. Blind indexes leak equality/frequency within their partition, including across the bound values they span and across records; an index without a partition leaks across the whole seal. Access patterns remain visible. |
| Alter indexes or omit query results | Candidate comparison rejects false matches, but cannot detect omitted matches. Search completeness is not guaranteed. |
| Compromise the live application | Plaintext and keys can be exposed. CryptBox supplies no process-isolation boundary. |

CryptBox is unsuitable for requirements such as production-approved cryptography
today, FIPS-validated AES, transparent whole-database encryption, arbitrary
encrypted queries, or secrecy from the application itself. Blind indexes support
equality-style candidate lookup, not ordering, ranges, or full-text search.

## Application responsibilities

- Own authorization, key provisioning, stable seal/index schema, and operational
  limits. Bound encoded/padded sizes, incoming envelopes, decoding expansion, and
  repeated authentication attempts; the [functional size limit](wire-format.md#size-semantics-and-enforcement)
  is not an operational budget.
- Store ciphertext and indexes atomically. Query every readable index generation,
  authenticate/decrypt candidates, and compare identically normalized plaintext.
  Never use truncated indexes as uniqueness constraints. Avoid indexing
  low-cardinality or highly skewed sensitive values; truncation does not remove
  their leakage. Detecting missing rows requires application-owned evidence.
- Protect logs, traces, crash dumps, swap, configuration, and application copies.
  CryptBox-owned zeroization cannot erase every copy; see
  [plaintext and key ownership](ownership.md).
- Treat rotation as selection of a new current generation, not revocation,
  re-encryption, or crypto-shredding. Follow [key lifecycle and recovery](key-rotation.md)
  and the [whole-store audit](reencryption-sweep.md#verification-and-retirement).
  Generation convergence alone establishes neither authenticated readability nor
  index consistency, and live-table convergence does not retire backup dependencies.

## What each check establishes

These checks answer different questions about stored data. Their results are
distinct from the independent security review status of the implementation.

| Check | Establishes | Does not establish |
| --- | --- | --- |
| Parse ciphertext or deserialize stored bytes | Supported structure and lengths | Authenticity or readability |
| Inspect generations / complete sweep verification | Stored values name the intended generations | Authentication, decodability, or index consistency |
| Open with the expected seal and binding values | Authentication under that seal, its bound values, and record, padding removal, and decoding for that value | Row identity for a seal without a record, freshness, or index consistency |
| Verify a lookup candidate | Its normalized plaintext matches the query | Stored-index authenticity or completeness of query results |
| Recompute a stored index under its recorded generation | Consistency with authenticated plaintext and the expected index policy at the configured precision | Absence of omitted rows or rollback |

A whole-store audit must cover the complete application-owned population, not only
rows returned by blind-index queries. Follow the
[verification procedure](reencryption-sweep.md#verification-and-retirement) before
retiring keys or closing a migration.

## Why these constructions

HKDF-SHA-256 separates operational keys by version, suite, generation, and binding.
XChaCha20-Poly1305 uses fresh OS-random 192-bit nonces, avoiding coordinated counters
across processes. It is **not nonce-misuse-resistant**: repeating a complete nonce
under one operational key is unsafe. Its specification is an expired IETF draft,
not a final standard. Separately keyed, domain-separated HMAC-SHA-256 indexes
permit deterministic lookup and independent rotation; truncation trades precision
for false candidates, without eliminating equality leakage.

## Security review path

Read the [wire recipes and provisional vectors](wire-format.md), then the
[current model](concepts.md) and [API reference](https://docs.rs/cryptbox/latest/cryptbox/).
Outstanding gates include independent vectors ([#10](https://github.com/sagikazarmark/cryptbox/issues/10)),
HKDF/HMAC/AAD composition and failure-path review, parser fuzzing
([#11](https://github.com/sagikazarmark/cryptbox/issues/11)), target/entropy and
compiler/zeroization review, accepted usage policy with an enforcement strategy,
and pilot use before format freeze ([#12](https://github.com/sagikazarmark/cryptbox/issues/12)).
A primitive implementation's audit does not audit CryptBox's composition.

## Historical references

The frozen [suite research (2026-08-21)](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/suite-evaluation.md),
[usage proposal (2026-08-21)](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/suite-1-usage-policy.md)
([#15](https://github.com/sagikazarmark/cryptbox/issues/15)), and
[v0.1 design](https://github.com/sagikazarmark/cryptbox/blob/0c3627e1817b88cfdc681efec20335fde525c526/docs/spec.md)
retain rationale and deferred plans. The numeric policy remains **proposed**;
issue closure recorded authoring, not acceptance. Its message-size, count, age,
and deployment failure budgets are not library-enforced.
