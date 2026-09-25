# Evaluate suitability and security

**Explanation · current 0.5.0 behavior, experimental assurance.** This is the
adoption and security-review starting point. [All tasks](README.md).

CryptBox encrypts selected application values before they cross supported
storage boundaries. The application owns policy and key provisioning; the
database stores ciphertext and, optionally, leakier searchable blind indexes.
The application still holds plaintext while using the value.

## Threats and unsuitable uses

| Situation | Boundary |
| --- | --- |
| An attacker reads a database dump, snapshot, backup, or detached volume | Selected encrypted values remain confidential **if keys and plaintext-bearing artifacts are kept separately and uncompromised**. Other columns and metadata remain visible. |
| Stored ciphertext is modified | Authenticated decryption rejects tampering; structural parsing alone does not. Unknown formats or keys can fail before authentication. |
| A ciphertext is copied to a different logical field | `FieldBound` rejects it at authentication; `Unbound` opts out. |
| A ciphertext is copied to another row in the same field | Current binding does not prevent substitution. Row/tenant binding is unavailable. |
| An older authentic ciphertext is restored | No replay or rollback protection is provided. |
| The application process is compromised while keys are live | Plaintext and keys can be exposed. CryptBox is not a process-isolation boundary. |
| An observer sees ciphertext sizes, queries, or index values | Unpadded sizes reveal encoded length; padding changes size leakage, not access patterns. Blind indexes reveal equality/frequency and return candidates, not authoritative matches. |

CryptBox is unsuitable when the requirement is production-approved cryptography
today, FIPS-validated AES, transparent whole-database encryption, arbitrary
encrypted queries, built-in row/tenant isolation, replay prevention, or secrecy
from the application itself. Current adapters cover PostgreSQL and SQLite with
SQLx; other storage integrations need application code or separately tracked work.

Avoid blind indexes for low-cardinality or highly skewed sensitive values. Never
use a truncated index as a uniqueness constraint. Decrypt candidates and compare
normalized plaintext. Logs, traces, crash dumps, swap, application copies, and
OS-retained secret configuration require application-level handling: zeroizing
CryptBox-owned keys/buffers does not erase all plaintext everywhere.

## Experimental maturity

**Do not treat CryptBox as production-ready.** Crate 0.5.0 uses experimental
ciphertext format 1, blind-index format 1, and suite 1. These numbers do not
indicate security approval. An audit of an underlying primitive implementation
does not review CryptBox's composition or its use in your application.

Outstanding production review gates include:

- Independently generated and cross-checked suite/envelope/index vectors
  ([#10](https://github.com/sagikazarmark/cryptbox/issues/10)). Existing vectors are provisional.
- Focused review of HKDF/HMAC domain separation, authenticated data, binding,
  parser failures, and key/plaintext lifetime, including compiler-generated copies.
- Accepted operational key-usage policy and an application enforcement strategy.
  The [numeric policy](suite-1-usage-policy.md) remains **proposed**; closing its
  authoring issue did not approve it. CryptBox does not enforce its proposed
  padded-message size, message-count, age, or deployment failure budgets.
- Parser fuzzing ([#11](https://github.com/sagikazarmark/cryptbox/issues/11)),
  supported-target/entropy review, and pilot use before format freeze
  ([#12](https://github.com/sagikazarmark/cryptbox/issues/12)). Passing CI is not
  completion of these gates.

## Configuration decision

Read the [authoritative feature/platform reference](features.md), also included
in the crate landing, before choosing a target or adapter. The published 0.5.0
archive predates these documentation additions. Your application must provide stable key/ID
pairs, a compatible target/entropy source, and any database runtime/TLS choices.
Generate encryption and blind-index roots independently.

Rotation selects a new current generation; it is not revocation, re-encryption,
or crypto-shredding. Live-table convergence does not prove that old keys can be
destroyed: backups, archives, and rollback data may still need them. Start with
the [maintenance guide](reencryption-sweep.md) and consult the remaining
[operational journey work](adoption-walk.md#remaining-journeys).

## Security review path

Read these in order:

1. This threat model and the [current concepts](concepts.md), especially sealed
   bindings and the difference between plaintext, ciphertext, and candidates.
2. The [crate reference](https://docs.rs/cryptbox/0.5.0/cryptbox/): features,
   platform constraints, persistent schema, and public trait contracts.
3. The [wire-format reference](wire-format.md): current layout and provisional
   vectors, including self-contained encryption and blind-index derivation recipes.
   Formats remain experimental.
4. The [suite evaluation](suite-evaluation.md): dated research, primitive
   rationale, alternatives, and review gates, not production authorization.
5. The [proposed usage policy](suite-1-usage-policy.md): recommendations and open
   review questions, with [padding-aware size definitions and examples](suite-1-usage-policy.md#plaintext-maximum).
6. The [stored-value assurance procedure](stored-values.md#obtain-additional-assurance)
   and [maintenance verification](reencryption-sweep.md#verification-and-retirement):
   parsing/generation classification versus authenticated readability and index consistency.

The [original v0.1 design](spec.md) supplies historical rationale only. Its API
sketches and future extension plans are not current instructions.
The [security-reference cold walk](adoption-walk.md#security-reference-follow-up)
records recipe and padded-size task completion, separately from assurance gates.

Next: choose a configuration in the crate reference, or try the
[ephemeral first round trip](../README.md#quick-start) before durable integration.
