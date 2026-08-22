# Migrating Legacy Data To CryptBox

Deployments may adopt CryptBox over columns that contain plaintext, ciphertext
from a previous application encryption solution, or a mixture of both. The
`migrate` Cargo feature provides an explicit facility for this bounded window: a
permissive read type, an application-supplied legacy recovery handler, and a
resumable sweep driver. The steady-state decoding path stays strict throughout:
legacy data and invalid CryptBox envelopes always fail normal
`Encrypted`/`Ciphertext` decoding.

The runnable [SQLite legacy migration example] shows mixed foreign ciphertext,
plaintext, and CryptBox rows. The simpler [plaintext-only example] uses the
built-in identity recovery path. The same control flow applies to PostgreSQL
and, through a custom `SweepStore`, other stores.

## Preconditions

Provision encryption (and, where indexed, blind-index) keys to every
application instance first. Then switch **every writer** to always encrypt
through `Encrypted`, `prepare_with`, or the automatic adapters before enabling
permissive reads. From that point on, only pre-existing rows use a legacy
format, so the migration window is bounded.

If a column gains a blind index during migration, add the index column ahead of
the sweep; legacy rows may hold an empty placeholder until the sweep derives
the real index. The sweep recovers sensitive data in the maintenance process,
so give that process the same logging, memory, and access controls as an
application writer.

## Recovering Legacy Values

Implement `LegacyFormat` on an application-owned handler. The handler closes
over the previous solution's keys and returns plaintext bytes in a
`Zeroizing<Vec<u8>>`; CryptBox then decodes those bytes with the profile's
codec. Keep the handler explicit rather than process-global so its uses can be
found and removed when the window closes.

```rust,ignore
struct PreviousEncryption {
    key: Zeroizing<[u8; 32]>,
}

impl LegacyFormat for PreviousEncryption {
    fn recover(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, LegacyError> {
        // Parse, authenticate, and decrypt with the previous solution.
        // Return only sanitized errors; never retain bytes or key material.
        previous_decrypt(&self.key, bytes)
    }
}
```

The trait is synchronous and intended for local, CPU-bound recovery. A legacy
system that requires a network call for every value should recover values in a
custom `SweepStore` or pre-fetch step rather than block inside the handler.

When plaintext and foreign ciphertext coexist, the handler must distinguish
the previous solution's representation, normally by an authenticated header,
and use identity recovery for plaintext:

```rust,ignore
if bytes.starts_with(PREVIOUS_FORMAT_HEADER) {
    previous_decrypt(&self.key, bytes)
} else {
    Ok(Zeroizing::new(bytes.to_vec()))
}
```

CryptBox only distinguishes valid CryptBox envelopes from non-envelope legacy
bytes. It does not detect which legacy format a non-envelope value uses, and it
never writes the legacy format.

**Unauthenticated legacy formats require extra verification.** A wrong key or
corrupt value in an authenticated format fails recovery. CBC without a MAC and
other unauthenticated formats can instead produce plausible garbage that the
sweep would encrypt as authoritative data. A structured codec may reject some
garbage, but `Raw` rejects none. Add out-of-band integrity checks or manually
verify representative values before accepting the sweep result.

Handler implementations are responsible for zeroizing their own key material
and intermediate buffers. CryptBox zeroizes the legacy and recovered plaintext
buffers that it owns.

## The Bounded Window

Read the column as `cryptbox::migrate::MaybeEncrypted<T, Profile>` wherever
legacy rows may still appear. `MaybeEncrypted::from_bytes` and its SQLx
`Decode` implementations classify bytes without accessing either CryptBox or
legacy keys:

- Valid CryptBox envelopes use normal authenticated decryption and ignore the
  legacy handler.
- Bytes without the envelope magic are retained in a zeroizing legacy buffer.
  `decrypt_with` treats them as plaintext; `decrypt_with_legacy` first invokes
  the handler and then the profile codec.
- Bytes carrying the magic must be structurally valid CryptBox envelopes.
  Malformed or unsupported envelopes are hard errors and never fall back to a
  legacy handler.

Because legacy decoding is deferred, codec-invalid non-envelope bytes now
construct and SQLx-decode successfully; the codec error is returned by
`decrypt`, `decrypt_with`, `decrypt_legacy`, or `decrypt_with_legacy` instead.

`MaybeEncrypted` implements no storage `Encode` and no Serde. Writes always go
through `Encrypted` or `Prepared`, so every write during the window shrinks the
legacy population.

**Envelope-magic collision.** Arbitrary legacy data that begins with the 4-byte
CryptBox envelope magic is classified as CryptBox ciphertext and then fails, a
hard error rather than silently wrong data. If a discriminator column tracks
the storage format, use `MaybeEncrypted::from_legacy_bytes` for rows known to be
legacy; it bypasses envelope classification entirely. Use `from_plaintext` for
an already decoded value and `From<Ciphertext>` for known CryptBox ciphertext.

## Running The Sweep

Configure a `RowPlanner` with the profile context, CryptBox key provider,
legacy handler, and each blind-index column in stored order:

```rust,ignore
let planner = RowPlanner::<String, UserEmail>::new(&(), &keys)
    .with_legacy(&previous_encryption)
    .with_index_with::<EmailLookup>(&index_keys);
```

Omit `with_legacy` for a plaintext-only migration; non-envelope bytes then use
identity recovery and decode directly through the profile's codec.

Drive the planner with `Sweep` over a `SweepStore`:

- `SqliteSweepStore` and `PostgresSweepStore` cover tables with an integer
  cursor column. A `SweepTable` names the table, cursor, ciphertext, and index
  columns. The cursor must contain unique, immutable values: pagination resumes
  strictly after the checkpoint, so a non-unique cursor silently skips rows at
  a batch boundary during both sweeping and verification.
- Any other store or cursor shape can implement `SweepStore` directly under
  the same unique total-order cursor contract.

`Sweep::run` resumes from the durable checkpoint and, per row, recovers and
encrypts legacy data (deriving every registered index), re-encrypts stale
envelopes, re-derives stale indexes from authoritative decrypted ciphertext,
and skips current rows without consuming nonces. Updates are compare-and-swap
against all originally read bytes. A row lost to a concurrent writer is counted
as a conflict and deliberately not retried. The checkpoint advances only after
a whole batch succeeds, so replay after a crash is safe.

An unrecoverable legacy row stops the run for investigation just like a
malformed envelope. The durable checkpoint bounds the search to one batch. Fix
or quarantine the row, then resume.

## Stepped Execution And Durable Runtimes

`Sweep::run` loops to exhaustion, but external orchestrators can drive one
batch at a time:

- `Sweep::run_batch` processes one batch using the store's durable checkpoint.
- `Sweep::process_batch` takes and returns a cursor without checkpoint IO, so a
  durable-execution runtime can journal progress itself.
- `Sweep::verify_batch` steps the read-only verification pass. Sum batch
  reports with `SweepReport::merge`.

Batch replay is idempotent: current rows are skipped and updates compare the
originally read bytes. Under replay, summed reports may overcount conflicts, so
treat run reports as advisory and terminal verification as authoritative.

## Verification And Closing The Window

`Sweep::verify` performs a fresh, full, read-only pass. It classifies legacy
rows without the legacy handler and returns a `SweepReport`. Close the window
only when a complete pass reports `is_terminal()`: zero `legacy`, zero `stale`,
and zero `malformed` rows. If writes continue during verification, repeat until
one complete pass is clean.

After the terminal state:

1. Replace `MaybeEncrypted` reads with strict `Encrypted`/`Ciphertext` reads.
2. Delete the legacy handler and confirm no references to its type remain.
3. Disable the `migrate` feature.
4. Retire historical CryptBox keys and probes following the
   [re-encryption sweep guide](reencryption-sweep.md).
5. Destroy the previous solution's keys only after all rollback and retention
   requirements permit it.

[SQLite legacy migration example]: ../examples/legacy_migration.rs
[plaintext-only example]: ../examples/plaintext_migration.rs
