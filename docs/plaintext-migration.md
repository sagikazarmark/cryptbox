# Migrating Plaintext Columns To Encryption

Most deployments adopt CryptBox over tables that already hold plaintext. The
`migrate` Cargo feature provides the explicit facility for that adoption: a
permissive read type for a bounded migration window and a resumable sweep
driver. The steady-state decoding path stays strict throughout — plaintext and
invalid envelopes always fail the normal `Encrypted`/`Ciphertext` decode.

The runnable [SQLite migration example] shows the complete pattern with SQLx.
The same control flow applies to PostgreSQL and, through a custom `SweepStore`,
to other stores.

## Preconditions

Provision encryption (and, where indexed, blind-index) keys to every
application instance first. Then switch **every writer** to always encrypt
through `Encrypted`, `prepare_with`, or the automatic adapters — before any
permissive reads are enabled. From that point on, only pre-existing rows hold
plaintext, so the migration window is bounded.

If a column gains a blind index during migration, add the index column ahead of
the sweep; legacy rows may hold an empty placeholder until the sweep derives
their index. The sweep decrypts sensitive data in the maintenance process, so
give that process the same logging, memory, and access controls as an
application writer.

## The Bounded Window

Enable the `migrate` feature and read the column as
`cryptbox::migrate::MaybeEncrypted<T, Profile>` wherever legacy rows may still
appear. Classification keys on the envelope magic: bytes without it are legacy
plaintext and decode through the profile's codec; bytes with it must be valid
envelopes — malformed or unsupported envelopes remain hard errors and never
fall back to plaintext.

`MaybeEncrypted` implements no storage `Encode` and no Serde. Writes always go
through `Encrypted` or `Prepared`, so every write during the window shrinks the
remaining plaintext.

**Binary legacy data caveat.** Arbitrary binary plaintext (a `Raw`-codec
column) that happens to begin with the 4-byte envelope magic is classified as
ciphertext and then fails — a hard error, never silently wrong data. Stores
that reject interior NUL bytes in text cannot produce such values. If your
legacy data is arbitrary binary, track encryption state out of band (for
example a discriminator column) and construct reads with
`MaybeEncrypted::from_plaintext` or `From<Ciphertext>` instead of byte
classification.

## Running The Sweep

Configure a `RowPlanner` with the profile's context, the encryption key
provider, and each blind-index column in stored order, then drive it with
`Sweep` over a `SweepStore`:

- `SqliteSweepStore` and `PostgresSweepStore` cover tables with an integer
  cursor column; a `SweepTable` names the table, cursor, ciphertext, and index
  columns. The cursor column must hold unique, immutable values, such as an
  integer primary key: pagination resumes strictly after the checkpoint, so a
  non-unique cursor silently skips rows sharing a value with a batch
  boundary — and the verification pass pages the same way, so it would miss
  them too.
- Any other store or cursor shape implements the `SweepStore` trait directly,
  under the same unique total-order cursor contract.

`Sweep::run` resumes from the durable checkpoint and, per row, encrypts legacy
plaintext (deriving every registered index), re-encrypts stale envelopes,
re-derives stale indexes from the decrypted, authoritative ciphertext, and
skips current rows without consuming nonces. Updates are compare-and-swap
against all originally read bytes; a row lost to a concurrent writer is counted
as a conflict and deliberately not retried. The checkpoint advances only after
a whole batch succeeds, so a crashed worker replays at most one batch, and
replay is safe.

A run stops at the first malformed row so it can be investigated; the durable
checkpoint bounds the search to one batch. Fix or quarantine the row, then
resume.

## Stepped Execution And Durable Runtimes

`Sweep::run` loops to exhaustion, but every layer beneath it is public, so an
external orchestrator can drive the sweep one batch at a time:

- `Sweep::run_batch` processes one batch using the store's durable checkpoint.
  Suited to a cron tick, systemd timer, or queue consumer: invoke it until the
  returned `BatchOutcome::checkpoint` is `None`.
- `Sweep::process_batch` performs no checkpoint IO at all — it takes the
  cursor and returns the next one — so a durable-execution runtime (Restate,
  Temporal, a workflow engine) can journal progress itself.
- `Sweep::verify_batch` steps the read-only verification pass the same way.
  Sum per-batch reports with `SweepReport::merge`.

Batch replay is idempotent by construction: current rows are skipped without
consuming nonces, and every update compares the originally read bytes, so a
replayed rewrite loses its compare-and-swap harmlessly. That is exactly the
contract at-least-once runtimes need. One consequence: under replay, summed
per-batch tallies may overcount conflicts — treat reports as advisory and let
the verification pass be authoritative.

A Restate-shaped sketch (pseudocode; a virtual object keyed by migration
name):

```rust,ignore
async fn step(ctx: ObjectContext<'_>) -> Result<(), HandlerError> {
    let cursor: Option<i64> = ctx.get("cursor").await?;
    let outcome = ctx
        .run(|| async {
            // Open a connection, build the planner, sweep, and store, then:
            sweep.process_batch(&mut store, cursor.as_ref()).await
        })
        .await?;

    match outcome.checkpoint {
        Some(next) => {
            ctx.set("cursor", next);
            ctx.object_client::<SweepObject>(key).step().send();
        }
        None => ctx.set("done", true),
    }

    Ok(())
}
```

The same shape works with the store-owned checkpoint instead: drop the
journaled cursor and call `run_batch` in each step.

## Verification And Closing The Window

`Sweep::verify` performs a fresh, full, read-only pass and returns a
`SweepReport`. The migration window may close only when a complete pass
reports `is_terminal()` — zero plaintext, zero stale, and zero malformed rows.
If writes continue during verification, repeat until one complete pass is
clean.

After the terminal state:

1. Replace `MaybeEncrypted` reads with strict `Encrypted`/`Ciphertext` reads.
2. Disable the `migrate` feature.
3. Retire historical keys and probes following the
   [re-encryption sweep guide](reencryption-sweep.md).

[SQLite migration example]: ../examples/plaintext_migration.rs
