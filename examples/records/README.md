# Records bound to their record IDs, with a keyring per org

Seal whole rows whose sealed fields are bound to their seal and record ID, keep
orgs apart with a keyring per org, store the rows in SQLite with SQLx, search an
email index across an org's workspaces, and carry a record as a JSON message.
[Examples](../README.md) · [Documentation](../../docs/README.md) · [Records](../../docs/records.md).

## Run the example

From the repository root:

```sh
cargo run --locked --example records --features derive,json,sqlx-sqlite,uuid
```

Expect `Records round trip, search, and message succeeded.` The database is in
memory and the keys are generated on every run, one set per org; for durable
keys, see [the SQLite example](../sqlite/README.md).

## What it shows

- **ID newtypes.** `OrgId` and `WorkspaceId` are the application's own ID
  newtypes, stored as plaintext columns; `#[sqlx(transparent)]` stores each as
  its UUID.
- **A record.** Every field of `Customer` has one role: the record ID, a sealed
  field, or plaintext. The stored form, `StoredCustomer`, derives
  `sqlx::FromRow` through `#[cryptbox(stored(…))]`, and an `Option<String>` note
  is stored as `NULL` when absent.
- **Reading within an org.** `Customer::open_expecting` checks that a row belongs
  to the caller's org before decrypting it, and it is opened with that org's
  keys: another org's keys fail with `UnknownEncryptionKey`.
- **A search within an org.** `Customer::EMAIL_INDEX.probes` derives the probes
  with the org's index keys, the query selects the org's rows, and
  `open_matching` opens the candidates and drops false ones. Each hit's workspace
  is a plaintext column: authorize on it.
- **A message.** `CustomerCreated`'s stored form, renamed
  `CustomerCreatedEvent`, derives Serde. JSON carries the sealed address as
  base64url text, and its `eventId` rename is forwarded with `stored(…)`.

See [records](../../docs/records.md) for what values are bound to and how
tenants are kept apart, and
[integration design](../../docs/integration.md#records-orms-and-serde) for other
ORMs.
