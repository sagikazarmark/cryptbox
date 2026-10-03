# Records with a keyring per org

Seal whole rows bound to their record IDs, keep orgs apart with a keyring per
org, store them in SQLite with SQLx, search an email index within an org, and
carry a record as a JSON message.

```sh
cargo run --locked --example records --features derive,json,sqlx-sqlite
```

Expect `Records round trip, search, and message succeeded.` The database is in
memory and keys are generated per run.

## What it shows

- **ID newtypes.** `OrgId` and `WorkspaceId` are plaintext columns, stored as
  UUIDs with `#[sqlx(transparent)]`.
- **A record.** `Customer`'s stored form, `StoredCustomer`, derives
  `sqlx::FromRow` through `#[cryptbox(stored(…))]`; an absent `Option<String>`
  note is stored as `NULL`.
- **Reading within an org.** `Customer::open_expecting` checks the row's org
  before decrypting with that org's keys; another org's keys fail with
  `UnknownEncryptionKey`.
- **Search within an org.** `Customer::EMAIL_INDEX.probes` derives probes with
  the org's index keys, and `open_matching` opens candidates and drops false
  ones. Authorize on each hit's plaintext workspace.
- **A message.** `CustomerCreated`'s stored form derives Serde; JSON carries the
  sealed address as base64url text.

See [records and tenants](../../docs/guide.md#records-and-tenants).
