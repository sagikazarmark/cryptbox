# Records that carry their bound values

Seal whole rows whose sealed fields are bound to the org and workspace the row
belongs to, store them in SQLite with SQLx, search an email index across an
org's workspaces, and carry a record as a JSON message.
[Examples](../README.md) · [Documentation](../../docs/README.md) · [Bindings](../../docs/bindings.md).

## Run the example

From the repository root:

```sh
cargo run --locked --example records --features derive,json,sqlx-sqlite,uuid
```

Expect `Records round trip, search, and message succeeded.` The database is in
memory and the keys are generated on every run, one set per org; for durable
keys, see [the SQLite example](../sqlite/README.md).

## What it shows

- **Bound ID types.** `OrgId` and `WorkspaceId` are the application's own ID
  newtypes. `#[derive(BoundId)]` marks the kind of value each is, once, and
  `#[sqlx(transparent)]` stores each as its UUID.
- **A record.** Every field of `Customer` has one role: the record ID, a bound
  value, a sealed field, or plaintext. The stored form, `StoredCustomer`, derives
  `sqlx::FromRow` through `#[cryptbox(stored(…))]`, and an `Option<String>` note
  is stored as `NULL` when absent.
- **Reading within an org.** `Customer::open_expecting` checks that a row belongs
  to the caller's org before decrypting it. Another org's keys fail with
  `UnknownEncryptionKey`.
- **An org-wide search.** The email index spans workspaces, `across(workspace)`,
  so a lookup supplies the org: `Customer::EMAIL_INDEX.probes` derives the probes
  to select by, and `open_matching` opens the candidates, drops false ones, and
  refuses a row of another org without decrypting it. Each hit's workspace is
  read from its row and authenticated: authorize on it.
- **A message.** `CustomerCreated`'s stored form, renamed
  `CustomerCreatedEvent`, derives Serde. JSON carries the sealed address as
  base64url text, and its `eventId` rename is forwarded with `stored(…)`.

See [bindings](../../docs/bindings.md) for where bound values come from and how
blind indexes are partitioned, and [integration design](../../docs/integration.md#records-orms-and-serde)
for other ORMs.
