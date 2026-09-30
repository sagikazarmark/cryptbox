# Restate

The `restate` feature journals sealed values safely in
[Restate](https://restate.dev) handlers. It needs `restate-sdk` 0.12, and so
Rust 1.90 or newer.

Restate journals each step of a handler, and replays the journal after a
failure or a suspension. On replay, the handler runs again, and Restate checks
that each step matches the step it recorded, byte for byte. Sealing draws a
fresh nonce, so a value sealed outside a journaled action seals to other bytes
on replay. The next `ctx.set` or call that carries it no longer matches its
journal entry, and the invocation fails with a journal mismatch.

So seal inside `ctx.run`. Restate journals the sealed bytes once, and replays
them.

## Sealing

```rust
use cryptbox::{Keys, Sealed, Tenant, restate::{self, ObjectKey}};
use restate_sdk::prelude::*;

#[derive(cryptbox::Seal)]
#[cryptbox(id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", value = String, scope = Tenant)]
struct CustomerEmail;

struct Customer {
    keys: Keys,
}

#[restate_sdk::object]
impl Customer {
    #[handler]
    async fn update_email(&self, ctx: ObjectContext<'_>, email: String) -> HandlerResult<()> {
        let tenant = ObjectKey::<Tenant>::parse(ctx.key()).map_err(restate::handler_error)?;

        let sealed = restate::seal::<CustomerEmail>(&ctx, &email, &tenant, &self.keys)
            .name("seal-email")
            .await?;
        ctx.set("email", sealed);

        Ok(())
    }

    #[handler]
    async fn email_domain(&self, ctx: ObjectContext<'_>) -> HandlerResult<String> {
        let tenant = ObjectKey::<Tenant>::parse(ctx.key()).map_err(restate::handler_error)?;

        let sealed: Sealed<CustomerEmail> = ctx
            .get("email")
            .await?
            .ok_or_else(|| TerminalError::new("no email"))?;
        let email = sealed.open(&tenant, &self.keys).map_err(restate::handler_error)?;

        Ok(email.rsplit('@').next().unwrap_or_default().to_owned())
    }
}
```

- `restate::seal` seals a value the handler already holds, such as a field of
  its input.
- `restate::seal_with` fetches a value and seals it inside the same `run`, so
  the plaintext is never a `run` result and never reaches the journal. Use it
  for a value loaded from a database or another service.
- `restate::seal_record` and `restate::seal_record_with` do the same for a
  whole `Record`. Restate journals the sealed record as JSON, so derive Serde's
  traits on it: `#[cryptbox(attr(derive(serde::Serialize, serde::Deserialize)))]`.
  Its plaintext fields, such as the record ID, are journaled as they are.

Each returns Restate's own `run` future, so it can be named and given a retry
policy.

The context, the value, the binding arguments, and the key source share one
lifetime, and move into the `run` closure. A `seal_with` fetch closure must own
what it uses: move a clone or an `Arc` of your database handle into it. Borrows
held by it would stop the handler's future from being `Send`, which Restate
requires. For the same reason, `seal` and `seal_with` take the key source
as `&dyn EncryptionKeySource`; a keyring or `Keys` converts on its own. The
record forms need both key roles, so they take any source of both.

Opening is deterministic, so it needs no `run`. Open where the plaintext is
used, and never return plaintext from a `run`, or store it with `ctx.set`.

`Sealed<F>` and `BlindIndex<S>` implement Restate's `Serialize`,
`Deserialize`, and `PayloadMetadata` as `application/octet-stream`, without a
JSON schema. They can be kept in state, passed in calls, and resolve
awakeables and promises. The codec moves bytes, and checks the structure of the
bytes it reads, as `Sealed::from_bytes` does. It never encrypts: that would
break replay.

## Errors

`restate::handler_error` maps an `Error` to a Restate `HandlerError`:

| Kind | Errors | Why |
| --- | --- | --- |
| Terminal | authentication failure, binding mismatch, codec failure, unknown key, malformed envelope, invalid binding, invalid object key | The data or the request is at fault. Retrying the same input can never succeed. |
| Retried | keys unavailable, keys not installed or not configured, invalid key configuration, randomness unavailable, internal errors | The environment is at fault. Loading keys, restoring configuration, or deploying a fix resolves it. |

The sealing functions classify their own errors this way. `restate::is_retryable`
reports the classification. A terminal error carries the error's sanitized
message, with code 400 for an invalid object key and 500 otherwise.

## Object keys

A Virtual Object keyed by a scope, such as one object per org or a blind
index's index scope, reads it back from its object key with `ObjectKey`:

```rust
let search: OrgSearch = ObjectKey::<OrgSearch>::parse(ctx.key())
    .map_err(restate::handler_error)?;
let key = ObjectKey::<OrgSearch>::encode(&search)?;
```

An object key encodes every part of its scope, separated by `:`. The `keys`
parts come first, and then the other parts, each in `PARTS` order. Key an object
by a view that holds only the parts the object is for.

| Kind | Encoding | Example |
| --- | --- | --- |
| uuid | 36 characters, lowercase and hyphenated | `01923a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b` |
| i64 | a sign and 19 zero-padded digits | `+0000000000000000042` |
| bytes | lowercase hex | `61636d65` |

Parsing accepts exactly one spelling of each value. A missing or extra part,
parts out of order, uppercase hex, a missing sign, or any other spelling fails
with `Error::InvalidObjectKey`, which is terminal. A scope parsed from an object
key needs `FromParts`; `#[derive(Scope)]` implements it.

An object key is plaintext wherever Restate shows it: in the journal, the admin
API, and logs. And a caller chooses the object key it calls. Authorize the caller
for the scope that the object key names before you bind values to it.

## What the journal exposes

Restate stores each journal entry until the invocation's journal is purged, and
state until it is cleared. Anything the handler did not seal is plaintext to
anyone who can read Restate's storage, the admin API, or its backups.

| Entry | What Restate stores | Keep it sealed |
| --- | --- | --- |
| Input | The handler's argument, as the caller sent it. | **Ingress input is plaintext**: an external caller has no keys. Callers inside the system can pass `Sealed<F>`. Where possible, have ingress carry an identifier and fetch the value with `seal_with`. |
| Run | The `run` closure's result. | Return sealed values only. `seal` and `seal_with` do. |
| State | The value of each `ctx.set`, beyond the invocation. | Store `Sealed<F>`. |
| Call | The arguments, in the caller's journal and as the callee's input. The result, in both journals. | Pass and return `Sealed<F>`. |
| Awakeable | The payload that resolves it. | Resolve with a sealed value. An external resolver needs keys to seal one. |
| Promise | The payload of a workflow's durable promise. | Resolve with a sealed value. |
| Output | The handler's result, returned to the caller and kept for idempotency and workflow retention. | Return `Sealed<F>`, or data that is not sensitive. |

Beyond the journal:

- Object keys, run names, and headers are plaintext.
- A journal mismatch reports the differing payloads in the invocation's last
  failure. Sealed values show as ciphertext. Plaintext handed to `ctx.set`
  shows as plaintext.
- Idempotency and workflow retention keep inputs and outputs after the
  invocation completes.

## Runbook: shredding an org

These are the Restate-specific steps of
[shredding a scope](shredding.md), whose prerequisites, cache and backup
guidance, and verification apply here too.

For a binding whose `org` part is its only [`keys`](shredding.md#prerequisites)
part, destroying the org's root keys makes every value sealed under them unreadable,
including those in Restate's journals and state. Restate still holds the
plaintext around them: ingress input, object keys, and anything the handlers
did not seal. And an invocation that replays after its keys are gone retries
forever, since unavailable keys are retryable. So drain Restate before you
destroy the keys.

1. **Stop new work.** Revoke the org's access, so no caller is authorized for
   its object keys.

2. **Find the org's objects.** Compute the key scope's object-key prefix:

   ```rust
   let org = KeyScope::of_keys::<OrgWorkspace>(&[PartValue::Uuid(*org_id.as_bytes())])?;
   let prefix = ObjectKey::<OrgWorkspace>::prefix(&org)?;
   ```

   Select the org's invocations for each service keyed by `OrgWorkspace`,
   through the admin API's `POST /query` or `restate sql`. The encoding never
   contains a quote or a SQL wildcard:

   ```sql
   SELECT id, target, status FROM sys_invocation
   WHERE target_service_name = 'Customer'
     AND (target_service_key = '<prefix>' OR target_service_key LIKE '<prefix>:%')
   ```

   A binding without `keys` parts has an empty prefix: every object of the
   service is in its one key scope, so select them by service alone.

   A plain Service has no object key. Find its invocations for the org another
   way, such as by an idempotency key or a header you set.

3. **Stop in-flight invocations.** Cancel each one that is not completed
   (`PATCH /invocations/{id}/cancel`), so its handlers can compensate. Kill any
   that do not finish (`PATCH /invocations/{id}/kill`).

4. **Purge completed invocations** (`PATCH /invocations/{id}/purge`). This
   removes their journals, with the plaintext inputs and outputs they hold, and
   their idempotency and workflow retention.

5. **Clear the org's state.** Clear each object's state, for example with a
   handler that calls `ctx.clear_all()`. Sealed values would become unreadable
   anyway; this removes their keys and anything that was not sealed.

6. **Destroy the org's root keys**, for both encryption and blind indexes.

7. **Verify.** The query in step 2 returns no rows. The key source reports the
   org's keys as unavailable. Restate's snapshots and backups, and your
   database's, still hold the org's sealed values until they expire; they
   stay unreadable once the keys are gone.
