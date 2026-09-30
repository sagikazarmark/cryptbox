# Runbook: shred a tenant

Crypto-shredding destroys one tenant's root keys, such as one org's, so that
every value sealed under them becomes unreadable, wherever a copy of those bytes
is. It is a procedure over your own key custody, storage inventory, and caches;
CryptBox supplies the binding that keeps a tenant's values from being moved into
another tenant's rows, and nothing else.
[Documentation](README.md) · [Bindings](bindings.md) · [Choosing keyrings](choosing-keyrings.md).

## What shredding does and does not do

| Destroying a tenant's root keys | Effect |
| --- | --- |
| Sealed values of that tenant, in live tables, replicas, exports, and backups | Unreadable, including copies you do not control |
| Blind-index columns of that tenant | No longer queryable: probes need the index root |
| Plaintext columns, object keys, row counts, sizes, and timestamps | Untouched |
| Equal values having equal index bytes | Still visible: the correlation survives the key |
| Keys already leaked, or plaintext already copied out | Unaffected |
| The bytes themselves | Still on disk until your storage and its backups expire them |

Shredding is therefore not erasure, not revocation, and not a substitute for
deleting rows. It is a way to make the rows you cannot reach — snapshots,
archives, a replica in another region — stop yielding plaintext. Rotation and
re-encryption are separate operations that do none of this; see
[key lifecycle](key-rotation.md).

## Prerequisites

Check each of these before you plan a destruction, because none of them can be
established afterwards:

1. **The tenant has root keys of its own.** What you can shred on its own is
   whatever your application keeps separate root keys for. If every org has its
   own roots, one org can be shredded; its workspaces, which share the org's
   keys, cannot be shredded on their own. Values sealed under one process-wide
   keyring are not shreddable per tenant at all.
   See [choosing keyrings](choosing-keyrings.md#write-the-custody-decision-down).
2. **Custody is per tenant, for both roles.** The tenant's encryption and
   blind-index roots exist only in its own keyring, are never shared with
   another tenant, and are destroyable independently in your secret store.
3. **Custody is tested.** A value sealed under another tenant's keyring survives
   this procedure, and nothing reports it. Pin key resolution in tests first:
   [test the choice](choosing-keyrings.md#test-the-choice).
4. **The inventory is complete.** Every store, cache, projection, queue, export,
   and backup that holds the tenant's sealed values or the plaintext around them
   is listed, with an owner. Reuse the
   [retirement inventory](key-rotation.md#inventory-before-retirement).
5. **Nothing else depends on those roots.** A shared recovery keyset, a rollback
   deployment, or a legacy migration window that still needs them blocks the
   destruction.

Per-tenant shredding rests entirely on which keyring sealed each value, which the
library does not verify at write time
([ADR-0006](adr/0006-keys-are-passed-in.md#consequences)).
Treat a tenant whose custody map is undocumented or untested as not shreddable.

## The runbook

1. **Stop new work for the tenant.** Revoke its access so no request is
   authorized for it any more, and disable the jobs, imports, and schedules that
   write on its behalf. New writes after this point would be sealed under keys
   you are about to destroy.

2. **Drain work in flight.** An operation that already holds a keyring keeps it,
   and a retry that runs after destruction fails with unavailable keys, which is
   usually a retryable error: a queue or workflow will retry it forever. Cancel
   or complete in-flight work, and let compensations run while the keys still
   exist.

3. **Clear in-memory copies.** Destroying a root in a secret store does not
   reach a process that already loaded it:

   | Where a copy lives | How to clear it |
   | --- | --- |
   | Your key resolution's snapshot, and per-tenant keyring caches | Refresh or evict the tenant's entry; a keyring clone keeps its keys alive until the last handle drops |
   | Opened plaintext held in application caches, sessions, or memoized responses | Evict by tenant, before the keys go |
   | Precomputed probes or index values | Evict: they remain valid lookup values even without the key |
   | Long-lived processes that loaded the root at startup | Drain and restart them |
   | Log lines, traces, and error payloads with plaintext | Follow your log retention; treat as a separate disposal |

   Key resolution is keyed by what the application keeps keys for, such as an
   `OrgId`, so caches and admin tooling can address one tenant by it without a
   whole binding.

4. **Account for the plaintext around the sealed values.** Shredding removes no
   plaintext. Delete or redact, per the inventory: tenant identifiers and object
   keys, unencrypted columns, search projections and analytics copies built from
   decrypted values, message payloads, and any export produced while the data was
   readable. For a Restate deployment, follow
   [shredding an org](restate.md#runbook-shredding-an-org), which drains
   invocations and purges journals and state before the keys go.

5. **Destroy both roles' roots.** Remove the tenant's encryption root and its
   blind-index root through your secret store's destruction mechanism, including
   that store's own replicas, escrow copies, and backups. A key file deleted
   from one host, or dropped from an online keyring, is custody separation, not
   destruction: the key is gone only when every copy of it is.

6. **Verify.** Confirm, and record:

   - Your key resolution reports the tenant's keys as unavailable, for both
     roles.
   - A canary read of a known row of the tenant fails, rather than returning
     plaintext.
   - A lookup in the tenant fails with unavailable keys, rather than returning an
     empty result that a working probe could still have filled.
   - Every other tenant is unaffected: a canary read and lookup of a neighbouring
     tenant still succeed.
   - The inventory's plaintext items are disposed of, and any remaining copies
     of sealed values are recorded as unreadable rather than removed.

7. **Record the evidence.** Note which key IDs were destroyed, when, who
   approved it, and which artifacts were accepted as permanently unreadable.
   Follow [evidence before eventual destruction](key-rotation.md#evidence-before-eventual-destruction).

## Backups and other copies

Backups are the reason shredding is worth doing and the reason it needs care:

- **Database backups, PITR logs, and snapshots** keep the tenant's sealed values
  until they expire. Once the roots are destroyed those values are unreadable,
  which is the intended outcome — but so is every other tenant's data in the same
  backup, if the backup's recovery keyset was shared. Keep recovery keysets per
  tenant where per-tenant shredding is a requirement.
- **Secret-store backups** can resurrect a destroyed root. A destruction is
  complete only when the key's own backups, escrow, and replicas are gone or
  expired; until then, record it as pending.
- **A restore after shredding** succeeds structurally and fails to open the
  tenant's values. Expect it: an isolated restore rehearsal run before the
  destruction is the only way to know what a later restore can still yield. See
  [restore and search in isolation](key-rotation.md#restore-and-search-in-isolation).
- **Copies held by other teams** — analytics extracts, support tooling, offline
  exports — are only reachable through the inventory. Sealed copies become
  unreadable; anything they decrypted earlier does not.

## What to read next

- [Bindings](bindings.md): what values are bound to, apart from their keys.
- [Choosing keyrings](choosing-keyrings.md): the custody map this runbook
  depends on.
- [Key lifecycle and recovery](key-rotation.md#retirement-and-recovery): online
  removal, recovery retention, and destruction evidence.
- [Restate handlers](restate.md#runbook-shredding-an-org): draining and purging
  a Restate deployment.
- [Security and threat model](security.md): what encryption protects and what it
  does not.
