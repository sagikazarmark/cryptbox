---
status: accepted
---

# A binding is the seal and the record

> Amended by [ADR-0012](0012-a-record-is-a-context-layer-over-a-seal.md):
> a record field's seal is no longer marked by a hidden `Seal::RECORD`. The
> record is a context, `InRecord<K>`, that its derive seals and opens with
> `Sealed::seal_in` and `open_in`.

> Amended when implemented. The binding is private to the library: standalone
> seals bind their seal ID alone, so `Seal::Record`, `Args`, and the public
> record ID types are removed, and only `#[derive(Record)]` binds a field to its
> record ID, through hidden functions. A record ID is a `Uuid` or `[u8; 16]`, an
> `i64`, or bytes; ID newtypes can return with a later redesign. A record field's
> seal is marked by a hidden `Seal::RECORD` const, and `Sealed::seal` with one
> fails the build. Legacy-binding windows are removed: no data uses an older
> declaration, and a window can return with the redesign. Above the envelope,
> "binding" is retired: a seal builds the envelope's context from its seal ID
> and, for a record's field, the record ID, and a mismatch is a
> `ContextMismatch`. The bytes are unchanged.

A sealed value is bound to its seal ID and, when it is a field of a record, to
the record's ID. Nothing else: bound values, their ID types, and blind-index
partitions are removed, so a binding can be added back later with fresh eyes, if
it is needed at all.

```rust
#[derive(cryptbox::Record)]
pub struct Customer {
    #[cryptbox(record_id)]
    id: Uuid,
    #[cryptbox(plaintext)]
    org: OrgId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(id = "ab78afa9-7aaa-499c-8239-037b7e136130", bits = 32,
                           normalize = normalize_email, normalizer = "email/1"))]
    email: String,
}

let keys = keyrings.of(org)?;                       // the org's keys, chosen by the application
let stored: StoredCustomer = customer.seal(&keys)?;
let customer = Customer::open_expecting(stored, &keys, |row| row.org == org)?;
let hits = Customer::EMAIL_INDEX.open_matching(email, rows, &keys)?;
```

- **A seal binds its seal ID**, and nothing else, unless it is a field of a
  record. `Seal::Record` names the record ID's type, `()` for none; `Seal::Bound`
  is removed, and with it `BoundId`, `BoundList`, `BoundValues`, `TenantId`, and
  `PartId`. A standalone value's binding arguments are `()`, or `&id` for a seal
  that binds a record.
- **A record's sealed fields bind its seal and its record ID.** A field has one
  of three roles: `record_id`, `seal = "…"`, or `plaintext`. A tenant or
  workspace column is `plaintext`, authorized like any other column, before
  decrypting with `open_expecting` or after.
- **A blind index binds its seal ID alone.** `BlindIndexSpec::Partition`,
  `across(…)`, and the partition structs are removed; an index handle's `probes`
  and `open_matching` take the query and the keys.
- **Tenants are kept apart by keys.** With a keyring per tenant, another tenant's
  value fails to open with `UnknownEncryptionKey`, and separate blind-index roots
  make equal values in different tenants derive unrelated index bytes, which is
  what partitions did.
- **The wire format does not change.** A binding still encodes as the seal ID
  and a list of parts, now empty or holding the record's part under the nil part
  ID, and the fingerprint covers the same bytes. Values sealed without bound
  values keep their bytes, and a later binding can add parts without a new
  format.

## Considered Options

- **Records that carry their bound values** (ADR-0010): reduced. Authenticating a
  record's tenant column needed a bound ID type per kind of value, partitions per
  blind index, partition structs, and an `OutsidePartition` error, in a model
  whose keys already separate tenants. That machinery is removed until a concrete
  need returns it.
- **Bound standalone values only**, keeping `Seal::Bound` outside records:
  rejected. It keeps every bound-value type for the one case of a value whose
  tenant comes from elsewhere, such as verified request claims, which a keyring
  per tenant also covers.

## Consequences

- **What a shared keyring no longer catches:** a tenant column edited in place
  opens without error, and equal values in different tenants share blind-index
  bytes. A value still cannot move to another record, seal, or field. With a
  keyring per tenant, an edited tenant column selects the wrong keyring and fails
  to open.
- **The API breaks, before 1.0:** `Seal::Bound`, `BoundId` and its derive,
  `BoundList`, `BoundValues`, `TenantId`, `PartId`, `PartSpec`, `part_id!`,
  `PartType::from_part_value`, `BlindIndexSpec::Partition`, the `bound` record
  role, `across(…)`, `bound(…)` in `legacy(…)`, `Error::OutsidePartition`, and
  `migrate::probes_across` go. Legacy windows name only the old record ID type.
- **ADR-0010 is amended:** its record roles, stored forms, index handles, legacy
  windows, keys passed to each call, and single attribute namespace stand; its
  bound values do not. **ADR-0005** is amended (a binding is the seal and the
  record).
- **Glossary:** "bound value", "bound ID type", and "partition" are retired;
  "tenant" names an application concept, kept apart by keys.
