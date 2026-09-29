---
status: accepted
---

# Record padding in the authenticated envelope header

> Amended when format 1 was dropped (#78). Format 1 is no longer read, so the
> last consequence below, which kept it readable under the field's current
> policy, no longer holds: parsing rejects it with `UnsupportedFormatVersion`,
> and only the authenticated flag decides unpadding. The crate is pre-1.0 and
> its wire formats are experimental, so a reader that could silently misread
> values cost more than the 0.5.0 data it served. 0.5.0 values are
> deliberately unreadable.

Ciphertext format 2 records whether the AEAD plaintext is padded, as a flag in
the envelope header. The header is already authenticated (the AAD covers
`envelope[0..46]` today), so the flag cannot be altered. Readers remove padding
only when the flag is set, which makes padding a writer-side policy: a field can
enable or disable padding at any time, old values stay readable, and a
re-encryption sweep upgrades them.

Format 1 left padding out of the envelope, which made enabling padding a
persistent-schema migration. That required two field markers sharing one ID,
plus `retag`/`cast` helpers. It could also mis-decode silently: padded data read
unpadded returns trailing `80 00…` (accepted by `Raw` and `Postcard`), and
unpadded data ending in `80`/`80 00` read as padded loses those bytes. The wire
format is marked experimental and the crate is pre-1.0, so this is the cheapest
point to change it.

## Considered Options

- **Keep format 1** (padding as persistent schema): rejected for the reasons above.
- **Always pad** (`NoPadding` appends only the `80` marker): uniform removal
  without a header change, but it costs a byte on every value and is still a
  breaking format change.

## Consequences

- `Field::PADDING` describes how new values are written; it is no longer
  persistent schema.
- Two markers sharing a field ID, and `retag`/`cast`, leave the API.
- Format 1 stays readable, interpreted with the field's current padding policy
  as it was written. Re-encryption reports and rewrites it as format 2, so a
  sweep retires it. Until then, changing a field's padding policy can still
  misread unswept format 1 values; sweep first.
