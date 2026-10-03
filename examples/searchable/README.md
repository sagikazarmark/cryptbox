# Searchable SQLx storage

A sample application with atomic ciphertext/index writes, nullable reads,
verified equality lookup, and a key generation change across restarts. SQLite is
the default backend; PostgreSQL is also supported. For encryption without
search, start with [durable SQLite storage](../sqlite/README.md).

Needs Rust, a C compiler, OpenSSL, and for PostgreSQL, Docker. Run every command
from this directory:

```sh
cd examples/searchable
cargo build --locked
```

## Provision keys once

Never overwrite existing key files:

```sh
(umask 077; set -C; mkdir keys &&
  for k in encryption-1 encryption-2 index-1 index-2; do openssl rand -hex 32 > keys/$k.hex; done)
export CRYPTBOX_KEY_DIR="$PWD/keys" CRYPTBOX_GENERATION=1
unset CRYPTBOX_ENCRYPTION CRYPTBOX_INDEX
```

The loader in [main.rs](main.rs) pairs each file with a fixed demonstration
generation ID. `CRYPTBOX_GENERATION=1` makes generation 1 current and both
readable; `2` promotes both roles while keeping generation 1. To stage each role
separately, set both `CRYPTBOX_ENCRYPTION` and `CRYPTBOX_INDEX` to one of `1`,
`staged`, `2`, `2-only`, `staged-3` or `3` instead. Missing or
malformed files fail before database access; wrong material of the right length
fails decryption or silently omits search results.

## Choose a database

SQLite:

```sh
export DATABASE_URL="sqlite://$PWD/users.db?mode=rwc"
consumer() { cargo run --locked -- "$@"; }
```

PostgreSQL (loopback credentials, no TLS; repeat `pg_isready` until it accepts connections):

```sh
docker run --detach --rm --name cryptbox-searchable-postgres \
  -e POSTGRES_USER=cryptbox -e POSTGRES_PASSWORD=cryptbox \
  -e POSTGRES_DB=cryptbox -p 127.0.0.1:55432:5432 postgres:18-trixie
docker exec cryptbox-searchable-postgres pg_isready -U cryptbox -d cryptbox
export DATABASE_URL='postgres://cryptbox:cryptbox@127.0.0.1:55432/cryptbox?sslmode=disable'
consumer() { cargo run --locked --no-default-features --features postgres -- "$@"; }
```

The schemas store envelopes and index tokens in `BLOB`/`BYTEA` columns behind a
**non-unique** lookup index, with a check that pairs a `NULL` email with a `NULL`
lookup.

## Run it

```sh
consumer init
consumer put 1 ' Alice@Example.com '
consumer put-null 2
consumer get 2                         # 2: NULL
consumer put 2 before@example.com
consumer put 2 after@example.com
consumer search before@example.com     # Matches: []; rejected: 0.
consumer search AFTER@example.com      # Matches: [2]; rejected: 0.
consumer put-null 2
```

Change generation across a restart:

```sh
export CRYPTBOX_GENERATION=2
consumer get 1
consumer put 3 alice@example.com
consumer search ALICE@example.com      # Matches: [1, 3]; rejected: 0.
```

Row 1 keeps generation-1 storage; row 3 uses generation 2. Both are found
because both generations stay readable.

Reject a false candidate (disposable database only):

```sh
consumer put 4 bob@example.com
consumer demo-false-candidate 4 3      # copies row 3's index onto row 4
consumer search ' ALICE@EXAMPLE.COM '  # Matches: [1, 3]; rejected: 1.
consumer put 4 bob@example.com
```

## How it works

See `put`, `get`, and `search` in [main.rs](main.rs).

- **`put`** derives the sealed value and index from one source with
  `Sealed::prepare(…).with_index::<EmailLookup>(…)` and upserts both in one
  statement, including value-to-NULL. The automatic `Plain` column rejects
  indexed seals because it cannot write the index column.
- **`get`** decodes `Option<Sealed<UserEmail>>`, which checks structure only;
  `open` authenticates.
- **`search`** probes every readable index generation, opens each candidate, and
  keeps it only if `verify_candidate` matches. A false candidate is an ordinary
  non-match; an authentication failure fails the lookup.

`EmailLookup` trims and ASCII-lowercases, an illustrative policy rather than
email canonicalization. Printing plaintext and taking it as arguments are
demonstration conveniences.

## Optional: SQLx query macros

`query!` needs a reachable `DATABASE_URL` with the schema applied, or an offline
cache. See `macro_get` and `macro_put` in [main.rs](main.rs): reads force
`"email?: SealedEmail"`, and writes pass `sealed as _` to override PostgreSQL's
`BYTEA` inference. After `consumer init` on SQLite:

```sh
cargo run --locked --features macro-check -- macro-get 2
cargo run --locked --features macro-check -- macro-put 5 macro@example.com
consumer search MACRO@example.com      # Matches: [5]; rejected: 0.
```

For PostgreSQL use `--no-default-features --features postgres,macro-check`. For
offline builds, run `cargo sqlx prepare -- --features macro-check` and set
`SQLX_OFFLINE=true`.

## Adapting it

The packaged sweep requires non-NULL values, so a nullable column like this one
needs a custom `SweepStore`; see [maintenance sweeps](../../docs/operations.md#maintenance-sweeps).
The `legacy-migration` feature enables [migration.rs](migration.rs); see
[legacy migration](../../docs/operations.md#legacy-migration).

## Clean up

`docker stop cryptbox-searchable-postgres` removes the PostgreSQL service. For a
fresh SQLite run, remove `users.db*` while stopped. Remove `keys/` only with the
data it protects.
