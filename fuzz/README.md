# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the stored
formats, which a reader parses from bytes the [threat model](../docs/security.md)
treats as adversary-controlled. The [wire format](../docs/wire-format.md)
defines both.

| Target | What it checks |
| --- | --- |
| `envelope_parse` | Arbitrary bytes parse only into the documented structural errors, agree with the envelope layout, and never open. |
| `envelope_round_trip` | Arbitrary plaintext, sealed standalone or as a record's field, opens; a flipped, inserted, or removed byte, or a truncation, never opens and fails with a structural or authentication error. |
| `blind_index_parse` | Arbitrary bytes parse only as canonical blind indexes, and otherwise report `InvalidBlindIndex`. |
| `blind_index_round_trip` | A derived index re-parses, is a probe, and is consistent with its value; a mutated one is rejected, or parses as canonical bytes that are not consistent with it. |

The keys are fixed, so a crash reproduces from its input alone.

## Running

The targets need a nightly toolchain and cargo-fuzz 0.13.2. From the repository
root:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz run envelope_parse -- -max_total_time=60
```

`cargo +nightly fuzz list` lists the targets. A crash is saved under
`fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

CI fuzzes each target for a minute on every pull request. The crate is its own
workspace, outside the library's, and is not published.
