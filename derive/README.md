# cryptbox-derive

Derive macros for [CryptBox](https://crates.io/crates/cryptbox):
`#[derive(Seal)]`, `#[derive(BlindIndexSpec)]`, and `#[derive(Record)]`.

Do not depend on this crate directly. Enable `cryptbox`'s `derive` feature and
use the macros through `cryptbox`:

```toml
[dependencies]
cryptbox = { version = "0.6", features = ["derive"] }
```

Each derive expands to the trait impls you would write by hand; a record also
gets its stored form, a seal per sealed field, and an index handle per blind
index. IDs, padding, index precision, and normalizer names are checked when the
macro expands. See the [`cryptbox` README](https://github.com/sagikazarmark/cryptbox#quick-start)
and the [API docs](https://docs.rs/cryptbox).

This crate is versioned in lockstep with `cryptbox`: each `cryptbox` release
requires exactly its own `cryptbox-derive` version.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
