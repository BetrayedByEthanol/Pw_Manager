# Rust reference port

This independent cargo crate intentionally does not import/modify the prototype vault engine. Its library exposes `analyze`, `blast_radius`, and `kek::derive/verify` and accepts only authenticated policy snapshots. Policy JSON and KEK JSON are shared unchanged with the Python reference at `../fixtures/`.

```sh
cargo test --manifest-path rust/Cargo.toml
cargo run --manifest-path rust/Cargo.toml -- fixtures/routes.json --entry independent --state loaded
cargo run --manifest-path rust/Cargo.toml -- fixtures/routes.json --blast-radius
cargo run --manifest-path rust/Cargo.toml -- --kek-vectors fixtures/kek_vectors.json
```

Run commands from `tools/security_probes/`.

All crypto remains a *candidate interoperability probe*. No encrypted vault files are read and no authenticator is invoked. Conformance equality is tested via stable JSON properties, not ordering of arbitrary equivalent access-route witnesses.
