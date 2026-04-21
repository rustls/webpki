# Fuzz Testing

Webpki supports fuzz testing using [cargo-fuzz]. See the [cargo-fuzz setup]
instructions for requirements (requires nightly Rust).

## Fuzz Targets

- `crl` - Fuzz `BorrowedCertRevocationList::from_der()`
- `cert` - Fuzz `EndEntityCert::try_from()`
- `anchor` - Fuzz `anchor_from_trusted_cert()`

## Running Locally

```shell
$ cargo fuzz list
anchor
cert
crl

# Fuzz CRL parsing (uses tests/crls as seed corpus)
$ mkdir -p corpus/crl
$ cargo fuzz run crl corpus/crl ../tests/crls -- -max_total_time=120

# Fuzz certificate parsing (build seed corpus first)
$ mkdir -p corpus/cert seed-certs
$ find ../tests -name "*.der" ! -path "*/crls/*" ! -name "*.crl.der" -exec cp {} seed-certs/ \;
$ cargo fuzz run cert corpus/cert seed-certs -- -max_total_time=120

# Fuzz trust anchor extraction (reuses seed-certs)
$ mkdir -p corpus/anchor
$ cargo fuzz run anchor corpus/anchor seed-certs -- -max_total_time=120
```

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
[cargo-fuzz setup]: https://rust-fuzz.github.io/book/cargo-fuzz/setup.html
