# Zcash Python test vectors

Code to generate test vectors for various parts of Zcash.

The generated test vectors are checked into the repository:
- `test-vectors/json/`: JSON format.
- `test-vectors/rust/`: Rust format, suitable for copying into a Rust library or
  application to use from `#[cfg(test)]` code.
- `test-vectors/zcash/`: Bitcoin-flavoured JSON format (where 256-bit values are
  encoded as byte-reversed hex strings), for use in `zcashd` unit tests.

To generate the test vectors yourself (for example, to generate a larger set
after adjusting:

- Install [`poetry`](https://python-poetry.org/).
- `poetry install`
- `poetry run SCRIPT_NAME [-t json|rust|zcash]`
  - `SCRIPT_NAME` is one of the scripts listed in `pyproject.toml`.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
