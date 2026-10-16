# Downstream use of generated test vectors

A short, manually maintained index of where selected generated test vectors
from this repository are consumed downstream. Each entry was checked against
the repository snapshots listed under [Checked commits](#checked-commits).

This index credits the initial downstream-use mapping collected in
[#128](https://github.com/zcash/zcash-test-vectors/issues/128). It covers
three verified examples only; it is not a complete mapping.

## f4jumble

- Generator: `zcash_test_vectors/f4jumble.py`
- Generated outputs: `test-vectors/rust/f4jumble.rs`,
  `test-vectors/rust/f4jumble_long.rs`
  (JSON equivalents under `test-vectors/json/`)
- Downstream consumer:
  [librustzcash](https://github.com/zcash/librustzcash)
  `components/f4jumble/src/test_vectors.rs` (9 of 9 vectors) and
  `components/f4jumble/src/test_vectors_long.rs` (3 of 3 vectors)
- Adaptation: the downstream crate wraps the vectors with a
  `MAX_VECTOR_LENGTH` configuration gate so `no_std` builds skip the long
  vectors. `test_vectors_long.rs` carries a stale provenance comment pointing
  at the old `zcash-hackworks` organization and a generator path that has
  since moved.

## Orchard Merkle tree

- Generator: `zcash_test_vectors/orchard/merkle_tree.py`
- Generated output: `test-vectors/rust/orchard_merkle_tree.rs` (17 vectors)
- Downstream consumer: [orchard](https://github.com/zcash/orchard)
  `src/test_vectors/merkle_path.rs` (17 of 17 vectors)
- Adaptation: downstream wraps the vectors in a
  `test_vectors() -> Vec<TestVector>` function instead of a `const`. Its
  provenance comment still points at the old `zcash-hackworks` organization
  and the generator's previous top-level path.

## Sapling note encryption

- Generator: `zcash_test_vectors/sapling/note_encryption.py`
- Generated output: `test-vectors/rust/sapling_note_encryption.rs`
  (11 vectors)
- Downstream consumer:
  [sapling-crypto](https://github.com/zcash/sapling-crypto)
  `src/test_vectors/note_encryption.rs` (11 of 11 vectors)
- Adaptation: downstream renames two fields (`p_enc` to `_p_enc`, `op` to
  `_op`) and exposes the vectors through a `make_test_vectors()` function.
  Its provenance comment points at the old `zcash-hackworks` organization
  and the generator's previous top-level path.

## Checked commits

| Repository | Commit |
| --- | --- |
| zcash/zcash-test-vectors | `78321beacb0e0477e33cd002b56585a107c2708c` |
| zcash/librustzcash | `17667fb4a33789ecb71fc8418dc320b358ce81b0` |
| zcash/orchard | `616a669df8c9a59c33d47064d3ce04b25d026b2e` |
| zcash/sapling-crypto | `88a7946b4a3066787776e11f0a502654167e022d` |

Checked on 2026-10-16. Vector counts above refer to the number of test
vectors present in both the generated file and its downstream copy at these
commits.
