#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <rust|json|zcash|all> <all|generator_name>"
  exit 1
fi

case "$2" in
  "all" )
    tv_scripts=(
        bip_0032
        f4jumble
        f4jumble_long
        orchard_empty_roots
        orchard_generators
        orchard_group_hash
        orchard_key_components
        orchard_map_to_curve
        orchard_merkle_tree
        orchard_note_encryption
        orchard_poseidon
        orchard_poseidon_hash
        orchard_sinsemilla
        orchard_zip32
        sapling_generators
        sapling_key_components
        sapling_note_encryption
        sapling_signatures
        sapling_zip32
        sapling_zip32_hard
        unified_address
        unified_address_r2
        unified_full_viewing_keys
        unified_incoming_viewing_keys
        unified_viewing_keys_r2
        zip_0032_registered
        zip_0032_arbitrary
        zip_0143
        zip_0233
        zip_0243
        zip_0244
        zip_0316
        zip_0320)
    ;;
  *)
    tv_scripts=($2)
    ;;
esac

case "$1" in
  "all" )
    echo "Generating all test vector formats..."
    for generator in "${tv_scripts[@]}"
    do
        echo "# $generator"
        uv run $generator -o test-vectors -n "$generator"
    done
    echo "Finished all formats."
    ;;
  "rust" | "json" | "zcash" )
    gen_type="$1"
    case "$gen_type" in
      "rust" )
        extension="rs"
        ;;
      * )
        extension="json"
        ;;
    esac

    echo "Generating $gen_type test vectors..."
    for generator in "${tv_scripts[@]}"
    do
        echo "# $generator"
        uv run $generator -t $gen_type >test-vectors/$gen_type/$generator.$extension
    done
    echo "Finished $gen_type."
    ;;
  *)
    echo "Unexpected generation type: $1"
    exit 1
    ;;
esac
