#!/usr/bin/env bash

case "$1" in
  "rust" )
    gen_types=(rust)
    ;;
  "zcash" )
    gen_types=(zcash)
    ;;
  "json")
    gen_types=(json)
    ;;
  "all")
    gen_types=(rust zcash json)
    ;;
  *)
    echo "Unexpected generation type: $1"
    exit 1
    ;;
esac

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
        unified_full_viewing_keys
        unified_incoming_viewing_keys
        zip_0032_registered
        zip_0032_arbitrary
        zip_0143
        zip_0243
        zip_0244
        zip_0316
        zip_0320)
    ;;
  *)
    tv_scripts=($2)
    ;;
esac

for generator in "${tv_scripts[@]}"
do
  for gen_type in "${gen_types[@]}"
  do
    extension="${gen_type/rust/rs}"
    extension="${extension/zcash/json}"
    output_file="test-vectors/$gen_type/$generator.$extension"
    echo $output_file
    mkdir -p "test-vectors/$gen_type"
    poetry run $generator -t $gen_type >$output_file
  done
done
