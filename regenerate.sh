#!/usr/bin/env bash

tv_scripts=(
    f4jumble
    orchard_generators
    orchard_group_hash
    orchard_key_components
    orchard_merkle_tree
    orchard_note_encryption
    orchard_poseidon
    orchard_sinsemilla
    sapling_generators
    sapling_key_components
    sapling_note_encryption
    sapling_signatures
    sapling_zip32
    zip_0143
    zip_0243
    zip_0244
    zip_0316)

tv_external_scripts=(
    f4jumble_long
    orchard_empty_roots
    orchard_map_to_curve
    orchard_poseidon_hash
    unified_address
    unified_full_viewing_keys)

for generator in "${tv_scripts[@]}"
do
    echo "# $generator"
    poetry run $generator -t $1 >test-vectors/$1/$generator.$2
done

for generator in "${tv_external_scripts[@]}"
do
    echo "# $generator"
    poetry run python ./$generator.py -t $1 >test-vectors/$1/$generator.$2
done
