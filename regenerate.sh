#!/usr/bin/env bash

poetry install -q

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
    sapling_generators
    sapling_key_components
    sapling_note_encryption
    sapling_signatures
    sapling_zip32
    unified_address
    unified_full_viewing_keys
    unified_incoming_viewing_keys
    zip_0143
    zip_0243
    zip_0244
    zip_0316)

formats="${*:-rust json zcash}"

for generator in "${tv_scripts[@]}"
do
    for format in $formats
    do
        filetype="${format/rust/rs}"
        filetype="${filetype/zcash/json}"
        output_file="test-vectors/$format/$generator.$filetype"
        echo $output_file
        poetry run $generator -t $format >$output_file
    done
done
