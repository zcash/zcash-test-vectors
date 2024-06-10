#!/usr/bin/env bash

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
    orchard_zsa_asset_base
    orchard_zsa_issuance_auth_sig
    orchard_zsa_key_components
    orchard_zsa_note_encryption
    sapling_generators
    sapling_key_components
    sapling_note_encryption
    sapling_signatures
    sapling_zip32
    sapling_zip32_hard
    unified_address
    unified_full_viewing_keys
    unified_incoming_viewing_keys
    zip_0143
    zip_0243
    zip_0244
    zip_0316)

for generator in "${tv_scripts[@]}"
do
    echo "# $generator"
    poetry run $generator -t $1 >test-vectors/$1/$generator.$2
done
