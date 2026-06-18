#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from random import Random

from .orchard.pallas import Fp as PallasBase
from .output import render_args, render_tv
from .transaction import IronwoodTransactionV6
from .transaction_hash import (
    TransparentInput,
    auth_digest_v6,
    generate_sighashes_and_txin,
    ironwood_auth_digest,
    ironwood_digest,
    orchard_v6_auth_digest,
    orchard_v6_digest,
    randbytes,
    sapling_auth_digest_v6,
    sapling_digest_v6,
    signature_digest_v6,
    txid_digest_v6,
)
from .utils import leos2ip
from .sapling.jubjub import Fq
from .zip_0143 import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)


IRONWOOD_EXPERIMENTAL_BRANCH_ID = 0xFFFFFFFF


def new_tx(rand, **kwargs):
    return IronwoodTransactionV6(rand, IRONWOOD_EXPERIMENTAL_BRANCH_ID, **kwargs)


def mutate_sapling_anchor(tx, rand):
    tx.anchorSapling = Fq(leos2ip(rand.b(32)))


def mutate_orchard_anchor(tx, rand):
    tx.anchorOrchard = PallasBase(leos2ip(rand.b(32)))


def mutate_ironwood_anchor(tx, rand):
    tx.anchorIronwood = PallasBase(leos2ip(rand.b(32)))


def mutate_sapling_nullifier(tx, rand):
    tx.vSpendsSapling[0].nullifier = rand.b(32)


def mutate_orchard_nullifier(tx, rand):
    tx.vActionsOrchard[0].nullifier = PallasBase(leos2ip(rand.b(32)))


def mutate_ironwood_nullifier(tx, rand):
    tx.vActionsIronwood[0].nullifier = PallasBase(leos2ip(rand.b(32)))


def mutate_ironwood_flags(tx, rand):
    tx.flagsIronwood ^= 0b100


def transparent_inputs(tx, rand):
    if tx.is_coinbase():
        return []
    return [TransparentInput(nIn, rand) for nIn in range(len(tx.vin))]


def test_vector(scenario, tx, rand):
    t_inputs = transparent_inputs(tx, rand)
    [sighash_shielded, other_sighashes, txin] = generate_sighashes_and_txin(
        tx,
        t_inputs,
        rand,
        signature_digest_v6,
    )

    return {
        'scenario': scenario,
        'tx': bytes(tx),
        'txid': txid_digest_v6(tx),
        'auth_digest': auth_digest_v6(tx),
        'sapling_digest': sapling_digest_v6(tx),
        'sapling_auth_digest': sapling_auth_digest_v6(tx),
        'orchard_digest': orchard_v6_digest(tx),
        'orchard_auth_digest': orchard_v6_auth_digest(tx),
        'ironwood_digest': ironwood_digest(tx),
        'ironwood_auth_digest': ironwood_auth_digest(tx),
        'amounts': [x.amount for x in t_inputs],
        'script_pubkeys': [x.scriptPubKey.raw() for x in t_inputs],
        'transparent_input': None if txin is None else txin.nIn,
        'sighash_shielded': sighash_shielded,
        'sighash_all': other_sighashes.get(SIGHASH_ALL),
        'sighash_none': other_sighashes.get(SIGHASH_NONE),
        'sighash_single': other_sighashes.get(SIGHASH_SINGLE),
        'sighash_all_anyone': other_sighashes.get(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
        'sighash_none_anyone': other_sighashes.get(SIGHASH_NONE | SIGHASH_ANYONECANPAY),
        'sighash_single_anyone': other_sighashes.get(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
    }


def append_anchor_pair(test_vectors, rand, name, tx, mutate_anchor, digest_name, auth_digest_name):
    anchor_a = test_vector('%s_anchor_a' % name, tx, rand)
    mutate_anchor(tx, rand)
    anchor_b = test_vector('%s_anchor_b' % name, tx, rand)

    assert anchor_a['tx'] != anchor_b['tx']
    assert anchor_a['txid'] == anchor_b['txid']
    assert anchor_a['sighash_shielded'] == anchor_b['sighash_shielded']
    assert anchor_a['auth_digest'] != anchor_b['auth_digest']
    assert anchor_a[digest_name] == anchor_b[digest_name]
    assert anchor_a[auth_digest_name] != anchor_b[auth_digest_name]

    test_vectors.append(anchor_a)
    test_vectors.append(anchor_b)


def append_effect_pair(test_vectors, rand, name, tx, mutate_effect, digest_name, auth_digest_name):
    effect_a = test_vector('%s_effect_a' % name, tx, rand)
    mutate_effect(tx, rand)
    effect_b = test_vector('%s_effect_b' % name, tx, rand)

    assert effect_a['tx'] != effect_b['tx']
    assert effect_a['txid'] != effect_b['txid']
    assert effect_a['sighash_shielded'] != effect_b['sighash_shielded']
    assert effect_a['auth_digest'] == effect_b['auth_digest']
    assert effect_a[digest_name] != effect_b[digest_name]
    assert effect_a[auth_digest_name] == effect_b[auth_digest_name]

    test_vectors.append(effect_a)
    test_vectors.append(effect_b)


def main():
    args = render_args()

    rng = Random(0x1A0E6D06)
    rand = randbytes(rng)

    test_vectors = []

    test_vectors.append(test_vector('empty_orchard_and_ironwood', new_tx(rand), rand))
    test_vectors.append(test_vector(
        'sapling_negative_value_balance',
        new_tx(rand, sapling_outputs=1, sapling_value_balance=-1),
        rand,
    ))

    append_anchor_pair(
        test_vectors,
        rand,
        'sapling',
        new_tx(rand, sapling_spends=1, sapling_value_balance=1000),
        mutate_sapling_anchor,
        'sapling_digest',
        'sapling_auth_digest',
    )

    append_anchor_pair(
        test_vectors,
        rand,
        'orchard',
        new_tx(rand, orchard_actions=1, orchard_flags=0b011, orchard_value_balance=1000),
        mutate_orchard_anchor,
        'orchard_digest',
        'orchard_auth_digest',
    )

    append_anchor_pair(
        test_vectors,
        rand,
        'ironwood',
        new_tx(rand, ironwood_actions=1, ironwood_flags=0b111, ironwood_value_balance=1000),
        mutate_ironwood_anchor,
        'ironwood_digest',
        'ironwood_auth_digest',
    )

    test_vectors.append(test_vector(
        'orchard_and_ironwood',
        new_tx(
            rand,
            orchard_actions=1,
            ironwood_actions=1,
            orchard_flags=0b011,
            ironwood_flags=0b111,
            orchard_value_balance=7,
            ironwood_value_balance=-7,
        ),
        rand,
    ))

    append_effect_pair(
        test_vectors,
        rand,
        'sapling_nullifier',
        new_tx(rand, sapling_spends=1, sapling_value_balance=42),
        mutate_sapling_nullifier,
        'sapling_digest',
        'sapling_auth_digest',
    )

    append_effect_pair(
        test_vectors,
        rand,
        'orchard_nullifier',
        new_tx(rand, orchard_actions=1, orchard_flags=0b011, orchard_value_balance=42),
        mutate_orchard_nullifier,
        'orchard_digest',
        'orchard_auth_digest',
    )

    append_effect_pair(
        test_vectors,
        rand,
        'ironwood_nullifier',
        new_tx(rand, ironwood_actions=1, ironwood_flags=0b111, ironwood_value_balance=-42),
        mutate_ironwood_nullifier,
        'ironwood_digest',
        'ironwood_auth_digest',
    )

    append_effect_pair(
        test_vectors,
        rand,
        'ironwood_flags',
        new_tx(rand, ironwood_actions=1, ironwood_flags=0b011, ironwood_value_balance=-1),
        mutate_ironwood_flags,
        'ironwood_digest',
        'ironwood_auth_digest',
    )

    test_vectors.append(test_vector(
        'transparent_sighashes',
        new_tx(
            rand,
            transparent_inputs=2,
            transparent_outputs=2,
            ironwood_actions=1,
            ironwood_flags=0b111,
            ironwood_value_balance=1,
        ),
        rand,
    ))

    render_tv(
        args,
        'zcash_test_vectors/ironwood_v6_tx_hash',
        (
            ('scenario',               '&\'static str'),
            ('tx',                     {'rust_type': '&\'static [u8]', 'bitcoin_flavoured': False}),
            ('txid',                   '[u8; 32]'),
            ('auth_digest',            '[u8; 32]'),
            ('sapling_digest',         '[u8; 32]'),
            ('sapling_auth_digest',    '[u8; 32]'),
            ('orchard_digest',         '[u8; 32]'),
            ('orchard_auth_digest',    '[u8; 32]'),
            ('ironwood_digest',        '[u8; 32]'),
            ('ironwood_auth_digest',   '[u8; 32]'),
            ('amounts',                '&\'static [i64]'),
            ('script_pubkeys',         {'rust_type': '&\'static [&\'static [u8]]', 'bitcoin_flavoured': False}),
            ('transparent_input',      'Option<u32>'),
            ('sighash_shielded',       '[u8; 32]'),
            ('sighash_all',            'Option<[u8; 32]>'),
            ('sighash_none',           'Option<[u8; 32]>'),
            ('sighash_single',         'Option<[u8; 32]>'),
            ('sighash_all_anyone',     'Option<[u8; 32]>'),
            ('sighash_none_anyone',    'Option<[u8; 32]>'),
            ('sighash_single_anyone',  'Option<[u8; 32]>'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
