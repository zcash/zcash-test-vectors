#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .transaction import IronwoodTransactionV6, MAX_MONEY
from .output import render_args, render_tv
from .transaction_hash import (
    TransparentInput,
    auth_digest_v6,
    generate_sighashes_and_txin,
    randbytes,
    signature_digest_v6,
    txid_digest_v6,
)
from .zip_0143 import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)

def main():
    args = render_args()

    from random import Random
    rng = Random(0xB7D6_0F44)
    rand = randbytes(rng)

    consensusBranchId = 0xFFFF_FFFF # ZFUTURE

    test_vectors = []
    for _ in range(10):
        # A v6 transaction always carries both an Orchard and an Ironwood bundle
        # section (each possibly empty), so build it with IronwoodTransactionV6
        # and hash it with the v6 digesters. zip233Amount is set below, which
        # both header_bytes and header_digest include via `hasattr`.
        tx = IronwoodTransactionV6(
            rand,
            consensusBranchId,
            transparent_inputs=rand.u8() % 4,
            transparent_outputs=rand.u8() % 4,
            sapling_spends=rand.u8() % 3,
            sapling_outputs=rand.u8() % 3,
            sapling_value_balance=rand.u64() % (MAX_MONEY + 1),
            orchard_actions=rand.u8() % 3,
            ironwood_actions=rand.u8() % 3,
            orchard_value_balance=rand.u64() % (MAX_MONEY + 1),
            ironwood_value_balance=rand.u64() % (MAX_MONEY + 1),
        )

        # Generate amounts and scriptCodes for each non-dummy transparent input.
        t_inputs = []
        sum_amount = 0
        in_count = len(tx.vin)
        if not tx.is_coinbase() and in_count > 0:
            t_inputs = [TransparentInput(i, rand, MAX_MONEY // (in_count-1)) for i in range(in_count-1)]
            sum_amount = sum(x.amount for x in t_inputs)
            # Ensure that at least one of the inputs can reach the full range.
            t_inputs.append(TransparentInput(in_count-1, rand, MAX_MONEY - sum_amount))
            sum_amount += t_inputs[in_count-1].amount

        tx.zip233Amount = rand.u64() % (MAX_MONEY - sum_amount + 1)
        # Make half the zip233Amounts = 0 for a more realistic distribution.
        if rand.u8() % 2 == 0:
            tx.zip233Amount = 0

        txid = txid_digest_v6(tx)
        auth = auth_digest_v6(tx)

        [sighash_shielded, other_sighashes, txin] = generate_sighashes_and_txin(
            tx, t_inputs, rand, signature_digest_v6)

        test_vectors.append({
            'tx': bytes(tx),
            'txid': txid,
            'auth_digest': auth,
            'amounts': [x.amount for x in t_inputs],
            'zip233_amount': tx.zip233Amount,
            'script_pubkeys': [x.scriptPubKey.raw() for x in t_inputs],
            'transparent_input': None if txin is None else txin.nIn,
            'sighash_shielded': sighash_shielded,
            'sighash_all': other_sighashes.get(SIGHASH_ALL),
            'sighash_none': other_sighashes.get(SIGHASH_NONE),
            'sighash_single': other_sighashes.get(SIGHASH_SINGLE),
            'sighash_all_anyone': other_sighashes.get(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            'sighash_none_anyone': other_sighashes.get(SIGHASH_NONE | SIGHASH_ANYONECANPAY),
            'sighash_single_anyone': other_sighashes.get(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
        })

    render_tv(
        args,
        'zcash_test_vectors/zip_0233',
        (
            ('tx',                    {'rust_type': '&\'static [u8]', 'bitcoin_flavoured': False}),
            ('txid',                  '[u8; 32]'),
            ('auth_digest',           '[u8; 32]'),
            ('amounts',               '&\'static [i64]'),
            ('zip233_amount',         'u64'),
            ('script_pubkeys',        {'rust_type': '&\'static [&\'static [u8]]', 'bitcoin_flavoured': False}),
            ('transparent_input',     'Option<u32>'),
            ('sighash_shielded',      '[u8; 32]'),
            ('sighash_all',           'Option<[u8; 32]>'),
            ('sighash_none',          'Option<[u8; 32]>'),
            ('sighash_single',        'Option<[u8; 32]>'),
            ('sighash_all_anyone',    'Option<[u8; 32]>'),
            ('sighash_none_anyone',   'Option<[u8; 32]>'),
            ('sighash_single_anyone', 'Option<[u8; 32]>'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
