#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .transaction_v6 import TransactionV6
from .output import render_args, render_tv
from .rand import Rand
from .zip_0143 import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)

from .zip_0244 import *

def main():
    args = render_args()

    from random import Random
    rng = Random(0xB7D6_0F44)
    rand = randbytes(rng)

    consensusBranchId = 0xFFFF_FFFF # ZFUTURE

    test_vectors = []
    for _ in range(10):
        tx = TransactionV6(rand, consensusBranchId)

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

        txid = txid_digest(tx)
        auth = auth_digest(tx)

        [sighash_shielded, other_sighashes, txin] = generate_sighashes_and_txin(tx, t_inputs, rand)

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
        'zip_0233',
        (
            ('tx',                    {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('txid',                  '[u8; 32]'),
            ('auth_digest',           '[u8; 32]'),
            ('amounts',               'Vec<i64>'),
            ('zip233_amount',         'u64'),
            ('script_pubkeys',        {'rust_type': 'Vec<Vec<u8>>', 'bitcoin_flavoured': False}),
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
