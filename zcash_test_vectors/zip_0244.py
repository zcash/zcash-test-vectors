#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from random import Random

from .output import render_args, render_tv
from .transaction import MAX_MONEY, TransactionV5
from .transaction_hash import (
    TransparentInput,
    auth_digest,
    generate_sighashes_and_txin,
    randbytes,
    txid_digest,
)
from .zip_0143 import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)


def main():
    args = render_args()

    rng = Random(0xabad533d)
    rand = randbytes(rng)

    consensusBranchId = 0xc2d6d0b4 # NU5

    test_vectors = []
    for _ in range(10):
        tx = TransactionV5(rand, consensusBranchId)
        txid = txid_digest(tx)
        auth = auth_digest(tx)

        # Generate amounts and scriptCodes for each non-dummy transparent input.
        if tx.is_coinbase():
            t_inputs = []
        else:
            # We don't attempt to avoid generating amounts than sum to more than MAX_MONEY.
            t_inputs = [TransparentInput(nIn, rand) for nIn in range(len(tx.vin))]

        [sighash_shielded, other_sighashes, txin] = generate_sighashes_and_txin(tx, t_inputs, rand)

        test_vectors.append({
            'tx': bytes(tx),
            'txid': txid,
            'auth_digest': auth,
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
        })

    render_tv(
        args,
        'zcash_test_vectors/zip_0244',
        (
            ('tx',                    {'rust_type': '&\'static [u8]', 'bitcoin_flavoured': False}),
            ('txid',                  '[u8; 32]'),
            ('auth_digest',           '[u8; 32]'),
            ('amounts',               '&\'static [i64]'),
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
