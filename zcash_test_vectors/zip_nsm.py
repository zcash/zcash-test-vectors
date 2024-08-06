#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from .transaction import (
    ZFUTURE_VERSION_GROUP_ID,
    TransactionNSM,
)
from .output import render_args, render_tv, Some
from .rand import Rand
from .zip_0143 import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)

from .zip_0244 import *

def auth_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_scripts_digest(tx))
    digest.update(sapling_auth_digest(tx))
    digest.update(orchard_auth_digest(tx))
    digest.update(burn_amount_digest(tx))

    return digest.digest()

# NSM
def burn_amount_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxBurnAmnt_Hash')

    digest.update(struct.pack('<Q', tx.burnAmount))

    return digest.digest()

def txid_digest(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest(tx))
    digest.update(orchard_digest(tx))
    digest.update(burn_amount_digest(tx))

    return digest.digest()

def signature_digest(tx, t_inputs, nHashType, txin):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, t_inputs, nHashType, txin))
    digest.update(sapling_digest(tx))
    digest.update(orchard_digest(tx))
    digest.update(burn_amount_digest(tx))

    return digest.digest()

def txin_sig_digest(tx, txin):
    digest = blake2b(digest_size=32, person=b'Zcash___TxInHash')
    if txin is not None:
        digest.update(bytes(tx.vin[txin.nIn].prevout))
        digest.update(struct.pack('<Q', txin.amount))
        digest.update(bytes(txin.scriptPubKey))
        digest.update(struct.pack('<I', tx.vin[txin.nIn].nSequence))
    return digest.digest()


def main():
    args = render_args()

    from random import Random
    rng = Random(0xB7D6_0F44)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    consensusBranchId = 0xFFFF_FFFF # ZFUTURE

    test_vectors = []
    for _ in range(10):
        tx = TransactionNSM(rand, consensusBranchId, ZFUTURE_VERSION_GROUP_ID)
        txid = txid_digest(tx)
        auth = auth_digest(tx)

        # Generate amounts and scriptCodes for each non-dummy transparent input.
        if tx.is_coinbase():
            t_inputs = []
        else:
            t_inputs = [TransparentInput(nIn, rand) for nIn in range(len(tx.vin))]

        # If there are any non-dummy transparent inputs, derive a corresponding transparent sighash.
        if len(t_inputs) > 0:
            txin = rand.a(t_inputs)
        else:
            txin = None

        sighash_shielded = signature_digest(tx, t_inputs, SIGHASH_ALL, None)
        other_sighashes = {
            nHashType: None if txin is None else signature_digest(tx, t_inputs, nHashType, txin)
            for nHashType in ([
                SIGHASH_ALL,
                SIGHASH_NONE,
                SIGHASH_SINGLE,
                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            ] if txin is None or txin.nIn < len(tx.vout) else [
                SIGHASH_ALL,
                SIGHASH_NONE,
                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            ])
        }

        test_vectors.append({
            'tx': bytes(tx),
            'txid': txid,
            'auth_digest': auth,
            'amounts': [x.amount for x in t_inputs],
            'burn_amount': tx.burnAmount,
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
        'zip_nsm',
        (
            ('tx',                    {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('txid',                  '[u8; 32]'),
            ('auth_digest',           '[u8; 32]'),
            ('amounts',               'Vec<i64>'),
            ('burn_amount',           'u64'),
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
