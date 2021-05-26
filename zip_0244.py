#!/usr/bin/env python3
from pyblake2 import blake2b
import struct

from transaction import (
    MAX_MONEY,
    NU5_TX_VERSION,
    Script,
    TransactionV5,
)
from tv_output import render_args, render_tv, Some
from tv_rand import Rand
from zip_0143 import (
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)


# Transparent

def transparent_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    if len(tx.vin) + len(tx.vout) > 0:
        digest.update(getHashPrevouts(tx, b'ZTxIdPrevoutHash'))
        digest.update(getHashSequence(tx, b'ZTxIdSequencHash'))
        digest.update(getHashOutputs(tx, b'ZTxIdOutputsHash'))

    return digest.digest()

# Sapling

def sapling_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSaplingHash')

    if len(tx.vSpendsSapling) + len(tx.vOutputsSapling) > 0:
        digest.update(sapling_spends_digest(tx))
        digest.update(sapling_outputs_digest(tx))
        digest.update(struct.pack('<Q', tx.valueBalanceSapling))

    return digest.digest()

# - Spends

def sapling_spends_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendsHash')

    if len(tx.vSpendsSapling) > 0:
        digest.update(sapling_spends_compact_digest(tx))
        digest.update(sapling_spends_noncompact_digest(tx))

    return digest.digest()

def sapling_spends_compact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendCHash')
    for desc in tx.vSpendsSapling:
        digest.update(desc.nullifier)
    return digest.digest()

def sapling_spends_noncompact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendNHash')
    for desc in tx.vSpendsSapling:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.anchor))
        digest.update(bytes(desc.rk))
    return digest.digest()

# - Outputs

def sapling_outputs_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutputHash')

    if len(tx.vOutputsSapling) > 0:
        digest.update(sapling_outputs_compact_digest(tx))
        digest.update(sapling_outputs_memos_digest(tx))
        digest.update(sapling_outputs_noncompact_digest(tx))

    return digest.digest()

def sapling_outputs_compact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutC__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(bytes(desc.cmu))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def sapling_outputs_memos_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutM__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def sapling_outputs_noncompact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutN__Hash')
    for desc in tx.vOutputsSapling:
        digest.update(bytes(desc.cv))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCipherText)
    return digest.digest()

# Orchard

def orchard_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrchardHash')

    if len(tx.vActionsOrchard) > 0:
        digest.update(orchard_actions_compact_digest(tx))
        digest.update(orchard_actions_memos_digest(tx))
        digest.update(orchard_actions_noncompact_digest(tx))
        digest.update(struct.pack('<B', tx.flagsOrchard))
        digest.update(struct.pack('<Q', tx.valueBalanceOrchard))
        digest.update(bytes(tx.anchorOrchard))

    return digest.digest()

# - Actions

def orchard_actions_compact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActCHash')
    for desc in tx.vActionsOrchard:
        digest.update(bytes(desc.nullifier))
        digest.update(bytes(desc.cmx))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def orchard_actions_memos_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActMHash')
    for desc in tx.vActionsOrchard:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def orchard_actions_noncompact_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActNHash')
    for desc in tx.vActionsOrchard:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()

# Transaction

def header_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdHeadersHash')

    digest.update(struct.pack('<I', tx.header()))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(struct.pack('<I', tx.nConsensusBranchId))
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))

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

    return digest.digest()

# Signatures

class TransparentInput(object):
    def __init__(self, tx, rand):
        self.scriptCode = Script(rand)
        self.nIn = rand.u8() % len(tx.vin)
        self.amount = rand.u64() % (MAX_MONEY + 1)

def signature_digest(tx, nHashType, txin):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, nHashType, txin))
    digest.update(sapling_digest(tx))
    digest.update(orchard_digest(tx))

    return digest.digest()

def transparent_sig_digest(tx, nHashType, txin):
    # Sapling Spend or Orchard Action
    if txin is None:
        return transparent_digest(tx)

    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    digest.update(prevouts_sig_digest(tx, nHashType))
    digest.update(sequence_sig_digest(tx, nHashType))
    digest.update(outputs_sig_digest(tx, nHashType, txin))
    digest.update(txin_sig_digest(tx, txin))

    return digest.digest()

def prevouts_sig_digest(tx, nHashType):
    # If the SIGHASH_ANYONECANPAY flag is not set:
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashPrevouts(tx, b'ZTxIdPrevoutHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdPrevoutHash').digest()

def sequence_sig_digest(tx, nHashType):
    # if the SIGHASH_ANYONECANPAY flag is not set, and the sighash type is neither
    # SIGHASH_SINGLE nor SIGHASH_NONE:
    if (
        (not (nHashType & SIGHASH_ANYONECANPAY)) and \
        (nHashType & 0x1f) != SIGHASH_SINGLE and \
        (nHashType & 0x1f) != SIGHASH_NONE
    ):
        return getHashSequence(tx, b'ZTxIdSequencHash')
    else:
        return blake2b(digest_size=32, person=b'ZTxIdSequencHash').digest()

def outputs_sig_digest(tx, nHashType, txin):
    # If the sighash type is neither SIGHASH_SINGLE nor SIGHASH_NONE:
    if (nHashType & 0x1f) != SIGHASH_SINGLE and (nHashType & 0x1f) != SIGHASH_NONE:
        return getHashOutputs(tx, b'ZTxIdOutputsHash')

    # If the sighash type is SIGHASH_SINGLE and the signature hash is being computed for
    # the transparent input at a particular index, and a transparent output appears in the
    # transaction at that index:
    elif (nHashType & 0x1f) == SIGHASH_SINGLE and 0 <= txin.nIn and txin.nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'ZTxIdOutputsHash')
        digest.update(bytes(tx.vout[txin.nIn]))
        return digest.digest()

    else:
        return blake2b(digest_size=32, person=b'ZTxIdOutputsHash').digest()

def txin_sig_digest(tx, txin):
    digest = blake2b(digest_size=32, person=b'Zcash___TxInHash')
    digest.update(bytes(tx.vin[txin.nIn].prevout))
    digest.update(bytes(txin.scriptCode))
    digest.update(struct.pack('<Q', txin.amount))
    digest.update(struct.pack('<I', tx.vin[txin.nIn].nSequence))
    return digest.digest()


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    consensusBranchId = 0xF919A198 # NU5

    test_vectors = []
    for _ in range(10):
        tx = TransactionV5(rand, consensusBranchId)
        txid = txid_digest(tx)

        # If there are any transparent inputs, derive a corresponding transparent sighash.
        if len(tx.vin) > 0:
            txin = TransparentInput(tx, rand)
        else:
            txin = None

        sighash_all = signature_digest(tx, SIGHASH_ALL, txin)
        other_sighashes = None if txin is None else [
            signature_digest(tx, nHashType, txin)
            for nHashType in [
                SIGHASH_NONE,
                SIGHASH_SINGLE,
                SIGHASH_ALL | SIGHASH_ANYONECANPAY,
                SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            ]
        ]

        test_vectors.append({
            'tx': bytes(tx),
            'txid': txid,
            'transparent_input': None if txin is None else txin.nIn,
            'script_code': None if txin is None else txin.scriptCode.raw(),
            'amount': None if txin is None else txin.amount,
            'sighash_all': sighash_all,
            'sighash_none': None if txin is None else other_sighashes[0],
            'sighash_single': None if txin is None else other_sighashes[1],
            'sighash_all_anyone': None if txin is None else other_sighashes[2],
            'sighash_none_anyone': None if txin is None else other_sighashes[3],
            'sighash_single_anyone': None if txin is None else other_sighashes[4],
        })

    render_tv(
        args,
        'zip_0244',
        (
            ('tx', {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('txid', '[u8; 32]'),
            ('transparent_input', {
                'rust_type': 'Option<u32>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('script_code', {
                'rust_type': 'Option<Vec<u8>>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('amount', {
                'rust_type': 'Option<i64>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('sighash_all', '[u8; 32]'),
            ('sighash_none', {
                'rust_type': 'Option<[u8; 32]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('sighash_single', {
                'rust_type': 'Option<[u8; 32]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('sighash_all_anyone', {
                'rust_type': 'Option<[u8; 32]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('sighash_none_anyone', {
                'rust_type': 'Option<[u8; 32]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
            ('sighash_single_anyone', {
                'rust_type': 'Option<[u8; 32]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
                }),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
