#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from .transaction import (
    LegacyTransaction,
    MAX_MONEY,
    SAPLING_TX_VERSION,
    Script,
)
from .output import render_args, render_tv, Some
from .rand import Rand

from .zip_0143 import (
    getHashJoinSplits,
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
    NOT_AN_INPUT,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)


def getHashShieldedSpends(tx):
    digest = blake2b(digest_size=32, person=b'ZcashSSpendsHash')
    for desc in tx.vShieldedSpends:
        # We don't pass in serialized form of desc as spendAuthSig is not part of the hash
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.anchor))
        digest.update(desc.nullifier)
        digest.update(bytes(desc.rk))
        digest.update(bytes(desc.proof))
    return digest.digest()

def getHashShieldedOutputs(tx):
    digest = blake2b(digest_size=32, person=b'ZcashSOutputHash')
    for desc in tx.vShieldedOutputs:
        digest.update(bytes(desc))
    return digest.digest()

def signature_hash(scriptCode, tx, nIn, nHashType, amount, consensusBranchId):
    hashPrevouts = b'\x00'*32
    hashSequence = b'\x00'*32
    hashOutputs = b'\x00'*32
    hashJoinSplits = b'\x00'*32
    hashShieldedSpends = b'\x00'*32
    hashShieldedOutputs = b'\x00'*32

    if not (nHashType & SIGHASH_ANYONECANPAY):
        hashPrevouts = getHashPrevouts(tx)

    if (not (nHashType & SIGHASH_ANYONECANPAY)) and \
        (nHashType & 0x1f) != SIGHASH_SINGLE and \
        (nHashType & 0x1f) != SIGHASH_NONE:
        hashSequence = getHashSequence(tx)

    if (nHashType & 0x1f) != SIGHASH_SINGLE and \
        (nHashType & 0x1f) != SIGHASH_NONE:
        hashOutputs = getHashOutputs(tx)
    elif (nHashType & 0x1f) == SIGHASH_SINGLE and \
        0 <= nIn and nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'ZcashOutputsHash')
        digest.update(bytes(tx.vout[nIn]))
        hashOutputs = digest.digest()

    if len(tx.vJoinSplit) > 0:
        hashJoinSplits = getHashJoinSplits(tx)

    if len(tx.vShieldedSpends) > 0:
        hashShieldedSpends = getHashShieldedSpends(tx)

    if len(tx.vShieldedOutputs) > 0:
        hashShieldedOutputs = getHashShieldedOutputs(tx)

    digest = blake2b(
        digest_size=32,
        person=b'ZcashSigHash' + struct.pack('<I', consensusBranchId),
    )

    digest.update(struct.pack('<I', tx.version_bytes()))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(hashPrevouts)
    digest.update(hashSequence)
    digest.update(hashOutputs)
    digest.update(hashJoinSplits)
    digest.update(hashShieldedSpends)
    digest.update(hashShieldedOutputs)
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))
    digest.update(struct.pack('<Q', tx.valueBalance))
    digest.update(struct.pack('<I', nHashType))

    if nIn != NOT_AN_INPUT:
        digest.update(bytes(tx.vin[nIn].prevout))
        digest.update(bytes(scriptCode))
        digest.update(struct.pack('<Q', amount))
        digest.update(struct.pack('<I', tx.vin[nIn].nSequence))

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

    consensusBranchId = 0x76b809bb # Sapling

    test_vectors = []
    for _ in range(10):
        tx = LegacyTransaction(rand, SAPLING_TX_VERSION)
        scriptCode = Script(rand)
        nIn = rand.i8() % (len(tx.vin) + 1)
        if nIn == len(tx.vin):
            nIn = NOT_AN_INPUT
        nHashType = SIGHASH_ALL if nIn == NOT_AN_INPUT else rand.a([
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ])
        amount = rand.u64() % (MAX_MONEY + 1)

        sighash = signature_hash(
            scriptCode,
            tx,
            nIn,
            nHashType,
            amount,
            consensusBranchId,
        )

        test_vectors.append({
            'tx': bytes(tx),
            'script_code': scriptCode.raw(),
            'transparent_input': nIn,
            'hash_type': nHashType,
            'amount': amount,
            'consensus_branch_id': consensusBranchId,
            'sighash': sighash,
        })

    render_tv(
        args,
        'zip_0243',
        (
            ('tx', {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('script_code', 'Vec<u8>'),
            ('transparent_input', {
                'rust_type': 'Option<u32>',
                'rust_fmt': lambda x: None if x == -1 else Some(x),
                }),
            ('hash_type', 'u32'),
            ('amount', 'i64'),
            ('consensus_branch_id', 'u32'),
            ('sighash', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
