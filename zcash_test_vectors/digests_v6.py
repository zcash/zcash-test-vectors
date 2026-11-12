#!/usr/bin/env python3
import sys;

from .zip_0244 import sapling_outputs_digest, sapling_spends_compact_digest, orchard_actions_compact_digest, \
    orchard_actions_memos_digest, orchard_actions_noncompact_digest

assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from .zc_utils import write_compact_size


def sapling_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSaplingHash')

    if len(tx.vSpendsSapling) + len(tx.vOutputsSapling) > 0:
        digest.update(sapling_spends_digest_v6(tx))
        digest.update(sapling_outputs_digest(tx))
        digest.update(struct.pack('<Q', tx.valueBalanceSapling))

    return digest.digest()

def sapling_spends_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendsHash')

    if len(tx.vSpendsSapling) > 0:
        digest.update(sapling_spends_compact_digest(tx))
        digest.update(sapling_spends_noncompact_digest_v6(tx))

    return digest.digest()

def sapling_spends_noncompact_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendNH_v6')
    for desc in tx.vSpendsSapling:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
    return digest.digest()

def sapling_auth_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthSapliH_v6')

    if len(tx.vSpendsSapling) + len(tx.vOutputsSapling) > 0:
        for desc in tx.vSpendsSapling:
            digest.update(bytes(desc.proof))
        for desc in tx.vSpendsSapling:
            digest.update(write_compact_size(len(desc.spendAuthSigInfo)))
            digest.update(bytes(desc.spendAuthSigInfo))
            digest.update(bytes(desc.spendAuthSig))
        for desc in tx.vOutputsSapling:
            digest.update(bytes(desc.proof))
        digest.update(write_compact_size(len(tx.bindingSigSaplingInfo)))
        digest.update(bytes(tx.bindingSigSaplingInfo))
        digest.update(bytes(tx.bindingSigSapling))
        if len(tx.vSpendsSapling) > 0:
            digest.update(bytes(tx.anchorSapling))

    return digest.digest()

def orchard_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrchardH_v6')

    if len(tx.vActionsOrchard) > 0:
        digest.update(orchard_actions_compact_digest(tx))
        digest.update(orchard_actions_memos_digest(tx))
        digest.update(orchard_actions_noncompact_digest(tx))
        digest.update(struct.pack('<B', tx.flagsOrchard))
        digest.update(struct.pack('<q', tx.valueBalanceOrchard))

    return digest.digest()

def orchard_auth_digest_v6(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthOrchaH_v6')

    if len(tx.vActionsOrchard) > 0:
        digest.update(tx.proofsOrchard)
        for desc in tx.vActionsOrchard:
            digest.update(write_compact_size(len(desc.spendAuthSigInfo)))
            digest.update(bytes(desc.spendAuthSigInfo))
            digest.update(bytes(desc.spendAuthSig))

        digest.update(write_compact_size(len(tx.bindingSigOrchardInfo)))
        digest.update(bytes(tx.bindingSigOrchardInfo))
        digest.update(bytes(tx.bindingSigOrchard))
        digest.update(bytes(tx.anchorOrchard))

    return digest.digest()

