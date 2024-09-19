#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

NU7_VERSION_GROUP_ID = 0x124A69F8
NU7_TX_VERSION = 6
NU7_TX_VERSION_BYTES = NU7_TX_VERSION | (1 << 31)

def orchard_zsa_burn_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcBurnHash')

    if len(tx.vAssetBurnOrchardZSA) > 0:
        for desc in tx.vAssetBurnOrchardZSA:
            digest.update(bytes(desc.assetBase))
            digest.update(struct.pack('<Q', desc.valueBurn))

    return digest.digest()


def issuance_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSAIssueHash')

    if len(tx.vIssueActions) > 0:
        digest.update(issue_actions_digest(tx))
        digest.update(tx.ik)

    return digest.digest()


def issuance_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthZSAOrHash')
    if len(tx.vIssueActions) > 0:
        digest.update(tx.issueAuthSig)
    return digest.digest()


def issue_actions_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdIssuActHash')

    for action in tx.vIssueActions:
        digest.update(issue_notes_digest(action))
        digest.update(action.asset_desc)
        digest.update(struct.pack('<B', action.flagsIssuance))

    return digest.digest()


def issue_notes_digest(action):
    digest = blake2b(digest_size=32, person=b'ZTxIdIAcNoteHash')

    for note in action.vNotes:
        digest.update(bytes(note.recipient))
        digest.update(struct.pack('<Q', note.value))
        digest.update(bytes(note.assetBase))
        digest.update(bytes(note.rho))
        digest.update(note.rseed)

    return digest.digest()
