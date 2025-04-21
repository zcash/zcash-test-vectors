#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

NU7_VERSION_GROUP_ID = 0x77777777
NU7_TX_VERSION = 6
NU7_TX_VERSION_BYTES = NU7_TX_VERSION | (1 << 31)


def orchard_zsa_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrchardHash')

    if len(tx.vActionGroupsOrchard) > 0:
        digest.update(orchard_zsa_action_groups_digest(tx))
        digest.update(struct.pack('<Q', tx.valueBalanceOrchard))

    return digest.digest()


def orchard_zsa_action_groups_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActGHash')

    if len(tx.vActionGroupsOrchard) > 0:
        for ag in tx.vActionGroupsOrchard:
            digest.update(orchard_zsa_actions_compact_digest(ag))
            digest.update(orchard_zsa_actions_memos_digest(ag))
            digest.update(orchard_zsa_actions_noncompact_digest(ag))
            digest.update(struct.pack('<B', ag.flagsOrchard))
            digest.update(bytes(ag.anchorOrchard))
            digest.update(struct.pack('<I', ag.nAGExpiryHeight))
            digest.update(orchard_zsa_burn_digest(ag))

    return digest.digest()


def orchard_zsa_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthOrchaHash')

    if len(tx.vActionGroupsOrchard) > 0:
        digest.update(orchard_zsa_action_groups_auth_digest(tx))
        digest.update(bytes(tx.bindingSigOrchard))

    return digest.digest()


def orchard_zsa_action_groups_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthOrcAGHash')

    if len(tx.vActionGroupsOrchard) > 0:
        for ag in tx.vActionGroupsOrchard:
            digest.update(ag.proofsOrchard)
            for desc in ag.vActionsOrchard:
                digest.update(bytes(desc.spendAuthSig))

    return digest.digest()


def orchard_zsa_actions_compact_digest(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActCHash')
    for desc in ag.vActionsOrchard:
        digest.update(bytes(desc.nullifier))
        digest.update(bytes(desc.cmx))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:84])

    return digest.digest()


def orchard_zsa_actions_memos_digest(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActMHash')
    for desc in ag.vActionsOrchard:
        digest.update(desc.encCiphertext[84:596])

    return digest.digest()


def orchard_zsa_actions_noncompact_digest(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcActNHash')
    for desc in ag.vActionsOrchard:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
        digest.update(desc.encCiphertext[596:])
        digest.update(desc.outCiphertext)

    return digest.digest()


def orchard_zsa_burn_digest(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdOrcBurnHash')

    if len(ag.vAssetBurnOrchardZSA) > 0:
        for desc in ag.vAssetBurnOrchardZSA:
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
        digest.update(action.asset_desc_hash)
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
