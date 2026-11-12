#!/usr/bin/env python3
import sys;

from ..digests_v6 import sapling_digest_v6, orchard_digest_v6, orchard_auth_digest_v6, sapling_auth_digest_v6
from ..zip_0244 import TRANSPARENT_AUTH_DIGEST_PERSONALIZATION, header_digest, transparent_digest, \
    transparent_sig_digest

assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import struct

from ..zc_utils import write_compact_size

NU7_VERSION_GROUP_ID = 0x77777777
NU7_TX_VERSION = 7
NU7_TX_VERSION_BYTES = NU7_TX_VERSION | (1 << 31)

def txid_digest_zsa(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest_v6(tx))
    digest.update(orchard_digest_v6(tx))
    digest.update(ironwood_digest_zsa(tx))
    digest.update(issuance_digest(tx))

    return digest.digest()

def auth_digest_zsa(tx):
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_auth_digest_with_sighash_info(tx))
    digest.update(sapling_auth_digest_v6(tx))
    digest.update(orchard_auth_digest_v6(tx))
    digest.update(ironwood_auth_digest_zsa(tx))
    digest.update(issuance_auth_digest(tx))

    return digest.digest()


def transparent_auth_digest_with_sighash_info(tx):
    digest = blake2b(digest_size=32, person=TRANSPARENT_AUTH_DIGEST_PERSONALIZATION)
    for (sighash_info, vin) in zip(tx.vSighashInfo, tx.vin):
        digest.update(write_compact_size(len(sighash_info)))
        digest.update(bytes(sighash_info))
        digest.update(bytes(vin.scriptSig))
    return digest.digest()

# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3-ironwood_digest_zsa
def ironwood_digest_zsa(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdIronwdH_zsa')

    if len(tx.vActionGroupsIronwood) > 0:
        digest.update(ironwood_action_groups_digest_zsa(tx))
        digest.update(struct.pack('<q', tx.valueBalanceIronwood))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3a-ironwood_action_groups_digest_zsa
def ironwood_action_groups_digest_zsa(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdIrn_AGH_zsa')

    if len(tx.vActionGroupsIronwood) > 0:
        for ag in tx.vActionGroupsIronwood:
            digest.update(ironwood_actions_compact_digest_zsa(ag))
            digest.update(ironwood_actions_memos_digest_zsa(ag))
            digest.update(ironwood_actions_noncompact_digest_zsa(ag))
            digest.update(struct.pack('<B', ag.flagsIronwood))
            digest.update(struct.pack('<I', ag.nAGExpiryHeight))
            digest.update(ironwood_burn_digest(ag))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#a2-ironwood_auth_digest_zsa
def ironwood_auth_digest_zsa(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthIrnH__zsa')

    if len(tx.vActionGroupsIronwood) > 0:
        digest.update(ironwood_action_groups_auth_digest(tx))
        digest.update(write_compact_size(len(tx.bindingSigIronwoodInfo)))
        digest.update(bytes(tx.bindingSigIronwoodInfo))
        digest.update(bytes(tx.bindingSigIronwood))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#a2a-ironwood_action_groups_auth_digest
def ironwood_action_groups_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthIrnAGHash')

    for ag in tx.vActionGroupsIronwood:
        digest.update(ag.proofsIronwood)
        digest.update(ironwood_spend_auth_sigs_auth_digest(ag.vActionsIronwood))
        digest.update(bytes(ag.anchorIronwood))

    return digest.digest()

# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#a2aii-ironwood_spend_auth_sigs_auth_digest
def ironwood_spend_auth_sigs_auth_digest(actions):
    digest = blake2b(digest_size=32, person=b'ZTxAuthIrnSASH__')

    for desc in actions:
        digest.update(write_compact_size(len(desc.spendAuthSigInfo)))
        digest.update(bytes(desc.spendAuthSigInfo))
        digest.update(bytes(desc.spendAuthSig))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3ai-ironwood_actions_compact_digest_zsa
def ironwood_actions_compact_digest_zsa(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdIrn_ACH_zsa')
    for desc in ag.vActionsIronwood:
        digest.update(bytes(desc.nullifier))
        digest.update(bytes(desc.cmx))
        digest.update(bytes(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:84])

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3aii-ironwood_actions_memos_digest_zsa
def ironwood_actions_memos_digest_zsa(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdIrn_AMH_zsa')
    for desc in ag.vActionsIronwood:
        digest.update(desc.encCiphertext[84:596])

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3aiii-ironwood_actions_noncompact_digest_zsa
def ironwood_actions_noncompact_digest_zsa(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdIrn_ANH_zsa')
    for desc in ag.vActionsIronwood:
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.rk))
        digest.update(desc.encCiphertext[596:])
        digest.update(desc.outCiphertext)

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t3avi-ironwood_burn_digest
def ironwood_burn_digest(ag):
    digest = blake2b(digest_size=32, person=b'ZTxIdIrnBurnHash')

    if len(ag.vAssetBurnIronwoodZSA) > 0:
        for desc in ag.vAssetBurnIronwoodZSA:
            digest.update(bytes(desc.assetBase))
            digest.update(struct.pack('<Q', desc.valueBurn))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t4-issuance_digest
def issuance_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdSAIssueHash')

    if len(tx.vIssueActions) > 0:
        digest.update(write_compact_size(len(tx.issuer)))
        digest.update(tx.issuer)
        digest.update(issue_actions_digest(tx))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#a3-issuance_auth_digest
def issuance_auth_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthIssH__zsa')
    if len(tx.vIssueActions) > 0:
        digest.update(write_compact_size(len(tx.issueAuthSigInfo)))
        digest.update(bytes(tx.issueAuthSigInfo))
        digest.update(write_compact_size(len(tx.issueAuthSig)))
        digest.update(tx.issueAuthSig)
    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t4c-issue_actions_digest
def issue_actions_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdIssuActHash')

    for action in tx.vIssueActions:
        digest.update(action.asset_desc_hash)
        digest.update(issue_notes_digest(action))
        digest.update(struct.pack('<B', action.flagsIssuance))

    return digest.digest()


# https://github.com/QED-it/zips/blob/zsa1/zips/draft-qedit-zsa-transaction-format-and-digests.rst#t4cii-issue_notes_digest
def issue_notes_digest(action):
    digest = blake2b(digest_size=32, person=b'ZTxIdIAcNoteHash')

    for note in action.vNotes:
        digest.update(bytes(note.recipient))
        digest.update(struct.pack('<Q', note.value))
        digest.update(bytes(note.rho))
        digest.update(note.rseed)

    return digest.digest()

def signature_digest_zsa(tx, t_inputs, nHashType, txin):
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, t_inputs, nHashType, txin))
    digest.update(sapling_digest_v6(tx))
    digest.update(orchard_digest_v6(tx))
    digest.update(ironwood_digest_zsa(tx))
    digest.update(issuance_digest(tx))

    return digest.digest()

