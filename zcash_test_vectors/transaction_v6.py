import struct

from zcash_test_vectors.bip340_reference import schnorr_sign
from zcash_test_vectors.orchard_zsa.issuance_auth_sig import encode_issue_auth_sig
from zcash_test_vectors.zip_0143 import SIGHASH_ALL
from .orchard.key_components import FullViewingKey, SpendingKey
from .orchard.pallas import Point
from .orchard_zsa.key_components import IssuanceKeys, ZSA_BIP340_SIG_SCHEME
from .orchard_zsa.digests import NU7_VERSION_GROUP_ID, NU7_TX_VERSION_BYTES
from .orchard_zsa.asset_base import zsa_value_base, asset_digest, encode_asset_id, get_random_unicode_bytes, asset_desc_digest
from .zc_utils import write_compact_size
from .transaction import (
    NOTEENCRYPTION_AUTH_BYTES, ZC_SAPLING_ENCPLAINTEXT_SIZE,
    OrchardActionBase, TransactionBase,
)
from .zip_0244 import rand_gen, populate_test_vector, generate_test_vectors, TransparentInput, \
    signature_digest

# Orchard ZSA note values
ZC_ORCHARD_ZSA_ASSET_SIZE = 32
ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + ZC_ORCHARD_ZSA_ASSET_SIZE
ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE = ZC_ORCHARD_ZSA_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES

# SighashInfo V0
SIGHASH_INFO_V0 = [0] + [] # sighashInfo = [sighashVersion] || associatedData


class OrchardZSAActionDescription(OrchardActionBase):
    def __init__(self, rand, sighash_info):
        super().__init__(ZC_ORCHARD_ZSA_ENCCIPHERTEXT_SIZE, rand)
        self.spendAuthSigInfo = sighash_info


class AssetBurnDescription(object):
    def __init__(self, rand):
        isk = IssuanceKeys(rand.b(32))
        desc_size = rand.u32() % 512 + 1
        desc_bytes = get_random_unicode_bytes(desc_size, rand)
        asset_desc_hash = asset_desc_digest(desc_bytes)
        asset_digest_bytes = asset_digest(
            encode_asset_id(isk.ik_encoding, asset_desc_hash)
        )
        self.assetBase: Point = zsa_value_base(asset_digest_bytes)
        self.valueBurn = rand.u64()

    def __bytes__(self):
        return bytes(self.assetBase) + struct.pack('<Q', self.valueBurn)


class IssueActionDescription(object):
    def __init__(self, rand):
        self.assetDescSize = rand.u32() % 512 + 1
        self.asset_desc_hash = asset_desc_digest(get_random_unicode_bytes(self.assetDescSize, rand))
        self.vNotes = []
        for _ in range(rand.u8() % 5):
            self.vNotes.append(IssueNoteDescription(rand))
        self.flagsIssuance = rand.u8() & 1  # Only one bit is reserved for the finalize flag currently

    def __bytes__(self):
        ret = b''

        ret += bytes(self.asset_desc_hash)
        ret += write_compact_size(len(self.vNotes))
        if len(self.vNotes) > 0:
            for note in self.vNotes:
                ret += bytes(note)
        ret += struct.pack('B', self.flagsIssuance)

        return ret


class IssueNoteDescription(object):
    def __init__(self, rand):
        fvk_r = FullViewingKey.from_spending_key(SpendingKey(rand.b(32)))
        self.recipient = fvk_r.default_d() + bytes(fvk_r.default_pkd())
        self.value = rand.u64()
        self.rho = Point.rand(rand).extract()
        self.rseed = rand.b(32)

    def __bytes__(self):
        ret = b''
        ret += bytes(self.recipient)
        ret += struct.pack('<Q', self.value)
        ret += bytes(self.rho)
        ret += self.rseed

        return ret


class ActionGroupDescription(object):
    def __init__(self, rand, anchor_orchard, proofs_orchard, is_coinbase, have_burn, sighash_info):
        self.vActionsOrchard = []
        # There must always be a non-zero number of Action Descriptions in an Action Group.
        for _ in range(rand.u8() % 4 + 1):
            self.vActionsOrchard.append(OrchardZSAActionDescription(rand, sighash_info))
        # Three flag bits are defined, ensure only 3 bits used (mask with 0b00000111).
        self.flagsOrchard = (rand.u8() & 7)
        # Set the enableZSAs flag to true by OR with 0b00000100
        self.flagsOrchard |= 4
        if is_coinbase:
            # set enableSpendsOrchard = 0
            self.flagsOrchard &= 2
        self.anchorOrchard = anchor_orchard
        self.proofsOrchard = proofs_orchard
        self.nAGExpiryHeight = 0

        # OrchardZSA Burn Fields
        self.vAssetBurnOrchardZSA = []
        if have_burn:
            for _ in range(rand.u8() % 5):
                self.vAssetBurnOrchardZSA.append(AssetBurnDescription(rand))


    def __bytes__(self):
        ret = b''
        ret += write_compact_size(len(self.vActionsOrchard))
        for desc in self.vActionsOrchard:
            ret += bytes(desc)  # Excludes spendAuthSig
        ret += struct.pack('B', self.flagsOrchard)
        ret += bytes(self.anchorOrchard)
        ret += struct.pack('<I', self.nAGExpiryHeight)
        ret += self.orchard_zsa_burn_field_bytes()
        ret += write_compact_size(len(self.proofsOrchard))
        ret += self.proofsOrchard
        for desc in self.vActionsOrchard:
            ret += write_compact_size(len(desc.spendAuthSigInfo))
            ret += bytes(desc.spendAuthSigInfo)
            ret += bytes(desc.spendAuthSig)

        return ret

    def orchard_zsa_burn_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.vAssetBurnOrchardZSA))
        if len(self.vAssetBurnOrchardZSA) > 0:
            for desc in self.vAssetBurnOrchardZSA:
                ret += bytes(desc)
        return ret


class TransactionV6(TransactionBase):
    def __init__(self, rand, consensus_branch_id, sighash_info, have_orchard_zsa=True, have_burn=True, have_issuance=True):

        # We cannot have burns without an OrchardZSA bundle.
        assert have_orchard_zsa or not have_burn

        # We cannot have issuance without an OrchardZSA bundle.
        assert have_orchard_zsa or not have_issuance

        # All Transparent, Sapling, and part of the Orchard Transaction Fields are initialized in the super class.
        super().__init__(rand, have_orchard_zsa)
        self.vSighashInfo = [sighash_info] * len(self.vin)
        for desc in self.vSpendsSapling:
            desc.spendAuthSigInfo = sighash_info
        if hasattr(self, "bindingSigSapling"):
            self.bindingSigSaplingInfo = sighash_info
        if hasattr(self, "bindingSigOrchard"):
            self.bindingSigOrchardInfo = sighash_info

        # Common Transaction Fields
        self.nVersionGroupId = NU7_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id
        self.zip233Amount = 0

        # OrchardZSA Transaction Fields
        self.vActionGroupsOrchard = []
        if have_orchard_zsa:
            # For NU7 we have a maximum of one Action Group.
            self.vActionGroupsOrchard.append(ActionGroupDescription(rand, self.anchorOrchard, self.proofsOrchard, self.is_coinbase(), have_burn, sighash_info))

        # OrchardZSA Issuance Fields
        self.vIssueActions = []
        self.issuer = []
        if have_issuance:
            self.isk = rand.b(32)
            self.issuer = IssuanceKeys(self.isk).ik_encoding
            for _ in range(rand.u8() % 5 + 1):
                self.vIssueActions.append(IssueActionDescription(rand))

            t_inputs = [TransparentInput(nIn, rand) for nIn in range(len(self.vin))]
            sighash = signature_digest(self, t_inputs, SIGHASH_ALL, None)

            self.issueAuthSigInfo = sighash_info
            self.issueAuthSig = encode_issue_auth_sig(ZSA_BIP340_SIG_SCHEME,
                                    schnorr_sign(sighash, self.isk, b'\0' * 32)
                                )

        if len(self.vIssueActions) == 0:
            assert len(self.issuer) == 0

    @staticmethod
    def version_bytes():
        return NU7_TX_VERSION_BYTES

    def header_bytes(self, version_bytes, version_group_id, consensus_branch_id):
        ret = b''
        ret += super().header_bytes(version_bytes, version_group_id, consensus_branch_id)
        ret += struct.pack('<Q', self.zip233Amount)
        return ret

    def issuance_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.issuer))
        if len(self.issuer) > 0:
            ret += self.issuer
        ret += write_compact_size(len(self.vIssueActions))
        if len(self.vIssueActions) > 0:
            for desc in self.vIssueActions:
                ret += bytes(desc)
            ret += write_compact_size(len(self.issueAuthSigInfo))
            ret += bytes(self.issueAuthSigInfo)
            ret += write_compact_size(len(self.issueAuthSig))
            ret += bytes(self.issueAuthSig)
        return ret

    def __bytes__(self):
        ret = b''

        # Common Transaction Fields
        ret += super().to_bytes(self.version_bytes(), self.nVersionGroupId, self.nConsensusBranchId)

        # OrchardZSA Transaction Fields
        ret += write_compact_size(len(self.vActionGroupsOrchard))
        if len(self.vActionGroupsOrchard) > 0:
            for ag in self.vActionGroupsOrchard:
                ret += bytes(ag)
            ret += struct.pack('<q', self.valueBalanceOrchard)
            ret += write_compact_size(len(self.bindingSigOrchardInfo))
            ret += bytes(self.bindingSigOrchardInfo)
            ret += bytes(self.bindingSigOrchard)

        # OrchardZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret


def main():
    consensus_branch_id = 0x77190AD8  # NU7
    rand = rand_gen()
    test_vectors = []

    # Since the burn fields are within the Orchard ZSA fields, we can't have burn without Orchard ZSA.
    # We also cannot have issuance without Orchard ZSA.
    # This gives us the following choices for [have_orchard_zsa, have_burn, have_issuance]:
    allowed_choices = [
        [False, False, False],
        [True, False, False],
        [True, False, True],
        [True, True, False],
        [True, True, True]
    ]

    for choice in allowed_choices:
        for _ in range(2):    # We generate two test vectors for each choice.
            tx = TransactionV6(rand, consensus_branch_id, SIGHASH_INFO_V0,  *choice)
            populate_test_vector(rand, test_vectors, tx)

    generate_test_vectors('orchard_zsa_digests', test_vectors)


if __name__ == '__main__':
    main()
