import struct

from zcash_test_vectors.bip340_reference import schnorr_sign
from zcash_test_vectors.orchard_zsa.issuance_auth_sig import encode_issue_auth_sig
from zcash_test_vectors.zip_0143 import SIGHASH_ALL
from .orchard.key_components import FullViewingKey, SpendingKey
from .orchard.pallas import Point
from .orchard_zsa.key_components import IssuanceKeys, ZSA_BIP340_SIG_SCHEME
from .orchard_zsa.digests import NU7_VERSION_GROUP_ID, NU7_TX_VERSION_BYTES, signature_digest_zsa
from .orchard_zsa.asset_base import zsa_value_base, asset_digest, encode_asset_id, get_random_unicode_bytes, asset_desc_digest
from .zc_utils import write_compact_size
from .transaction import (
    NOTEENCRYPTION_AUTH_BYTES, ZC_SAPLING_ENCPLAINTEXT_SIZE,
    OrchardActionBase, TransactionBase,
)
from .zip_0244 import rand_gen, populate_test_vector, generate_test_vectors, TransparentInput

# Orchard ZSA note values
ZC_IRONWOOD_ZSA_ASSET_SIZE = 32
ZC_IRONWOOD_ZSA_ENCPLAINTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + ZC_IRONWOOD_ZSA_ASSET_SIZE
ZC_IRONWOOD_ZSA_ENCCIPHERTEXT_SIZE = ZC_IRONWOOD_ZSA_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES

# SighashInfo V0
SIGHASH_INFO_V0 = [0] + [] # sighashInfo = [sighashVersion] || associatedData

# Must match Proof::expected_proof_size for OrchardZSA in QED-it/orchard.
IRONWOOD_ZSA_BASE_PROOF_SIZE = 2848
IRONWOOD_ZSA_PER_ACTION_PROOF_SIZE = 2272


def ironwood_zsa_proof_size(num_actions):
    return IRONWOOD_ZSA_BASE_PROOF_SIZE + IRONWOOD_ZSA_PER_ACTION_PROOF_SIZE * num_actions


class IronwoodZSAActionDescription(OrchardActionBase):
    def __init__(self, rand, sighash_info):
        super().__init__(ZC_IRONWOOD_ZSA_ENCCIPHERTEXT_SIZE, rand)
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
    def __init__(self, rand, anchor_ironwood, is_coinbase, have_burn, sighash_info):
        self.vActionsIronwood = []
        # There must always be a non-zero number of Action Descriptions in an Action Group.
        for _ in range(rand.u8() % 4 + 1):
            self.vActionsIronwood.append(IronwoodZSAActionDescription(rand, sighash_info))
        # flagsIronwood, from LSB to MSB: enableSpends, enableOutputs, enableCrossAddress (ZIP 2006),
        # enableZSA; the remaining bits MUST be 0. At least one of enableSpends and enableOutputs
        # MUST be set; enableCrossAddress may take either value.
        self.flagsIronwood = rand.a([0b001, 0b010, 0b011, 0b101, 0b110, 0b111])
        # Set enableZSA by OR with 0b00001000.
        self.flagsIronwood |= 8
        if is_coinbase:
            # In coinbase transactions, enableSpends and enableZSA MUST be 0, so set enableOutputs = 1
            # and keep the drawn enableCrossAddress.
            self.flagsIronwood = (self.flagsIronwood & 0b100) | 0b010
        self.anchorIronwood = anchor_ironwood
        self.nAGExpiryHeight = 0

        # OrchardZSA Burn Fields
        self.vAssetBurnIronwoodZSA = []
        if have_burn:
            for _ in range(rand.u8() % 5):
                self.vAssetBurnIronwoodZSA.append(AssetBurnDescription(rand))

        self.proofsIronwood = rand.b(ironwood_zsa_proof_size(len(self.vActionsIronwood)))


    def __bytes__(self):
        ret = b''
        ret += write_compact_size(len(self.vActionsIronwood))
        for desc in self.vActionsIronwood:
            ret += bytes(desc)  # Excludes spendAuthSig
        ret += struct.pack('B', self.flagsIronwood)
        ret += bytes(self.anchorIronwood)
        ret += struct.pack('<I', self.nAGExpiryHeight)
        ret += self.ironwood_zsa_burn_field_bytes()
        ret += write_compact_size(len(self.proofsIronwood))
        ret += self.proofsIronwood
        for desc in self.vActionsIronwood:
            ret += write_compact_size(len(desc.spendAuthSigInfo))
            ret += bytes(desc.spendAuthSigInfo)
            ret += bytes(desc.spendAuthSig)

        return ret

    def ironwood_zsa_burn_field_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.vAssetBurnIronwoodZSA))
        if len(self.vAssetBurnIronwoodZSA) > 0:
            for desc in self.vAssetBurnIronwoodZSA:
                ret += bytes(desc)
        return ret


class TransactionZSA(TransactionBase):
    def __init__(self, rand, consensus_branch_id, sighash_info, have_ironwood_zsa=True, have_burn=True, have_issuance=True):

        # We cannot have burns without an IronwoodZSA bundle.
        assert have_ironwood_zsa or not have_burn

        # We cannot have issuance without an IronwoodZSA bundle.
        assert have_ironwood_zsa or not have_issuance

        # All Transparent, Sapling, Orchard and part of the Ironwood Transaction Fields are initialized in the super
        # class.
        super().__init__(rand, have_ironwood_zsa)
        if have_ironwood_zsa:
            # The base class draws proofsIronwood only to keep the rand stream stable;
            # IronwoodZSA proofs live per Action Group, so drop the stale attribute.
            del self.proofsIronwood
        self.vSighashInfo = [sighash_info] * len(self.vin)
        for desc in self.vSpendsSapling:
            desc.spendAuthSigInfo = sighash_info
        for desc in self.vActionsOrchard:
            desc.spendAuthSigInfo = sighash_info
        if hasattr(self, "bindingSigSapling"):
            self.bindingSigSaplingInfo = sighash_info
        if hasattr(self, "bindingSigOrchard"):
            self.bindingSigOrchardInfo = sighash_info
        if hasattr(self, "bindingSigIronwood"):
            self.bindingSigIronwoodInfo = sighash_info


    # Common Transaction Fields
        self.nVersionGroupId = NU7_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id
        self.zip233Amount = 0

        # IronwoodZSA Transaction Fields
        self.vActionGroupsIronwood = []
        if have_ironwood_zsa:
            # For ZSA (pre-Swaps) we have a maximum of one Action Group.
            self.vActionGroupsIronwood.append(ActionGroupDescription(rand, self.anchorIronwood, self.is_coinbase(), have_burn, sighash_info))

        # IronwoodZSA Issuance Fields
        self.vIssueActions = []
        self.issuer = []
        if have_issuance:
            self.isk = rand.b(32)
            self.issuer = IssuanceKeys(self.isk).ik_encoding
            for _ in range(rand.u8() % 5 + 1):
                self.vIssueActions.append(IssueActionDescription(rand))

            t_inputs = [TransparentInput(nIn, rand) for nIn in range(len(self.vin))]
            sighash = signature_digest_zsa(self, t_inputs, SIGHASH_ALL, None)

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
        # ret += struct.pack('<Q', self.zip233Amount) #not included in spec.
        return ret

    def transparent_sighash_info_bytes(self):
        ret = b''
        for sighash_info in self.vSighashInfo:
            ret += write_compact_size(len(sighash_info))
            ret += bytes(sighash_info)
        return ret

    def sapling_spend_auth_sig_bytes(self, desc):
        ret = b''
        ret += write_compact_size(len(desc.spendAuthSigInfo))
        ret += bytes(desc.spendAuthSigInfo)
        ret += bytes(desc.spendAuthSig)
        return ret

    def sapling_binding_sig_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.bindingSigSaplingInfo))
        ret += bytes(self.bindingSigSaplingInfo)
        ret += bytes(self.bindingSigSapling)
        return ret

    def orchard_spend_auth_sig_bytes(self, desc):
        ret = b''
        ret += write_compact_size(len(desc.spendAuthSigInfo))
        ret += bytes(desc.spendAuthSigInfo)
        ret += bytes(desc.spendAuthSig)
        return ret

    def orchard_binding_sig_bytes(self):
        ret = b''
        ret += write_compact_size(len(self.bindingSigOrchardInfo))
        ret += bytes(self.bindingSigOrchardInfo)
        ret += bytes(self.bindingSigOrchard)
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

        # IronwoodZSA Transaction Fields
        ret += write_compact_size(len(self.vActionGroupsIronwood))
        if len(self.vActionGroupsIronwood) > 0:
            for ag in self.vActionGroupsIronwood:
                ret += bytes(ag)
            ret += struct.pack('<q', self.valueBalanceIronwood)
            ret += write_compact_size(len(self.bindingSigIronwoodInfo))
            ret += bytes(self.bindingSigIronwoodInfo)
            ret += bytes(self.bindingSigIronwood)

        # IronwoodZSA Issuance Fields
        ret += self.issuance_field_bytes()

        return ret


def main():
    consensus_branch_id = 0x77190AD8  # NU7
    rand = rand_gen()
    test_vectors = []

    # Since the burn fields are within the Ironwood ZSA fields, we can't have burn without Ironwood ZSA.
    # We also cannot have issuance without Ironwood ZSA.
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
            tx = TransactionZSA(rand, consensus_branch_id, SIGHASH_INFO_V0, *choice)
            populate_test_vector(rand, test_vectors, tx, True)

    generate_test_vectors('zcash_test_vectors/transaction_zsa', test_vectors)


if __name__ == '__main__':
    main()
