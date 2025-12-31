import struct

from .orchard.pallas import (
    Fp as PallasBase,
    Scalar as PallasScalar,
)
from .orchard.sinsemilla import group_hash as pallas_group_hash
from .orchard_zsa.digests import NU7_TX_VERSION_BYTES
from .sapling.generators import find_group_hash, SPENDING_KEY_BASE
from .sapling.jubjub import (
    Fq,
    Point,
    Fr as JubjubScalar,
)
from .utils import leos2ip, i2leosp
from .zc_utils import write_compact_size

MAX_MONEY = 21000000 * 100000000
TX_EXPIRY_HEIGHT_THRESHOLD = 500000000

OVERWINTER_VERSION_GROUP_ID = 0x03C48270
OVERWINTER_TX_VERSION = 3

SAPLING_VERSION_GROUP_ID = 0x892F2085
SAPLING_TX_VERSION = 4

NU5_VERSION_GROUP_ID = 0x26A7270A
NU5_TX_VERSION = 5
NU5_TX_VERSION_BYTES = NU5_TX_VERSION | (1 << 31)

# Sapling note magic values, copied from src/zcash/Zcash.h
NOTEENCRYPTION_AUTH_BYTES = 16
ZC_NOTEPLAINTEXT_LEADING = 1
ZC_V_SIZE = 8
ZC_RHO_SIZE = 32
ZC_R_SIZE = 32
ZC_MEMO_SIZE = 512
ZC_DIVERSIFIER_SIZE = 11
ZC_JUBJUB_POINT_SIZE = 32
ZC_JUBJUB_SCALAR_SIZE = 32
ZC_NOTEPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE
ZC_SAPLING_ENCPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_DIVERSIFIER_SIZE + ZC_V_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE
ZC_SAPLING_OUTPLAINTEXT_SIZE = ZC_JUBJUB_POINT_SIZE + ZC_JUBJUB_SCALAR_SIZE
ZC_SAPLING_ENCCIPHERTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES
ZC_SAPLING_OUTCIPHERTEXT_SIZE = ZC_SAPLING_OUTPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES

# BN254 encoding of G1 elements. p[1] is big-endian.
def pack_g1(p):
    return struct.pack('B', 0x02 | (1 if p[0] else 0)) + p[1]

# BN254 encoding of G2 elements. p[1] is big-endian.
def pack_g2(p):
    return struct.pack('B', 0x0a | (1 if p[0] else 0)) + p[1]

class PHGRProof(object):
    def __init__(self, rand):
        self.g_A = (rand.bool(), rand.b(32))
        self.g_A_prime = (rand.bool(), rand.b(32))
        self.g_B = (rand.bool(), rand.b(64))
        self.g_B_prime = (rand.bool(), rand.b(32))
        self.g_C = (rand.bool(), rand.b(32))
        self.g_C_prime = (rand.bool(), rand.b(32))
        self.g_K = (rand.bool(), rand.b(32))
        self.g_H = (rand.bool(), rand.b(32))

    def __bytes__(self):
        return (
            pack_g1(self.g_A) +
            pack_g1(self.g_A_prime) +
            pack_g2(self.g_B) +
            pack_g1(self.g_B_prime) +
            pack_g1(self.g_C) +
            pack_g1(self.g_C_prime) +
            pack_g1(self.g_K) +
            pack_g1(self.g_H)
        )

class GrothProof(object):
    def __init__(self, rand):
        self.g_A = rand.b(48)
        self.g_B = rand.b(96)
        self.g_C = rand.b(48)

    def __bytes__(self):
        return (
            self.g_A +
            self.g_B +
            self.g_C
        )

class RedJubjubSignature(object):
    def __init__(self, rand):
        self.R = find_group_hash(b'TVRandPt', rand.b(32))
        self.S = JubjubScalar(leos2ip(rand.b(32)))

    def __bytes__(self):
        return (
            bytes(self.R) +
            bytes(self.S)
        )

class RedPallasSignature(object):
    def __init__(self, rand):
        self.R = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.S = PallasScalar(leos2ip(rand.b(32)))

    def __bytes__(self):
        return (
            bytes(self.R) +
            bytes(self.S)
        )

class SpendDescription(object):
    def __init__(self, rand, anchor=None):
        self.cv = find_group_hash(b'TVRandPt', rand.b(32))
        self.anchor = Fq(leos2ip(rand.b(32))) if anchor is None else anchor
        self.nullifier = rand.b(32)
        self.rk = Point.rand(rand)
        self.proof = GrothProof(rand)
        self.spendAuthSig = rand.b(64) if anchor is None else RedJubjubSignature(rand) # Invalid

    def bytes_v5(self):
        return (
            bytes(self.cv) +
            self.nullifier +
            bytes(self.rk)
        )

    def __bytes__(self):
        return (
            bytes(self.cv) +
            bytes(self.anchor) +
            self.nullifier +
            bytes(self.rk) +
            bytes(self.proof) +
            self.spendAuthSig
        )

class OutputDescription(object):
    def __init__(self, rand):
        self.cv = find_group_hash(b'TVRandPt', rand.b(32))
        self.cmu = Fq(leos2ip(rand.b(32)))
        self.ephemeralKey = find_group_hash(b'TVRandPt', rand.b(32))
        self.encCiphertext = rand.b(ZC_SAPLING_ENCCIPHERTEXT_SIZE)
        self.outCipherText = rand.b(ZC_SAPLING_OUTCIPHERTEXT_SIZE)
        self.proof = GrothProof(rand)

    def bytes_v5(self):
        return (
            bytes(self.cv) +
            bytes(self.cmu) +
            bytes(self.ephemeralKey) +
            self.encCiphertext +
            self.outCipherText
        )

    def __bytes__(self):
        return (
            self.bytes_v5() +
            bytes(self.proof)
        )

class OrchardActionBase(object):
    def __init__(self, enc_ciphertext_size, rand):
        # We don't need to take account of whether this is a coinbase transaction,
        # because we're only generating random fields.
        self.cv = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.nullifier = PallasBase(leos2ip(rand.b(32)))
        self.rk = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.cmx = PallasBase(leos2ip(rand.b(32)))
        self.ephemeralKey = pallas_group_hash(b'TVRandPt', rand.b(32))
        self.encCiphertext = rand.b(enc_ciphertext_size)
        self.outCiphertext = rand.b(ZC_SAPLING_OUTCIPHERTEXT_SIZE)
        self.spendAuthSig = RedPallasSignature(rand)

    def __bytes__(self):
        return (
            bytes(self.cv) +
            bytes(self.nullifier) +
            bytes(self.rk) +
            bytes(self.cmx) +
            bytes(self.ephemeralKey) +
            self.encCiphertext +
            self.outCiphertext
        )

class OrchardActionDescription(OrchardActionBase):
    def __init__(self, rand):
        super().__init__(ZC_SAPLING_ENCCIPHERTEXT_SIZE, rand)

class JoinSplit(object):
    def __init__(self, rand, fUseGroth = False):
        self.vpub_old = 0
        self.vpub_new = 0
        self.anchor = rand.b(32)
        self.nullifiers = (rand.b(32), rand.b(32))
        self.commitments = (rand.b(32), rand.b(32))
        self.ephemeralKey = rand.b(32)
        self.randomSeed = rand.b(32)
        self.macs = (rand.b(32), rand.b(32))
        self.proof = GrothProof(rand) if fUseGroth else PHGRProof(rand)
        self.ciphertexts = (rand.b(601), rand.b(601))

    def __bytes__(self):
        return (
            struct.pack('<Q', self.vpub_old) +
            struct.pack('<Q', self.vpub_new) +
            self.anchor +
            b''.join(self.nullifiers) +
            b''.join(self.commitments) +
            self.ephemeralKey +
            self.randomSeed +
            b''.join(self.macs) +
            bytes(self.proof) +
            b''.join(self.ciphertexts)
        )


RAND_OPCODES = [
    0x00, # OP_FALSE,
    0x51, # OP_1,
    0x52, # OP_2,
    0x53, # OP_3,
    0xac, # OP_CHECKSIG,
    0x63, # OP_IF,
    0x65, # OP_VERIF,
    0x6a, # OP_RETURN,
]

class Script(object):
    def __init__(self, rand=None):
        if rand is not None:
            self._script = bytes([
                rand.a(RAND_OPCODES) for i in range(rand.i8() % 10)
            ])

    @staticmethod
    def from_bytes(b):
        script = Script()
        script._script = b
        return script

    @staticmethod
    def coinbase_from_height(height):
        assert height >= 0
        if height == 0:
            enc_height = b'\x00'
        elif height <= 16:
            enc_height = bytes([0x50 + height])
        elif height <= 0x7F:
            enc_height = b'\x01' + i2leosp( 8, height)
        elif height <= 0x7FFF:
            enc_height = b'\x02' + i2leosp(16, height)
        elif height <= 0x7FFFFF:
            enc_height = b'\x03' + i2leosp(24, height)
        elif height <= 0x7FFFFFFF:
            enc_height = b'\x04' + i2leosp(32, height)
        else:
            assert height <= 0x7FFFFFFFFF
            enc_height = b'\x05' + i2leosp(40, height)

        # zcashd adds an OP_0
        return Script.from_bytes(enc_height + b'\x00')

    def raw(self):
        return self._script

    def __bytes__(self):
        return write_compact_size(len(self._script)) + self._script


class OutPoint(object):
    def __init__(self, rand=None):
        if rand is not None:
            self.txid = rand.b(32)
            self.n = rand.u32()

    @staticmethod
    def from_components(txid, n):
        outpoint = OutPoint()
        outpoint.txid = txid
        outpoint.n = n
        return outpoint

    def __bytes__(self):
        return self.txid + struct.pack('<I', self.n)


class TxIn(object):
    def __init__(self, rand=None):
        if rand is not None:
            self.prevout = OutPoint(rand)
            self.scriptSig = Script(rand)
            self.nSequence = rand.u32()

    @staticmethod
    def from_components(prevout, scriptSig, nSequence):
        txin = TxIn()
        txin.prevout = prevout
        txin.scriptSig = scriptSig
        txin.nSequence = nSequence
        return txin

    def __bytes__(self):
        return (
            bytes(self.prevout) +
            bytes(self.scriptSig) +
            struct.pack('<I', self.nSequence)
        )


class TxOut(object):
    def __init__(self, rand):
        self.nValue = rand.u64() % (MAX_MONEY + 1)
        self.scriptPubKey = Script(rand)

    def __bytes__(self):
        return struct.pack('<Q', self.nValue) + bytes(self.scriptPubKey)


class LegacyTransaction(object):
    def __init__(self, rand, version):
        if version == OVERWINTER_TX_VERSION:
            self.fOverwintered = True
            self.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
            self.nVersion = OVERWINTER_TX_VERSION
        elif version == SAPLING_TX_VERSION:
            self.fOverwintered = True
            self.nVersionGroupId = SAPLING_VERSION_GROUP_ID
            self.nVersion = SAPLING_TX_VERSION
        else:
            self.fOverwintered = False
            self.nVersion = rand.u32() & ((1 << 31) - 1)

        self.vin = []
        for i in range(rand.i8() % 3):
            self.vin.append(TxIn(rand))

        self.vout = []
        for i in range(rand.i8() % 3):
            self.vout.append(TxOut(rand))

        self.nLockTime = rand.u32()
        self.nExpiryHeight = rand.u32() % TX_EXPIRY_HEIGHT_THRESHOLD
        if self.nVersion >= SAPLING_TX_VERSION:
            self.valueBalance = rand.u64() % (MAX_MONEY + 1)

        self.vShieldedSpends = []
        self.vShieldedOutputs = []
        if self.nVersion >= SAPLING_TX_VERSION:
            for _ in range(rand.i8() % 5):
                self.vShieldedSpends.append(SpendDescription(rand))
            for _ in range(rand.i8() % 5):
                self.vShieldedOutputs.append(OutputDescription(rand))

        self.vJoinSplit = []
        if self.nVersion >= 2:
            for i in range(rand.i8() % 3):
                self.vJoinSplit.append(JoinSplit(rand, self.fOverwintered and self.nVersion >= SAPLING_TX_VERSION))
            if len(self.vJoinSplit) > 0:
                self.joinSplitPubKey = rand.b(32) # Potentially invalid
                self.joinSplitSig = rand.b(64) # Invalid

        if self.nVersion >= SAPLING_TX_VERSION:
            self.bindingSig = rand.b(64) # Invalid

    def version_bytes(self):
        return self.nVersion | (1 << 31 if self.fOverwintered else 0)

    def __bytes__(self):
        ret = b''
        ret += struct.pack('<I', self.version_bytes())
        if self.fOverwintered:
            ret += struct.pack('<I', self.nVersionGroupId)

        isOverwinterV3 = \
            self.fOverwintered and \
            self.nVersionGroupId == OVERWINTER_VERSION_GROUP_ID and \
            self.nVersion == OVERWINTER_TX_VERSION

        isSaplingV4 = \
            self.fOverwintered and \
            self.nVersionGroupId == SAPLING_VERSION_GROUP_ID and \
            self.nVersion == SAPLING_TX_VERSION

        ret += write_compact_size(len(self.vin))
        for x in self.vin:
            ret += bytes(x)

        ret += write_compact_size(len(self.vout))
        for x in self.vout:
            ret += bytes(x)

        ret += struct.pack('<I', self.nLockTime)
        if isOverwinterV3 or isSaplingV4:
            ret += struct.pack('<I', self.nExpiryHeight)

        if isSaplingV4:
            ret += struct.pack('<Q', self.valueBalance)
            ret += write_compact_size(len(self.vShieldedSpends))
            for desc in self.vShieldedSpends:
                ret += bytes(desc)
            ret += write_compact_size(len(self.vShieldedOutputs))
            for desc in self.vShieldedOutputs:
                ret += bytes(desc)

        if self.nVersion >= 2:
            ret += write_compact_size(len(self.vJoinSplit))
            for jsdesc in self.vJoinSplit:
                ret += bytes(jsdesc)
            if len(self.vJoinSplit) > 0:
                ret += self.joinSplitPubKey
                ret += self.joinSplitSig

        if isSaplingV4 and not (len(self.vShieldedSpends) == 0 and len(self.vShieldedOutputs) == 0):
            ret += self.bindingSig

        return ret

# Creating a base transaction class with common fields that V5 and subsequent versions can inherit.
class TransactionBase(object):
    def __init__(self, rand, have_orchard=True):
        # Decide which transaction parts will be generated.
        flip_coins = rand.u8()
        have_transparent_in = (flip_coins >> 0) % 2
        have_transparent_out = (flip_coins >> 1) % 2
        have_sapling = (flip_coins >> 2) % 2
        is_coinbase = (not have_transparent_in) and (flip_coins >> 4) % 2

        self.init_header_base(rand)
        self.init_transparent(rand, have_transparent_in, have_transparent_out, is_coinbase)
        self.init_sapling(rand, have_sapling, is_coinbase)
        self.init_orchard_base(rand, have_orchard)

        assert is_coinbase == self.is_coinbase()

    def init_header_base(self, rand):
        # Common Transaction Fields
        self.nLockTime = rand.u32()
        self.nExpiryHeight = rand.u32() % TX_EXPIRY_HEIGHT_THRESHOLD

    def init_transparent(self, rand, have_transparent_in, have_transparent_out, is_coinbase):
        # Transparent Transaction Fields
        self.vin = []
        self.vout = []
        if have_transparent_in:
            for _ in range((rand.u8() % 3) + 1):
                self.vin.append(TxIn(rand))
        if is_coinbase:
            self.vin.append(TxIn.from_components(
                OutPoint.from_components(b'\x00' * 32, 0xFFFFFFFF),
                Script.coinbase_from_height(self.nExpiryHeight),
                0xFFFFFFFF))
        if have_transparent_out:
            for _ in range((rand.u8() % 3) + 1):
                self.vout.append(TxOut(rand))

    def init_sapling(self, rand, have_sapling, is_coinbase):
        # Sapling Transaction Fields
        self.vSpendsSapling = []
        self.vOutputsSapling = []
        if have_sapling:
            # This anchor will be ignored if there are no Sapling spends.
            self.anchorSapling = Fq(leos2ip(rand.b(32)))
            # We use the randomness unconditionally here to avoid unnecessary test vector changes.
            for _ in range(rand.u8() % 3):
                spend = SpendDescription(rand, self.anchorSapling)
                if not is_coinbase:
                    self.vSpendsSapling.append(spend)
            for _ in range(rand.u8() % 3):
                self.vOutputsSapling.append(OutputDescription(rand))

            # valueBalanceSapling is "The net value of Sapling spends minus outputs."
            # So it's invalid to have a positive valueBalanceSapling if there are no spends,
            # or a negative valueBalanceSapling if there are no outputs (this is not enforced
            # as a separate consensus rule but it holds under the assumption of soundness
            # of the spend and output circuits).
            valueBalanceSapling = rand.u64() % (MAX_MONEY + 1)
            if len(self.vSpendsSapling) == 0:
                valueBalanceSapling = min(0, valueBalanceSapling)
            if len(self.vOutputsSapling) == 0:
                valueBalanceSapling = max(0, valueBalanceSapling)
            self.valueBalanceSapling = valueBalanceSapling

            # This binding sig will be ignored if there are neither Sapling spends nor outputs.
            self.bindingSigSapling = RedJubjubSignature(rand)
        else:
            # If valueBalanceSapling is not present in the serialized transaction, then
            # v^balanceSapling is defined to be 0.
            self.valueBalanceSapling = 0

    def init_orchard_base(self, rand, have_orchard):
        # Orchard Transaction Fields that are present in both V5 and V6
        if have_orchard:
            self.valueBalanceOrchard = rand.u64() % (MAX_MONEY + 1)
            self.anchorOrchard = PallasBase(leos2ip(rand.b(32)))
            self.proofsOrchard = rand.b(rand.u8() + 32) # Proof will always contain at least one element
            self.bindingSigOrchard = RedPallasSignature(rand)
        else:
            # If valueBalanceOrchard is not present in the serialized transaction, then
            # v^balanceOrchard is defined to be 0.
            self.valueBalanceOrchard = 0

    def is_coinbase(self):
        # <https://github.com/zcash/zcash/blob/d8c818bfa507adb845e527f5beb38345c490b330/src/primitives/transaction.h#L969-L972>
        return len(self.vin) == 1 and bytes(self.vin[0].prevout.txid) == b'\x00'*32 and self.vin[0].prevout.n == 0xFFFFFFFF

    def to_bytes(self, version_bytes, version_group_id, consensus_branch_id):
        ret = b''
        ret += self.header_bytes(version_bytes, version_group_id, consensus_branch_id)
        ret += self.transparent_bytes(version_bytes)
        ret += self.sapling_bytes(version_bytes)
        return ret

    def header_bytes(self, version_bytes, version_group_id, consensus_branch_id):
        ret = b''
        # Common Transaction Fields
        ret += struct.pack('<I', version_bytes)
        ret += struct.pack('<I', version_group_id)
        ret += struct.pack('<I', consensus_branch_id)
        ret += struct.pack('<I', self.nLockTime)
        ret += struct.pack('<I', self.nExpiryHeight)

        return ret

    def transparent_bytes(self, version_bytes):
        ret = b''
        # Transparent Transaction Fields
        ret += write_compact_size(len(self.vin))
        for x in self.vin:
            ret += bytes(x)
        ret += write_compact_size(len(self.vout))
        for x in self.vout:
            ret += bytes(x)
        if version_bytes == NU7_TX_VERSION_BYTES:
            for sighash_info in self.vSighashInfo:
                ret += write_compact_size(len(sighash_info))
                ret += bytes(sighash_info)

        return ret

    def sapling_bytes(self, version_bytes):
        ret = b''
        # Sapling Transaction Fields
        has_sapling = len(self.vSpendsSapling) + len(self.vOutputsSapling) > 0
        ret += write_compact_size(len(self.vSpendsSapling))
        for desc in self.vSpendsSapling:
            ret += desc.bytes_v5()
        ret += write_compact_size(len(self.vOutputsSapling))
        for desc in self.vOutputsSapling:
            ret += desc.bytes_v5()
        if has_sapling:
            ret += struct.pack('<Q', self.valueBalanceSapling)
        if len(self.vSpendsSapling) > 0:
            ret += bytes(self.anchorSapling)
            # Not explicitly gated in the protocol spec, but if the gate
            # were inactive then these loops would be empty by definition.
            for desc in self.vSpendsSapling: # vSpendProofsSapling
                ret += bytes(desc.proof)
            for desc in self.vSpendsSapling: # vSpendAuthSigsSapling
                if version_bytes == NU7_TX_VERSION_BYTES:
                    ret += write_compact_size(len(desc.spendAuthSigInfo))
                    ret += bytes(desc.spendAuthSigInfo)
                ret += bytes(desc.spendAuthSig)
        for desc in self.vOutputsSapling: # vOutputProofsSapling
            ret += bytes(desc.proof)
        if has_sapling:
            if version_bytes == NU7_TX_VERSION_BYTES:
                ret += write_compact_size(len(self.bindingSigSaplingInfo))
                ret += bytes(self.bindingSigSaplingInfo)
            ret += bytes(self.bindingSigSapling)

        return ret

class TransactionV5(TransactionBase):
    def __init__(self, rand, consensus_branch_id):
        have_orchard = rand.bool()
        # All Transparent, Sapling, and part of the Orchard Transaction Fields are initialized in the super class.
        super().__init__(rand, have_orchard)

        # Common Transaction Fields
        self.nVersionGroupId = NU5_VERSION_GROUP_ID
        self.nConsensusBranchId = consensus_branch_id

        # Orchard Transaction Fields
        self.vActionsOrchard = []
        if have_orchard:
            for _ in range(rand.u8() % 5):
                self.vActionsOrchard.append(OrchardActionDescription(rand))
            self.flagsOrchard = rand.u8()
            self.flagsOrchard &= 3  # Only two flag bits are currently defined.
            if self.is_coinbase():
                # set enableSpendsOrchard = 0
                self.flagsOrchard &= 2

    @staticmethod
    def version_bytes():
        return NU5_TX_VERSION_BYTES

    def __bytes__(self):
        ret = b''

        # Common Transaction Fields
        ret += super().to_bytes(self.version_bytes(), self.nVersionGroupId, self.nConsensusBranchId)

        # Orchard Transaction Fields
        ret += write_compact_size(len(self.vActionsOrchard))
        if len(self.vActionsOrchard) > 0:
            # Not explicitly gated in the protocol spec, but if the gate
            # were inactive then these loops would be empty by definition.
            for desc in self.vActionsOrchard:
                ret += bytes(desc) # Excludes spendAuthSig
            ret += struct.pack('B', self.flagsOrchard)
            ret += struct.pack('<q', self.valueBalanceOrchard)
            ret += bytes(self.anchorOrchard)
            ret += write_compact_size(len(self.proofsOrchard))
            ret += self.proofsOrchard
            for desc in self.vActionsOrchard:
                ret += bytes(desc.spendAuthSig)
            ret += bytes(self.bindingSigOrchard)

        return ret

class Transaction(object):
    def __init__(self, rand, version, consensus_branch_id=None):
        if version == NU5_TX_VERSION:
            assert consensus_branch_id is not None
            self.inner = TransactionV5(rand, consensus_branch_id)
        else:
            self.inner = LegacyTransaction(rand, version)

    def __getattr__(self, item):
        return getattr(self.inner, item)

    def __bytes__(self):
        return bytes(self.inner)
