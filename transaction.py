#!/usr/bin/env python3
import struct

from zc_utils import write_compact_size

MAX_MONEY = 21000000 * 100000000
TX_EXPIRY_HEIGHT_THRESHOLD = 500000000

OVERWINTER_VERSION_GROUP_ID = 0x03C48270
OVERWINTER_TX_VERSION = 3


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


class JoinSplit(object):
    def __init__(self, rand):
        self.vpub_old = 0
        self.vpub_new = 0
        self.anchor = rand.b(32)
        self.nullifiers = (rand.b(32), rand.b(32))
        self.commitments = (rand.b(32), rand.b(32))
        self.ephemeralKey = rand.b(32)
        self.randomSeed = rand.b(32)
        self.macs = (rand.b(32), rand.b(32))
        self.proof = PHGRProof(rand)
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
    def __init__(self, rand):
        self._script = bytes([
            rand.a(RAND_OPCODES) for i in range(rand.u8() % 10)
        ])

    def raw(self):
        return self._script

    def __bytes__(self):
        return write_compact_size(len(self._script)) + self._script


class OutPoint(object):
    def __init__(self, rand):
        self.txid = rand.b(32)
        self.n = rand.u32()

    def __bytes__(self):
        return self.txid + struct.pack('<I', self.n)


class TxIn(object):
    def __init__(self, rand):
        self.prevout = OutPoint(rand)
        self.scriptSig = Script(rand)
        self.nSequence = rand.u32()

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


class Transaction(object):
    def __init__(self, rand, version):
        if version == OVERWINTER_TX_VERSION:
            self.fOverwintered = True
            self.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
            self.nVersion = OVERWINTER_TX_VERSION
        else:
            self.fOverwintered = False
            self.nVersion = rand.u32() & ((1 << 31) - 1)

        self.vin = []
        for i in range(rand.u8() % 3):
            self.vin.append(TxIn(rand))

        self.vout = []
        for i in range(rand.u8() % 3):
            self.vout.append(TxOut(rand))

        self.nLockTime = rand.u32()
        self.nExpiryHeight = rand.u32() % TX_EXPIRY_HEIGHT_THRESHOLD

        self.vJoinSplit = []
        if self.nVersion >= 2:
            for i in range(rand.u8() % 3):
                self.vJoinSplit.append(JoinSplit(rand))
            if len(self.vJoinSplit) > 0:
                self.joinSplitPubKey = rand.b(32) # Potentially invalid
                self.joinSplitSig = rand.b(64) # Invalid

    def header(self):
        return self.nVersion | (1 << 31 if self.fOverwintered else 0)

    def __bytes__(self):
        ret = b''
        ret += struct.pack('<I', self.header())
        if self.fOverwintered:
            ret += struct.pack('<I', self.nVersionGroupId)

        isOverwinterV3 = \
            self.fOverwintered and \
            self.nVersionGroupId == OVERWINTER_VERSION_GROUP_ID and \
            self.nVersion == OVERWINTER_TX_VERSION

        ret += write_compact_size(len(self.vin))
        for x in self.vin:
            ret += bytes(x)

        ret += write_compact_size(len(self.vout))
        for x in self.vout:
            ret += bytes(x)

        ret += struct.pack('<I', self.nLockTime)
        if isOverwinterV3:
            ret += struct.pack('<I', self.nExpiryHeight)

        if self.nVersion >= 2:
            ret += write_compact_size(len(self.vJoinSplit))
            for jsdesc in self.vJoinSplit:
                ret += bytes(jsdesc)
            if len(self.vJoinSplit) > 0:
                ret += self.joinSplitPubKey
                ret += self.joinSplitSig

        return ret
