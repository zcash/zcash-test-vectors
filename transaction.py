#!/usr/bin/env python3
import struct

MAX_MONEY = 21000000 * 100000000
TX_EXPIRY_HEIGHT_THRESHOLD = 500000000

OVERWINTER_VERSION_GROUP_ID = 0x03C48270
OVERWINTER_TX_VERSION = 3


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
        return struct.pack('b', len(self._script)) + self._script


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

        ret += struct.pack('b', len(self.vin))
        for x in self.vin:
            ret += bytes(x)

        ret += struct.pack('b', len(self.vout))
        for x in self.vout:
            ret += bytes(x)

        ret += struct.pack('<I', self.nLockTime)
        if isOverwinterV3:
            ret += struct.pack('<I', self.nExpiryHeight)

        if self.nVersion >= 2:
            ret += struct.pack('b', 0)

        return ret
