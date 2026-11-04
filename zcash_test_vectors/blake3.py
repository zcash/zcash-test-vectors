#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import struct

# A straightforward implementation of BLAKE3, following the reference
# implementation in the BLAKE3 specification
# <https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf>.
# It is slow, but the test vector generators only hash short inputs.

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

MASK = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK

def g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr(state[b] ^ state[c], 7)

def round_function(state, m):
    # Mix the columns.
    g(state, 0, 4, 8, 12, m[0], m[1])
    g(state, 1, 5, 9, 13, m[2], m[3])
    g(state, 2, 6, 10, 14, m[4], m[5])
    g(state, 3, 7, 11, 15, m[6], m[7])
    # Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9])
    g(state, 1, 6, 11, 12, m[10], m[11])
    g(state, 2, 7, 8, 13, m[12], m[13])
    g(state, 3, 4, 9, 14, m[14], m[15])

def compress(chaining_value, block_words, counter, block_len, flags):
    state = list(chaining_value) + IV[:4] + [
        counter & MASK,
        (counter >> 32) & MASK,
        block_len,
        flags,
    ]
    block = list(block_words)
    for r in range(7):
        round_function(state, block)
        if r < 6:
            block = [block[i] for i in MSG_PERMUTATION]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state

def words_from_bytes(b):
    assert len(b) % 4 == 0
    return list(struct.unpack('<%dI' % (len(b) // 4), b))


class Output(object):
    def __init__(self, input_chaining_value, block_words, counter, block_len, flags):
        self.input_chaining_value = input_chaining_value
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return compress(
            self.input_chaining_value,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )[:8]

    def root_output_bytes(self, length):
        out = b''
        output_block_counter = 0
        while len(out) < length:
            words = compress(
                self.input_chaining_value,
                self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | ROOT,
            )
            out += struct.pack('<16I', *words)
            output_block_counter += 1
        return out[:length]


class ChunkState(object):
    def __init__(self, key_words, chunk_counter, flags):
        self.chaining_value = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = b''
        self.blocks_compressed = 0
        self.flags = flags

    def len(self):
        return BLOCK_LEN * self.blocks_compressed + len(self.block)

    def start_flag(self):
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data):
        while data:
            # If the block buffer is full, compress it and clear it. More
            # input is coming, so this compression is not CHUNK_END.
            if len(self.block) == BLOCK_LEN:
                self.chaining_value = compress(
                    self.chaining_value,
                    words_from_bytes(self.block),
                    self.chunk_counter,
                    BLOCK_LEN,
                    self.flags | self.start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block = b''
            take = min(BLOCK_LEN - len(self.block), len(data))
            self.block += data[:take]
            data = data[take:]

    def output(self):
        block = self.block + bytes(BLOCK_LEN - len(self.block))
        return Output(
            self.chaining_value,
            words_from_bytes(block),
            self.chunk_counter,
            len(self.block),
            self.flags | self.start_flag() | CHUNK_END,
        )


def parent_output(left_child_cv, right_child_cv, key_words, flags):
    return Output(key_words, left_child_cv + right_child_cv, 0, BLOCK_LEN, PARENT | flags)

def parent_cv(left_child_cv, right_child_cv, key_words, flags):
    return parent_output(left_child_cv, right_child_cv, key_words, flags).chaining_value()


class Hasher(object):
    def __init__(self, key_words=IV, flags=0):
        self.chunk_state = ChunkState(key_words, 0, flags)
        self.key_words = list(key_words)
        self.cv_stack = []
        self.flags = flags

    @classmethod
    def new_keyed(cls, key):
        assert len(key) == KEY_LEN
        return cls(words_from_bytes(key), KEYED_HASH)

    @classmethod
    def new_derive_key(cls, context):
        context_hasher = cls(IV, DERIVE_KEY_CONTEXT)
        context_hasher.update(context.encode('utf-8'))
        context_key = context_hasher.finalize(KEY_LEN)
        return cls(words_from_bytes(context_key), DERIVE_KEY_MATERIAL)

    def add_chunk_chaining_value(self, new_cv, total_chunks):
        # Merge completed subtrees: each trailing zero bit in the new total
        # number of chunks closes one subtree.
        while total_chunks & 1 == 0:
            new_cv = parent_cv(self.cv_stack.pop(), new_cv, self.key_words, self.flags)
            total_chunks >>= 1
        self.cv_stack.append(new_cv)

    def update(self, data):
        while data:
            # If the current chunk is complete, finalize it and start a new
            # one. More input is coming, so this chunk is not the root.
            if self.chunk_state.len() == CHUNK_LEN:
                chunk_cv = self.chunk_state.output().chaining_value()
                total_chunks = self.chunk_state.chunk_counter + 1
                self.add_chunk_chaining_value(chunk_cv, total_chunks)
                self.chunk_state = ChunkState(self.key_words, total_chunks, self.flags)
            take = min(CHUNK_LEN - self.chunk_state.len(), len(data))
            self.chunk_state.update(data[:take])
            data = data[take:]

    def finalize(self, length=OUT_LEN):
        output = self.chunk_state.output()
        for cv in reversed(self.cv_stack):
            output = parent_output(cv, output.chaining_value(), self.key_words, self.flags)
        return output.root_output_bytes(length)


def blake3_hash(data, length=OUT_LEN):
    h = Hasher()
    h.update(data)
    return h.finalize(length)

def blake3_keyed_hash(key, data, length=OUT_LEN):
    h = Hasher.new_keyed(key)
    h.update(data)
    return h.finalize(length)

def blake3_derive_key(context, key_material, length=OUT_LEN):
    h = Hasher.new_derive_key(context)
    h.update(key_material)
    return h.finalize(length)
