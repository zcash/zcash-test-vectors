#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import struct
from hashlib import blake2b

from .output import render_args, render_tv
from .rand import Rand
from .utils import i2leosp
from .zc_utils import write_compact_size

# https://zips.z.cash/zip-0221#tree-node-specification
# H(msg, branch_id) = BLAKE2b-256(msg, personalization = b'ZcashHistory' || LE32(branch_id))
def H(msg, consensus_branch_id):
    person = b'ZcashHistory' + struct.pack('<I', consensus_branch_id)
    assert len(person) == 16
    return blake2b(msg, digest_size=32, person=person).digest()

# Zcash Protocol Spec section 7.7.5 (Definition of Work): decode the compact
# `nBits` target representation.
def to_target(n_bits):
    size = n_bits >> 24
    mantissa = n_bits & 0x007fffff
    if size <= 3:
        return mantissa >> (8 * (3 - size))
    else:
        return mantissa << (8 * (size - 3))

# https://zips.z.cash/zip-0221 field 8: floor(2^256 / (ToTarget(nBits) + 1))
def calculate_work(n_bits):
    target = to_target(n_bits)
    assert 0 < target < (1 << 256)
    return (1 << 256) // (target + 1)


# A node in the ZIP 221 MMR. Orchard fields (present from V2/NU5) and Ironwood
# fields (present from V3/NU6.3, per ZIP 229) are None when absent; their
# presence is what distinguishes the tree version. Leaf nodes have no children.
class ZcashMMRNode:
    def __init__(self, consensus_branch_id, left_child, right_child,
                 hash_subtree_commitment,
                 n_earliest_timestamp, n_latest_timestamp,
                 n_earliest_target_bits, n_latest_target_bits,
                 hash_earliest_sapling_root, hash_latest_sapling_root,
                 n_subtree_total_work,
                 n_earliest_height, n_latest_height,
                 n_sapling_tx_count,
                 hash_earliest_orchard_root=None, hash_latest_orchard_root=None,
                 n_orchard_tx_count=None,
                 hash_earliest_ironwood_root=None, hash_latest_ironwood_root=None,
                 n_ironwood_tx_count=None):
        self.consensus_branch_id = consensus_branch_id
        self.left_child = left_child
        self.right_child = right_child
        self.hash_subtree_commitment = hash_subtree_commitment
        self.n_earliest_timestamp = n_earliest_timestamp
        self.n_latest_timestamp = n_latest_timestamp
        self.n_earliest_target_bits = n_earliest_target_bits
        self.n_latest_target_bits = n_latest_target_bits
        self.hash_earliest_sapling_root = hash_earliest_sapling_root
        self.hash_latest_sapling_root = hash_latest_sapling_root
        self.n_subtree_total_work = n_subtree_total_work
        self.n_earliest_height = n_earliest_height
        self.n_latest_height = n_latest_height
        self.n_sapling_tx_count = n_sapling_tx_count
        self.hash_earliest_orchard_root = hash_earliest_orchard_root
        self.hash_latest_orchard_root = hash_latest_orchard_root
        self.n_orchard_tx_count = n_orchard_tx_count
        self.hash_earliest_ironwood_root = hash_earliest_ironwood_root
        self.hash_latest_ironwood_root = hash_latest_ironwood_root
        self.n_ironwood_tx_count = n_ironwood_tx_count

    @property
    def n_leaves(self):
        return self.n_latest_height - (self.n_earliest_height - 1)

    def serialize(self):
        buf = (self.hash_subtree_commitment
            + struct.pack('<I', self.n_earliest_timestamp)
            + struct.pack('<I', self.n_latest_timestamp)
            + struct.pack('<I', self.n_earliest_target_bits)
            + struct.pack('<I', self.n_latest_target_bits)
            + self.hash_earliest_sapling_root
            + self.hash_latest_sapling_root
            + i2leosp(256, self.n_subtree_total_work)
            + write_compact_size(self.n_earliest_height, allow_u64=True)
            + write_compact_size(self.n_latest_height, allow_u64=True)
            + write_compact_size(self.n_sapling_tx_count, allow_u64=True))
        if self.hash_earliest_orchard_root is not None:
            buf += (self.hash_earliest_orchard_root
                + self.hash_latest_orchard_root
                + write_compact_size(self.n_orchard_tx_count, allow_u64=True))
        if self.hash_earliest_ironwood_root is not None:
            buf += (self.hash_earliest_ironwood_root
                + self.hash_latest_ironwood_root
                + write_compact_size(self.n_ironwood_tx_count, allow_u64=True))
        return buf


# Build a leaf node from a block's header data and metadata. Every
# earliest/latest pair is set to the block's single value.
def from_block(block):
    return ZcashMMRNode(
        consensus_branch_id=block['consensus_branch_id'],
        left_child=None, right_child=None,
        hash_subtree_commitment=block['block_hash'],
        n_earliest_timestamp=block['time'],
        n_latest_timestamp=block['time'],
        n_earliest_target_bits=block['n_bits'],
        n_latest_target_bits=block['n_bits'],
        hash_earliest_sapling_root=block['sapling_root'],
        hash_latest_sapling_root=block['sapling_root'],
        n_subtree_total_work=calculate_work(block['n_bits']),
        n_earliest_height=block['height'],
        n_latest_height=block['height'],
        n_sapling_tx_count=block['sapling_tx_count'],
        hash_earliest_orchard_root=block.get('orchard_root'),
        hash_latest_orchard_root=block.get('orchard_root'),
        n_orchard_tx_count=block.get('orchard_tx_count'),
        hash_earliest_ironwood_root=block.get('ironwood_root'),
        hash_latest_ironwood_root=block.get('ironwood_root'),
        n_ironwood_tx_count=block.get('ironwood_tx_count'))


# https://zips.z.cash/zip-0221#tree-nodes-and-hashing-pseudocode
# Internal node: subtree commitment is H(serialize(left) || serialize(right));
# earliest-* fields inherit from the left child, latest-* from the right child;
# work and transaction counts are summed.
def make_parent(left, right):
    assert left.consensus_branch_id == right.consensus_branch_id

    def sum_opt(a, b):
        return None if a is None or b is None else a + b

    return ZcashMMRNode(
        consensus_branch_id=left.consensus_branch_id,
        left_child=left, right_child=right,
        hash_subtree_commitment=H(left.serialize() + right.serialize(),
                                  left.consensus_branch_id),
        n_earliest_timestamp=left.n_earliest_timestamp,
        n_latest_timestamp=right.n_latest_timestamp,
        n_earliest_target_bits=left.n_earliest_target_bits,
        n_latest_target_bits=right.n_latest_target_bits,
        hash_earliest_sapling_root=left.hash_earliest_sapling_root,
        hash_latest_sapling_root=right.hash_latest_sapling_root,
        n_subtree_total_work=left.n_subtree_total_work + right.n_subtree_total_work,
        n_earliest_height=left.n_earliest_height,
        n_latest_height=right.n_latest_height,
        n_sapling_tx_count=left.n_sapling_tx_count + right.n_sapling_tx_count,
        hash_earliest_orchard_root=left.hash_earliest_orchard_root,
        hash_latest_orchard_root=right.hash_latest_orchard_root,
        n_orchard_tx_count=sum_opt(left.n_orchard_tx_count, right.n_orchard_tx_count),
        hash_earliest_ironwood_root=left.hash_earliest_ironwood_root,
        hash_latest_ironwood_root=right.hash_latest_ironwood_root,
        n_ironwood_tx_count=sum_opt(left.n_ironwood_tx_count, right.n_ironwood_tx_count))


def get_peaks(node):
    leaves = node.n_leaves
    assert leaves > 0
    # A power-of-two leaf count is a single perfect subtree (one peak); this
    # also covers a single isolated leaf.
    if (leaves & (leaves - 1)) == 0:
        return [node]
    return get_peaks(node.left_child) + get_peaks(node.right_child)


def bag_peaks(peaks):
    # Fold left-to-right, accumulator as the left child.
    root = peaks[0]
    for peak in peaks[1:]:
        root = make_parent(root, peak)
    return root


def append(root, leaf):
    peaks = get_peaks(root)
    merged = []
    current = leaf
    for peak in peaks[::-1]:
        if current.n_leaves == peak.n_leaves:
            current = make_parent(peak, current)
        else:
            merged.append(current)
            current = peak
    merged.append(current)
    return bag_peaks(merged[::-1])


# https://zips.z.cash/zip-0221 : hashChainHistoryRoot = H(serialize(root)).
def make_root_commitment(root):
    return H(root.serialize(), root.consensus_branch_id)


N_LEAVES = 16

# Base (earliest) height per version — only affects which CompactSize width is
# exercised. Real activation heights where known; V3 uses a plausible value.
BASE_HEIGHT = {1: 903000, 2: 1687104, 3: 3500000}

# Consensus branch ID per version (see ZIPs 250 / 252 / 229).
BRANCH_ID = {1: 0xF5B9230B, 2: 0xC2D6D0B4, 3: 0x37A5165B}


def gen_block(rand, version, height):
    # nBits: exponent in [0x1c, 0x1f] and a normalized 3-byte mantissa with the
    # sign bit clear, so to_target stays in (0, 2^256).
    exponent = 0x1c + (rand.u8() % 4)
    mantissa = 0x008000 + (rand.u32() % (0x7fffff - 0x008000 + 1))
    n_bits = (exponent << 24) | mantissa
    block = dict(
        consensus_branch_id=BRANCH_ID[version],
        block_hash=rand.b(32),
        time=rand.u32(),
        n_bits=n_bits,
        sapling_root=rand.b(32),
        height=height,
        sapling_tx_count=rand.u8() % 8,
    )
    if version >= 2:
        block['orchard_root'] = rand.b(32)
        block['orchard_tx_count'] = rand.u8() % 8
    if version >= 3:
        block['ironwood_root'] = rand.b(32)
        block['ironwood_tx_count'] = rand.u8() % 8
    return block


def build_vectors(version):
    from random import Random
    rng = Random(0x02210000 + version)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    (lo_len, hi_len) = {1: (147, 171), 2: (212, 244), 3: (277, 317)}[version]

    vectors = []
    root = None
    for i in range(N_LEAVES):
        block = gen_block(rand, version, BASE_HEIGHT[version] + i)
        leaf = from_block(block)
        assert lo_len <= len(leaf.serialize()) <= hi_len, len(leaf.serialize())
        root = leaf if root is None else append(root, leaf)
        assert root.n_leaves == i + 1

        peaks = get_peaks(root)
        vector = {
            'consensus_branch_id': BRANCH_ID[version],
            'n_leaves': i + 1,
            'leaf_block_hash': block['block_hash'],
            'leaf_time': block['time'],
            'leaf_target_bits': block['n_bits'],
            'leaf_sapling_root': block['sapling_root'],
            'leaf_work': i2leosp(256, leaf.n_subtree_total_work),
            'leaf_height': block['height'],
            'leaf_sapling_tx_count': block['sapling_tx_count'],
            'leaf_serialized': leaf.serialize(),
            'peaks': [p.serialize() for p in peaks],
            'root_serialized': root.serialize(),
            'hash_chain_history_root': make_root_commitment(root),
        }
        if version >= 2:
            vector['leaf_orchard_root'] = block['orchard_root']
            vector['leaf_orchard_tx_count'] = block['orchard_tx_count']
        if version >= 3:
            vector['leaf_ironwood_root'] = block['ironwood_root']
            vector['leaf_ironwood_tx_count'] = block['ironwood_tx_count']
        vectors.append(vector)
    return vectors


# Field layout passed to render_tv, per version. 32-byte values render as
# [u8; 32]; variable-length serializations as &[u8]; the peaks list as
# &[&[u8]]. In the "zcash" target, 32-byte values are byte-reversed (repo
# convention); the variable-length blobs are never 32 bytes, so they stay
# byte-exact.
def parts_for(version):
    parts = [
        ('consensus_branch_id', 'u32'),
        ('n_leaves', 'u32'),
        ('leaf_block_hash', '[u8; 32]'),
        ('leaf_time', 'u32'),
        ('leaf_target_bits', 'u32'),
        ('leaf_sapling_root', '[u8; 32]'),
        ('leaf_work', '[u8; 32]'),
        ('leaf_height', 'u64'),
        ('leaf_sapling_tx_count', 'u64'),
    ]
    if version >= 2:
        parts += [
            ('leaf_orchard_root', '[u8; 32]'),
            ('leaf_orchard_tx_count', 'u64'),
        ]
    if version >= 3:
        parts += [
            ('leaf_ironwood_root', '[u8; 32]'),
            ('leaf_ironwood_tx_count', 'u64'),
        ]
    parts += [
        ('leaf_serialized', "&'static [u8]"),
        ('peaks', "&'static [&'static [u8]]"),
        ('root_serialized', "&'static [u8]"),
        ('hash_chain_history_root', '[u8; 32]'),
    ]
    return parts


def render_version(version):
    args = render_args()
    render_tv(
        args,
        'zcash_test_vectors/zip_0221',
        parts_for(version),
        build_vectors(version),
    )


def v1():
    render_version(1)


def v2():
    render_version(2)


def v3():
    render_version(3)


if __name__ == '__main__':
    v3()
