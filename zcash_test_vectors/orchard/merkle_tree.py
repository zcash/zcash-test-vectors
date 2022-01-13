#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from binascii import unhexlify

from .pallas import Fp
from .sinsemilla import sinsemilla_hash

from ..output import render_args, render_tv
from ..utils import i2lebsp, leos2bsp

# https://zips.z.cash/protocol/nu5.pdf#constants
MERKLE_DEPTH = 32
L_MERKLE = 255
UNCOMMITTED_ORCHARD = Fp(2)

# https://zips.z.cash/protocol/nu5.pdf#orchardmerklecrh
def merkle_crh(layer, left, right, depth=MERKLE_DEPTH):
    assert layer < depth
    assert len(left) == L_MERKLE
    assert len(right) == L_MERKLE
    l = i2lebsp(10, depth - 1 - layer)
    return sinsemilla_hash(b"z.cash:Orchard-MerkleCRH", l + left + right)

left = unhexlify("87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505")[::-1]
right = unhexlify("a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406")[::-1]

left = leos2bsp(left)[:L_MERKLE]
right = leos2bsp(right)[:L_MERKLE]

# parent = merkle_crh(MERKLE_DEPTH - 1 - 25, left, right)
parent = Fp(626278560043615083774572461435172561667439770708282630516615972307985967801)
assert merkle_crh(MERKLE_DEPTH - 1 - 25, left, right) == parent
assert merkle_crh(MERKLE_DEPTH - 1 - 26, left, right) != parent

def empty_roots():
    empty_roots = [UNCOMMITTED_ORCHARD]
    for layer in range(0, MERKLE_DEPTH)[::-1]:
        bits = i2lebsp(L_MERKLE, empty_roots[-1].s)
        empty_roots.append(merkle_crh(layer, bits, bits))
    return empty_roots


def main():
    args = render_args()

    from random import Random
    from ..rand import Rand

    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    SMALL_DEPTH = 4

    # Derive path for each leaf in a tree of depth 4.
    def get_paths_and_root(leaves):
        assert(len(leaves) == (1 << SMALL_DEPTH))
        paths = [[] for _ in range(1 << SMALL_DEPTH)]

        # At layer 0, we want:
        # - leaf 0: sibling 1
        # - leaf 1: sibling 0
        # - leaf 2: sibling 3
        # - leaf 3: sibling 2 (etc.)
        # We repeat this all the way up, just with shorter arrays.
        cur_layer = leaves
        next_layer = []
        for l in range(0, SMALL_DEPTH):
            # Iterate over nodes in the current layer.
            for i in range(0, len(cur_layer)):
                is_left = (i % 2) == 0
                sibling = cur_layer[i + 1] if is_left else cur_layer[i - 1]

                # As we compute the tree, we start appending siblings to
                # multiple paths. Each sibling corresponds to (1 << layer)
                # leaves.
                leaves_per_sibling = (1 << l)
                for j in range(leaves_per_sibling * i, leaves_per_sibling * (i+1)):
                    paths[j].append(sibling)

                # Compute the parent of the current pair of siblings.
                if is_left:
                    layer = SMALL_DEPTH - 1 - l
                    left = leos2bsp(bytes(cur_layer[i]))[:L_MERKLE]
                    right = leos2bsp(bytes(sibling))[:L_MERKLE]
                    next_layer.append(merkle_crh(layer, left, right, depth=SMALL_DEPTH))

            cur_layer = next_layer
            next_layer = []

        # We should have reached the root of the tree.
        assert(len(cur_layer) == 1)
        return (paths, cur_layer[0])

    # Test vectors:
    # - Create empty tree of depth 4.
    # - Append random leaves
    # - After each leaf is appended, derive the Merkle paths for every leaf
    #   position (using the empty leaf for positions that have not been filled).
    test_vectors = []
    leaves = [UNCOMMITTED_ORCHARD] * (1 << SMALL_DEPTH)
    for i in range(0, (1 << SMALL_DEPTH)):
        print("Appending leaf", i + 1, file = sys.stderr)
        # Append next leaf
        leaves[i] = Fp.random(rand)

        # Derive Merkle paths for all leaves
        (paths, root) = get_paths_and_root(leaves)

        test_vectors.append({
            'leaves': [bytes(leaf) for leaf in leaves],
            'paths': [[bytes(node) for node in path] for path in paths],
            'root': bytes(root),
        })

    render_tv(
        args,
        'orchard_merkle_tree',
        (
            ('leaves', '[[u8; 32]; %d]' % (1 << SMALL_DEPTH)),
            ('paths', '[[[u8; 32]; %d]; %d]' % (SMALL_DEPTH, (1 << SMALL_DEPTH))),
            ('root', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
