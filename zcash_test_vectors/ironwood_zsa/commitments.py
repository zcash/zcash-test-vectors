#!/usr/bin/env python3
import sys

assert sys.version_info[0] >= 3, "Python 3 required."

from ..orchard.group_hash import group_hash
from ..orchard.pallas import Fp, Scalar, Point
from ..orchard.sinsemilla import sinsemilla_hash_to_point
from ..utils import i2lebsp, leos2bsp
from .asset_base import zsa_value_base, asset_digest, encode_asset_id, native_asset

# Commitment schemes used in Orchard https://zips.z.cash/protocol/protocol.pdf#concretecommit
from ..orchard.commitments import rcv_trapdoor, L_ORCHARD_BASE

def value_commit(rcv: Scalar, v: Scalar, asset: Point):
    return asset * v + group_hash(b"z.cash:Orchard-cv", b"r") * rcv

# https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
def sinsemilla_commit_with_blind_personalization(r: Scalar, D_hash, D_blind, M):
    assert isinstance(r, Scalar)
    return sinsemilla_hash_to_point(D_hash + b"-M", M) + (
        group_hash(D_blind + b"-r", b"") * r
    )

# ZIP-226 (https://zips.z.cash/zip-0226)
def note_commit(rcm, g_d, pk_d, v, asset, rho, psi):
    from ..orchard.commitments import note_commit as note_commit_orchard

    if asset == leos2bsp(bytes(native_asset())):
        return note_commit_orchard(rcm, g_d, pk_d, v, rho, psi)
    else:
        return note_commit_zsa(rcm, g_d, pk_d, v, asset, rho, psi)

def note_commit_zsa(rcm, g_d, pk_d, v, asset, rho, psi):
    return sinsemilla_commit_with_blind_personalization(
        rcm,
        b"z.cash:ZSA-NoteCommit",
        b"z.cash:Orchard-NoteCommit",
        g_d + pk_d + i2lebsp(64, v) + i2lebsp(L_ORCHARD_BASE, rho.s) + i2lebsp(L_ORCHARD_BASE, psi.s) + asset
    )

# Test consistency of ValueCommit^{Orchard} and ValueCommit^{OrchardZSA} with precomputed generators
def test_value_commit():
    from random import Random
    from ..rand import Rand
    from ..orchard.generators import VALUE_COMMITMENT_RANDOMNESS_BASE

    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    rcv = rcv_trapdoor(rand)
    v = Scalar(rand.u64())

    # Native asset
    asset_base = native_asset()
    assert value_commit(rcv, v, asset_base) == VALUE_COMMITMENT_RANDOMNESS_BASE * rcv + asset_base * v

    # Random non-native asset
    asset_base = zsa_value_base(asset_digest(encode_asset_id(randbytes(32), randbytes(512))))
    assert value_commit(rcv, v, asset_base) == VALUE_COMMITMENT_RANDOMNESS_BASE * rcv + asset_base * v


if __name__ == '__main__':
    test_value_commit()
