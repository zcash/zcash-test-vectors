#!/usr/bin/env python3
import sys

assert sys.version_info[0] >= 3, "Python 3 required."

from .group_hash import group_hash
from .pallas import Fp, Scalar, Point
from .sinsemilla import sinsemilla_hash_to_point
from .asset_base import zsa_value_base, asset_digest, encode_asset_id, native_asset
from ..utils import i2lebsp, leos2bsp

# Commitment schemes used in Orchard https://zips.z.cash/protocol/nu5.pdf#concretecommit

# https://zips.z.cash/protocol/nu5.pdf#constants
L_ORCHARD_BASE = 255

# https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
def homomorphic_pedersen_commitment(rcv: Scalar, D, v: Scalar):
    return group_hash(D, b"v") * v + group_hash(D, b"r") * rcv

def value_commit(rcv: Scalar, v: Scalar, asset: Point):
    return asset * v + group_hash(b"z.cash:Orchard-cv", b"r") * rcv

def rcv_trapdoor(rand):
    return Scalar.random(rand)

# https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
def sinsemilla_commit(r: Scalar, D, M):
    assert isinstance(r, Scalar)
    return sinsemilla_hash_to_point(D + b"-M", M) + (
        group_hash(D + b"-r", b"") * r
    )

# https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
def sinsemilla_commit_with_blind_personalization(r: Scalar, D_hash, D_blind, M):
    assert isinstance(r, Scalar)
    return sinsemilla_hash_to_point(D_hash + b"-M", M) + (
        group_hash(D_blind + b"-r", b"") * r
    )

def sinsemilla_short_commit(r: Scalar, D, M):
    return sinsemilla_commit(r, D, M).extract()

# ZIP-226 (https://github.com/zcash/zips/pull/628)
def note_commit(rcm, g_d, pk_d, v, asset, rho, psi):
    if asset == leos2bsp(bytes(native_asset())):
        return note_commit_orchard(rcm, g_d, pk_d, v, rho, psi)
    else:
        return note_commit_zsa(rcm, g_d, pk_d, v, asset, rho, psi)

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardnotecommit
def note_commit_orchard(rcm, g_d, pk_d, v, rho, psi):
    return sinsemilla_commit(
        rcm,
        b"z.cash:Orchard-NoteCommit",
        g_d + pk_d + i2lebsp(64, v) + i2lebsp(L_ORCHARD_BASE, rho.s) + i2lebsp(L_ORCHARD_BASE, psi.s)
    )

def note_commit_zsa(rcm, g_d, pk_d, v, asset, rho, psi):
    return sinsemilla_commit_with_blind_personalization(
        rcm,
        b"z.cash:ZSA-NoteCommit",
        b"z.cash:Orchard-NoteCommit",
        g_d + pk_d + i2lebsp(64, v) + i2lebsp(L_ORCHARD_BASE, rho.s) + i2lebsp(L_ORCHARD_BASE, psi.s) + asset
    )

def rcm_trapdoor(rand):
    return Scalar.random(rand)

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardnotecommit
def commit_ivk(rivk: Scalar, ak: Fp, nk: Fp):
    return sinsemilla_short_commit(
        rivk,
        b"z.cash:Orchard-CommitIvk",
        i2lebsp(L_ORCHARD_BASE, ak.s) + i2lebsp(L_ORCHARD_BASE, nk.s)
    )

def rivk_trapdoor(rand):
    return Scalar.random(rand)

# Test consistency of ValueCommit^{Orchard} with precomputed generators
def test_value_commit():
    from random import Random
    from ..rand import Rand
    from .generators import VALUE_COMMITMENT_RANDOMNESS_BASE

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
