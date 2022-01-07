#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .group_hash import group_hash
from .pallas import Fp, Scalar
from .sinsemilla import sinsemilla_hash_to_point
from ..utils import i2lebsp

# Commitment schemes used in Orchard https://zips.z.cash/protocol/nu5.pdf#concretecommit

# https://zips.z.cash/protocol/nu5.pdf#constants
L_ORCHARD_BASE = 255

# https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
def homomorphic_pedersen_commitment(rcv: Scalar, D, v: Scalar):
    return group_hash(D, b"v") * v + group_hash(D, b"r") * rcv

def value_commit(rcv: Scalar, v: Scalar):
    return homomorphic_pedersen_commitment(rcv, b"z.cash:Orchard-cv", v)

def rcv_trapdoor(rand):
    return Scalar.random(rand)

# https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
def sinsemilla_commit(r: Scalar, D, M):
    assert isinstance(r, Scalar)
    return sinsemilla_hash_to_point(D + b"-M", M) + (
        group_hash(D + b"-r", b"") * r
    )

def sinsemilla_short_commit(r: Scalar, D, M):
    return sinsemilla_commit(r, D, M).extract()

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardnotecommit
def note_commit(rcm, g_d, pk_d, v, rho, psi):
    return sinsemilla_commit(
        rcm,
        b"z.cash:Orchard-NoteCommit",
        g_d + pk_d + i2lebsp(64, v) + i2lebsp(L_ORCHARD_BASE, rho.s) + i2lebsp(L_ORCHARD_BASE, psi.s)
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
    from .generators import VALUE_COMMITMENT_RANDOMNESS_BASE, VALUE_COMMITMENT_VALUE_BASE

    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    rcv = rcv_trapdoor(rand)
    v = Scalar(100000000)

    assert value_commit(rcv, v) == VALUE_COMMITMENT_RANDOMNESS_BASE * rcv + VALUE_COMMITMENT_VALUE_BASE * v

if __name__ == '__main__':
    test_value_commit()
