#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

# Test vectors for the key negation of ZIP 312, "FROST for Spend Authorization
# Multisignatures" <https://zips.z.cash/zip-0312>, as revised in
# <https://github.com/zcash/zips/pull/1459>:
#
#   ... if the last bit of SerializeElement(PK) is 1 then PK MUST be replaced
#   by -PK, every signing key share sk_i MUST be replaced by -sk_i, and every
#   public verifying share PK_i MUST be replaced by -PK_i. ... Values
#   recomputed later from the DKG transcript ... are the values before this
#   replacement, so the replacement MUST be applied again whenever they are
#   recomputed.
#
# Two 2-of-3 DKGs from one seed: the first whose transcript gives a group key
# with y-tilde = 0 (nothing replaced) and the first whose transcript gives
# y-tilde = 1 (replaced). Each vector carries the DKG transcript, the values
# before and after the replacement, and one Re-Randomized FROST signing session
# by participants 1 and 3 whose signature verifies as a RedPallas SpendAuthSig
# under the randomized, replaced group key.
#
# The DKG is the PedPoP DKG that frost-core implements (RFC 9591 defines no
# DKG): the proof of knowledge of participant i is (R, mu) with
# c = HDKG(identifier_i || phi_i0 || R), HDKG = BLAKE2b-512("FROST_RedPallasD").
# ZIP 312 does not fix a DKG, and the replacement applies after key generation
# by any method; only the dkg_* fields depend on this choice.
#
# The message is 32 random bytes standing in for a SIGHASH.

from hashlib import blake2b
from random import Random

from .orchard.generators import SPENDING_KEY_BASE as G
from .orchard.pallas import Point, Scalar
from .orchard.utils import to_scalar
from .output import render_args, render_tv
from .rand import Rand, randbytes


def blake2b512(person, m):
    return blake2b(m, digest_size=64, person=person).digest()


# The hash functions of the ciphersuite FROST(Pallas, BLAKE2b-512).
def H1(m): return to_scalar(blake2b512(b"FROST_RedPallasR", m))
def H2(m): return to_scalar(blake2b512(b"Zcash_RedPallasH", m))
def H3(m): return to_scalar(blake2b512(b"FROST_RedPallasN", m))
def H4(m): return blake2b512(b"FROST_RedPallasM", m)
def H5(m): return blake2b512(b"FROST_RedPallasC", m)
def HR(m): return to_scalar(blake2b512(b"FROST_RedPallasA", m))
# The proof of knowledge of frost-core's DKG (not part of ZIP 312).
def HDKG(m): return to_scalar(blake2b512(b"FROST_RedPallasD", m))


def ser_e(P):
    assert P != Point.identity()
    return bytes(P)


def ser_s(s):
    return bytes(s)


def ident(i):
    return ser_s(Scalar(i))


def ytilde(P):
    return bytes(P)[31] >> 7


def random_nonzero(rand):
    while True:
        s = Scalar.random(rand)
        if s != Scalar.ZERO:
            return s


def poly_eval(coeffs, x):
    ret = Scalar.ZERO
    for c in reversed(coeffs):
        ret = ret * Scalar(x) + c
    return ret


def lagrange_at_zero(i, signers):
    num = Scalar.ONE
    den = Scalar.ONE
    for j in signers:
        if j != i:
            num = num * Scalar(j)
            den = den * (Scalar(j) - Scalar(i))
    return num / den


#
# Key generation and the replacement
#

class Dkg(object):
    def __init__(self, rand, t, n):
        self.t, self.n = t, n
        self.coeffs = {}
        self.commitments = {}
        self.pok = {}
        for i in range(1, n + 1):
            a = [random_nonzero(rand)] + [Scalar.random(rand) for _ in range(t - 1)]
            phi = [G * c for c in a]
            k = random_nonzero(rand)
            R = G * k
            c = HDKG(ident(i) + ser_e(phi[0]) + ser_e(R))
            mu = k + a[0] * c
            self.coeffs[i], self.commitments[i], self.pok[i] = a, phi, ser_e(R) + ser_s(mu)
            assert verify_pok(i, phi, self.pok[i])
        # Round 2: f_l(i), sent by participant l to participant i.
        self.shares = {(l, i): poly_eval(self.coeffs[l], i)
                       for l in range(1, n + 1) for i in range(1, n + 1)}

        # The values before the replacement, which is what the transcript gives.
        self.raw_pk = Point.identity()
        for l in range(1, n + 1):
            self.raw_pk = self.raw_pk + self.commitments[l][0]
        self.raw_sk = {i: sum((self.shares[(l, i)] for l in range(1, n + 1)), Scalar.ZERO)
                       for i in range(1, n + 1)}
        self.raw_vk = {i: self.vk_from_transcript(i) for i in range(1, n + 1)}
        for i in range(1, n + 1):
            assert G * self.raw_sk[i] == self.raw_vk[i]

        # ZIP 312: if the last bit of SerializeElement(PK) is 1, PK is replaced
        # by -PK, every sk_i by -sk_i and every PK_i by -PK_i.
        self.negated = ytilde(self.raw_pk) == 1
        sign = (lambda x: -x) if self.negated else (lambda x: x)
        self.pk = sign(self.raw_pk)
        self.sk = {i: sign(s) for (i, s) in self.raw_sk.items()}
        self.vk = {i: sign(P) for (i, P) in self.raw_vk.items()}
        assert ytilde(self.pk) == 0
        for i in range(1, n + 1):
            assert G * self.sk[i] == self.vk[i]

    def vk_from_transcript(self, i):
        """PK_i recomputed from the public commitments alone."""
        acc = Point.identity()
        for l in range(1, self.n + 1):
            xj = Scalar.ONE
            for phi in self.commitments[l]:
                acc = acc + phi * xj
                xj = xj * Scalar(i)
        return acc


def verify_pok(i, phi, pok):
    R = Point.from_bytes(pok[:32])
    mu = Scalar.from_bytes(pok[32:])
    c = HDKG(ident(i) + ser_e(phi[0]) + ser_e(R))
    return R == G * mu - phi[0] * c


#
# Re-Randomized FROST signing (ZIP 312, RFC 9591)
#

def encode_commitment_list(commitments):
    """commitments: {i: (D_i, E_i)}, encoded in order of identifier."""
    return b"".join(ident(i) + ser_e(D) + ser_e(E) for (i, (D, E)) in sorted(commitments.items()))


def round_one(rand, sk_i):
    """RFC 9591 nonce_generate, hedged with the signing share."""
    h = H3(rand.b(32) + ser_s(sk_i))
    b = H3(rand.b(32) + ser_s(sk_i))
    return (h, b), (G * h, G * b)


def randomizer_regenerate(seed, commitments):
    return HR(seed + encode_commitment_list(commitments))


def binding_factors(rpk, msg, commitments):
    prefix = ser_e(rpk) + H4(msg) + H5(encode_commitment_list(commitments))
    return {i: H1(prefix + ident(i)) for i in sorted(commitments)}


def group_commitment(commitments, rho):
    R = Point.identity()
    for (i, (D, E)) in sorted(commitments.items()):
        R = R + D + E * rho[i]
    return R


class Session(object):
    """One signing session; `nonces` and `commitments` are {i: pair}."""

    def __init__(self, pk, sk, vk, msg, nonces, commitments, seed):
        self.signers = sorted(commitments)
        self.msg = msg
        self.nonces, self.commitments, self.seed = nonces, commitments, seed
        self.randomizer = randomizer_regenerate(seed, commitments)
        self.rpk = pk + G * self.randomizer
        self.rho = binding_factors(self.rpk, msg, commitments)
        self.R = group_commitment(commitments, self.rho)
        self.c = H2(ser_e(self.R) + ser_e(self.rpk) + msg)
        self.lam = {i: lagrange_at_zero(i, self.signers) for i in self.signers}
        self.z = {}
        for i in self.signers:
            (h, b) = nonces[i]
            self.z[i] = h + b * self.rho[i] + self.lam[i] * (sk[i] + self.randomizer) * self.c
            assert verify_share(self, i, vk[i], self.z[i])
        self.signature = ser_e(self.R) + ser_s(sum(self.z.values(), Scalar.ZERO))
        assert redpallas_verify(ser_e(self.rpk), msg, self.signature)


def verify_share(sess, i, vk_i, z_i):
    """Signature share check under PK_i + [randomizer]G."""
    (D, E) = sess.commitments[i]
    rvk = vk_i + G * sess.randomizer
    return G * z_i == D + E * sess.rho[i] + rvk * (sess.c * sess.lam[i])


def redpallas_verify(vk_bytes, msg, sig):
    """RedDSA.Validate for SpendAuthSig^Orchard (protocol specification 5.4.7)."""
    vk = Point.from_bytes(vk_bytes)
    R = Point.from_bytes(sig[:32])
    if vk is None or R is None:
        return False
    try:
        S = Scalar.from_bytes(sig[32:])
    except ValueError:
        return False
    c = H2(sig[:32] + vk_bytes + msg)
    return G * S == R + vk * c


#
# Key negation vectors
#

NEGATION_T, NEGATION_N = 2, 3
NEGATION_SIGNERS = [1, 3]


def negation_vector(rand, dkg):
    t, n, signers = NEGATION_T, NEGATION_N, NEGATION_SIGNERS
    msg = rand.b(32)  # stands in for a SIGHASH
    nonces, commitments = {}, {}
    for i in signers:
        nonces[i], commitments[i] = round_one(rand, dkg.sk[i])
    seed = rand.b(32)
    s = Session(dkg.pk, dkg.sk, dkg.vk, msg, nonces, commitments, seed)
    if dkg.negated:
        # Under the key before the replacement, the signature does not verify.
        assert not redpallas_verify(ser_e(dkg.raw_pk + G * s.randomizer), msg, s.signature)
    rng = range(1, n + 1)
    return {
        't': t,
        'n': n,
        'dkg_coefficients': [[ser_s(c) for c in dkg.coeffs[l]] for l in rng],
        'dkg_commitments': [[ser_e(P) for P in dkg.commitments[l]] for l in rng],
        'dkg_proofs_of_knowledge': [dkg.pok[l] for l in rng],
        'dkg_shares': [[ser_s(dkg.shares[(l, i)]) for i in rng] for l in rng],
        'raw_group_key': ser_e(dkg.raw_pk),
        'raw_signing_shares': [ser_s(dkg.raw_sk[i]) for i in rng],
        'raw_verifying_shares': [ser_e(dkg.raw_vk[i]) for i in rng],
        'raw_ytilde': ytilde(dkg.raw_pk),
        'group_key': ser_e(dkg.pk),
        'signing_shares': [ser_s(dkg.sk[i]) for i in rng],
        'verifying_shares': [ser_e(dkg.vk[i]) for i in rng],
        'signers': signers,
        'message': msg,
        'hiding_nonces': [ser_s(nonces[i][0]) for i in signers],
        'binding_nonces': [ser_s(nonces[i][1]) for i in signers],
        'hiding_commitments': [ser_e(commitments[i][0]) for i in signers],
        'binding_commitments': [ser_e(commitments[i][1]) for i in signers],
        'randomizer_seed': seed,
        'randomizer': ser_s(s.randomizer),
        'randomized_group_key': ser_e(s.rpk),
        'binding_factors': [ser_s(s.rho[i]) for i in signers],
        'group_commitment': ser_e(s.R),
        'signature_shares': [ser_s(s.z[i]) for i in signers],
        'signature': s.signature,
    }


def negation():
    args = render_args()

    rand = Rand(randbytes(Random(0x312E6A7E)))
    found = {}
    while len(found) < 2:
        dkg = Dkg(rand, NEGATION_T, NEGATION_N)
        if dkg.negated not in found:
            found[dkg.negated] = negation_vector(rand, dkg)
    test_vectors = [found[False], found[True]]

    render_tv(
        args,
        'zcash_test_vectors/zip_0312',
        (
            ('t', 'u8'),
            ('n', 'u8'),
            ('dkg_coefficients', {'rust_type': '[[[u8; 32]; 2]; 3]', 'bitcoin_flavoured': False}),
            ('dkg_commitments', {'rust_type': '[[[u8; 32]; 2]; 3]', 'bitcoin_flavoured': False}),
            ('dkg_proofs_of_knowledge', {'rust_type': '[[u8; 64]; 3]', 'bitcoin_flavoured': False}),
            ('dkg_shares', {'rust_type': '[[[u8; 32]; 3]; 3]', 'bitcoin_flavoured': False}),
            ('raw_group_key', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('raw_signing_shares', {'rust_type': '[[u8; 32]; 3]', 'bitcoin_flavoured': False}),
            ('raw_verifying_shares', {'rust_type': '[[u8; 32]; 3]', 'bitcoin_flavoured': False}),
            ('raw_ytilde', 'u8'),
            ('group_key', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('signing_shares', {'rust_type': '[[u8; 32]; 3]', 'bitcoin_flavoured': False}),
            ('verifying_shares', {'rust_type': '[[u8; 32]; 3]', 'bitcoin_flavoured': False}),
            ('signers', '[u16; 2]'),
            ('message', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('hiding_nonces', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('binding_nonces', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('hiding_commitments', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('binding_commitments', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('randomizer_seed', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('randomizer', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('randomized_group_key', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('binding_factors', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('group_commitment', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('signature_shares', {'rust_type': '[[u8; 32]; 2]', 'bitcoin_flavoured': False}),
            ('signature', {'rust_type': '[u8; 64]', 'bitcoin_flavoured': False}),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    negation()
