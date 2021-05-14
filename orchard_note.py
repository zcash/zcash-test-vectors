import struct

from orchard_commitments import note_commit
from orchard_key_components import diversify_hash, prf_expand, derive_nullifier, FullViewingKey, SpendingKey
from orchard_pallas import Point, Scalar
from orchard_utils import to_base, to_scalar

from utils import leos2bsp

class OrchardNote(object):
    def __init__(self, d, pk_d, v: Scalar, rho, rseed):
        self.d = d
        self.pk_d = pk_d
        self.v = v
        self.rho = rho
        self.rseed = rseed
        self.rcm = self.rcm(rho)
        self.psi = self.psi(rho)

    def __bytes__(self):
        return (
            self.d +
            bytes(self.pk_d) +
            struct.pack('<Q', self.v.s) +
            bytes(self.rho) +
            bytes(self.rcm) +
            bytes(self.psi)
        )

    def rcm(self, rho):
        return to_scalar(prf_expand(bytes(self.rseed), b'\x05' + bytes(rho)))

    def psi(self, rho):
        return to_base(prf_expand(bytes(self.rseed), b'\x09' + bytes(rho)))

    def note_commitment(self):
        g_d = diversify_hash(self.d)
        return note_commit(self.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v.s, self.rho, self.psi)

    def note_plaintext(self, memo):
        return OrchardNotePlaintext(self.d, self.v, self.rseed, memo)

# https://zips.z.cash/protocol/nu5.pdf#notept
class OrchardNotePlaintext(object):
    def __init__(self, d, v, rseed, memo):
        self.leadbyte = bytes.fromhex('02')
        self.d = d
        self.v = v
        self.rseed = rseed
        self.memo = memo

    def __bytes__(self):
        return (
            self.leadbyte +
            self.d +
            struct.pack('<Q', self.v.s) +
            bytes(self.rseed) +
            self.memo
        )

    def dummy_nullifier(self, rand):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey(sk)
        pk_d = fvk.default_pkd()
        g_d = diversify_hash(fvk.default_d())

        v = Scalar.ZERO

        rho = Point.rand(rand)
        rho_bytes = bytes(rho)
        rho = rho.extract()

        note = OrchardNote(fvk.default_d(), pk_d, v, rho, rho_bytes)
        cm = note_commit(note.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(pk_d)), v.s, rho, note.psi)
        return derive_nullifier(fvk.nk, rho, note.psi, cm)