import struct

from .commitments import note_commit
from .key_components import diversify_hash, prf_expand, derive_nullifier, FullViewingKey, SpendingKey
from .pallas import Point
from .utils import to_base, to_scalar
from ..utils import leos2bsp

class OrchardNote(object):
    def __init__(self, d, pk_d, v, rho, rseed):
        assert isinstance(v, int)
        self.d = d
        self.pk_d = pk_d
        self.v = v
        self.rho = rho
        self.rseed = rseed
        self.rcm = self.rcm()
        self.psi = self.psi()

    def __eq__(self, other):
        if other is None:
            return False
        return (
            self.d == other.d and
            self.pk_d == other.pk_d and
            self.v == other.v and
            self.rho == other.rho and
            self.rcm == other.rcm and
            self.psi == other.psi
        )

    def rcm(self):
        return to_scalar(prf_expand(self.rseed, b'\x05' + bytes(self.rho)))

    def psi(self):
        return to_base(prf_expand(self.rseed, b'\x09' + bytes(self.rho)))

    def note_commitment(self):
        g_d = diversify_hash(self.d)
        return note_commit(self.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v, self.rho, self.psi)

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
            struct.pack('<Q', self.v) +
            self.rseed +
            self.memo
        )

    def dummy_nullifier(self, rand):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        pk_d = fvk.default_pkd()
        d = fvk.default_d()

        v = 0
        rseed = rand.b(32)
        rho = Point.rand(rand).extract()

        note = OrchardNote(d, pk_d, v, rho, rseed)
        cm = note.note_commitment()
        return derive_nullifier(fvk.nk, rho, note.psi, cm)
