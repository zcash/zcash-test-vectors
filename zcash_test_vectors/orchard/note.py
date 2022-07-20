import struct

from .commitments import note_commit
from .key_components import diversify_hash, prf_expand, derive_nullifier, FullViewingKey, SpendingKey
from .pallas import Point, Scalar
from .utils import to_base, to_scalar

from ..utils import leos2bsp

class OrchardNote(object):
    def __init__(self, d, pk_d, v, note_type, rho, rseed):
        assert isinstance(v, int)
        self.d = d
        self.pk_d = pk_d
        self.v = v
        self.note_type = note_type
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
            self.note_type == other.note_type and
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
        note_type = self.note_type and leos2bsp(self.note_type)
        return note_commit(self.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v, note_type, self.rho, self.psi)

    def note_plaintext(self, memo):
        return OrchardNotePlaintext(self.d, self.v, self.note_type, self.rseed, memo)

# https://zips.z.cash/protocol/nu5.pdf#notept
class OrchardNotePlaintext(object):
    def __init__(self, d, v, note_type, rseed, memo):
        self.leadbyte = bytes.fromhex('03' if note_type else '02')
        self.d = d
        self.v = v
        self.note_type = note_type
        self.rseed = rseed
        self.memo = memo
        if note_type:
            assert(max(memo[512-32:]) == 0)
    
    @staticmethod
    def from_bytes(buf):
        leadbyte = buf[0]
        if leadbyte == 2:
            return OrchardNotePlaintext._from_bytes_orchard(buf)
        if leadbyte == 3:
            return OrchardNotePlaintext._from_bytes_zsa(buf)
        raise "invalid lead byte"

    @staticmethod
    def _from_bytes_orchard(buf):
        return OrchardNotePlaintext(
            buf[1:12],   # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            None,        # note_type
            buf[20:52],  # rseed
            buf[52:564], # memo
        )

    @staticmethod
    def _from_bytes_zsa(buf):
        return OrchardNotePlaintext(
            buf[1:12],   # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            buf[52:84],  # note_type
            buf[20:52],  # rseed
            buf[84:564] + bytes(32), # memo
        )

    def __bytes__(self):
        if self.note_type:
            return self._to_bytes_zsa()
        else:
            return self._to_bytes_orchard()

    def _to_bytes_orchard(self):
        return (
            self.leadbyte +
            self.d +
            struct.pack('<Q', self.v) +
            self.rseed +
            self.memo
        )

    def _to_bytes_zsa(self):
        return (
            self.leadbyte +
            self.d +
            struct.pack('<Q', self.v) +
            self.rseed +
            self.note_type +
            self.memo[:512-32]
        )

    def dummy_nullifier(self, rand):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        pk_d = fvk.default_pkd()
        d = fvk.default_d()

        v = 0
        note_type = None

        rseed = rand.b(32)
        rho = Point.rand(rand).extract()

        note = OrchardNote(d, pk_d, v, note_type, rho, rseed)
        cm = note.note_commitment()
        return derive_nullifier(fvk.nk, rho, note.psi, cm)
