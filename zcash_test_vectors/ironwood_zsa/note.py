import struct

from .asset_base import native_asset
from .commitments import note_commit
from ..orchard.key_components import diversify_hash, prf_expand
from ..orchard.note import OrchardNote, OrchardNotePlaintext
from ..orchard.utils import to_scalar
from ..utils import i2leosp, leos2bsp


class OrchardZSANote(OrchardNote):
    def __init__(self, d, pk_d, v, asset, rho, rseed):
        super().__init__(d, pk_d, v, rho, rseed)
        self.asset = asset

    def __eq__(self, other):
        if other is None:
            return False
        return (
                super().__eq__(other) and
                self.asset == other.asset
        )

    def qr_rcm(self):
        g_d = diversify_hash(self.d)
        return to_scalar(prf_expand(
            self.rseed,
            b'\x0e' +
            bytes(g_d) +
            bytes(self.pk_d) +
            i2leosp(64, self.v) +
            bytes(self.rho) +
            bytes(self.psi) +
            bytes(self.asset),
            ))

    def note_commitment(self):
        g_d = diversify_hash(self.d)
        return note_commit(self.rcm, leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v, leos2bsp(bytes(self.asset)), self.rho, self.psi)

    def qr_note_commitment(self):
        g_d = diversify_hash(self.d)
        return note_commit(self.qr_rcm(), leos2bsp(bytes(g_d)), leos2bsp(bytes(self.pk_d)), self.v, leos2bsp(bytes(self.asset)), self.rho, self.psi)

    def note_plaintext(self, memo):
        return OrchardZSANotePlaintext(self.d, self.v, self.rseed, self.asset, memo)

# https://zips.z.cash/zip-0226#note-structure-commitment
class OrchardZSANotePlaintext(OrchardNotePlaintext):
    def __init__(self, d, v, rseed, asset, memo):
        super().__init__(d, v, rseed, memo)
        self.leadbyte = bytes.fromhex('f0')
        self.asset = asset

    @staticmethod
    def from_bytes(buf):
        leadbyte = buf[0]
        if leadbyte in (2, 3):
            return OrchardZSANotePlaintext._from_bytes_orchard(buf)
        if leadbyte == 0xf0:
            return OrchardZSANotePlaintext._from_bytes_zsa(buf)
        raise ValueError("invalid lead byte")

    @staticmethod
    def _from_bytes_orchard(buf):
        return OrchardZSANotePlaintext(
            buf[1:12],      # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            buf[20:52],     # rseed
            native_asset(), # asset
            buf[52:564],    # memo
        )

    @staticmethod
    def _from_bytes_zsa(buf):
        return OrchardZSANotePlaintext(
            buf[1:12],   # d
            struct.unpack('<Q', buf[12:20])[0],  # v
            buf[20:52],  # rseed
            buf[52:84],  # asset
            buf[84:596]  # memo
        )

    def __bytes__(self):
        return (
            super().__bytes__()[:-512] +
            self.asset +
            self.memo
        )
