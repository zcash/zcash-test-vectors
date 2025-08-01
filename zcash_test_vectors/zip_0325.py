from .unified_encoding import (
    ORCHARD_ITEM,
    SAPLING_ITEM,
    P2PKH_ITEM,
    decode_unified,
    preference_order_key,
    tlv,
)
from .zip_0032 import RegisteredKey

from .hd_common import hardened
from .output import render_args, render_tv

ContextString = b'MetadataKeys'
ZipNumber = 325

class AccountMetadataKey(object):
    def __init__(self, S, coinType, account):
        self.key = RegisteredKey.subtree_root(
            ContextString, S, ZipNumber
        ).child(
            hardened(coinType), b""
        ).child(
            hardened(account), b""
        )

    def InherentMetadataKey(self):
        return self.key.child(hardened(0), b"")

    def ImportedUfvkMetadataKey(self, ufvk):
        fvk_items = decode_unified(ufvk, "uview", {})

        def fvk_item(key, value):
            if key == "orchard":
                return (ORCHARD_ITEM, value)
            elif key == "sapling":
                return (SAPLING_ITEM, value)
            elif key == "transparent":
                # TODO: The existing test vector machinery doesn't distinguish. This
                # workaround is fine for now because we know what we put in the UFVK.
                return (P2PKH_ITEM, value)
            elif key == "unknown":
                return value
            else:
                assert False

        fvk_items = [fvk_item(key, value) for (key, value) in fvk_items.items()]

        # Sort in preference order.
        fvk_items.sort(key=lambda x : preference_order_key(x[0]))

        external_metadata_key = self.key.child(hardened(1), b"")

        return [
            external_metadata_key.child(hardened(0), tlv(typecode, value))
            for (typecode, value) in fvk_items
        ]

def PrivateUseMetadataKey(K, PrivateUseSubject):
    return K.child(hardened(0x7FFFFFFF), PrivateUseSubject)

def main():
    args = render_args()

    # First UFVK from the UFVK test vectors.
    ufvk = "uview1cgrqnry478ckvpr0f580t6fsahp0a5mj2e9xl7hv2d2jd4ldzy449mwwk2l9yeuts85wjls6hjtghdsy5vhhvmjdw3jxl3cxhrg3vs296a3czazrycrr5cywjhwc5c3ztfyjdhmz0exvzzeyejamyp0cr9z8f9wj0953fzht0m4lenk94t70ruwgjxag2tvp63wn9ftzhtkh20gyre3w5s24f6wlgqxnjh40gd2lxe75sf3z8h5y2x0atpxcyf9t3em4h0evvsftluruqne6w4sm066sw0qe5y8qg423grple5fftxrqyy7xmqmatv7nzd7tcjadu8f7mqz4l83jsyxy4t8pkayytyk7nrp467ds85knekdkvnd7hqkfer8mnqd7pv"

    seed = bytes(range(32))
    private_use_subject = b"Zip325TestVectors"

    test_vectors = []
    for account in [0, 1, 2, 3]:
        amk = AccountMetadataKey(seed, 133, account)
        inherent_private_use_key = PrivateUseMetadataKey(
            amk.InherentMetadataKey(),
            private_use_subject,
        )
        test_vectors.append({
            'seed':                seed,
            'account':             account,
            'ufvk':                None,
            'private_use_subject': private_use_subject,
            'private_use_keys':    [inherent_private_use_key.sk],
        })

        external_private_use_keys = [
            PrivateUseMetadataKey(key, private_use_subject).sk
            for key in amk.ImportedUfvkMetadataKey(ufvk)
        ]
        test_vectors.append({
            'seed':                seed,
            'account':             account,
            'ufvk':                ufvk,
            'private_use_subject': private_use_subject,
            'private_use_keys':    external_private_use_keys,
        })

    render_tv(
        args,
        'zip_0325',
        (
            ('seed',    '[u8; 32]'),
            ('account', 'u32'),
            ('ufvk',    'Option<&\'static str>'),
            ('private_use_subject', '&\'static [u8]'),
            ('private_use_keys',    '&\'static [[u8; 32]]'),
        ),
        test_vectors,
    )
