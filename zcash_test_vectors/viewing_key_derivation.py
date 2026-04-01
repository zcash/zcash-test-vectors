"""Shared derivation of Sapling and Orchard viewing key encodings for unified types."""

import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .hd_common import hardened
from .orchard import key_components as orchard_key_components
from .sapling import zip32 as sapling_zip32


def derive_sapling_fvk(s_coin_key, account):
    """Derive Sapling FVK encoding: ak || nk || ovk || dk (128 bytes).

    Returns (fvk_bytes, extended_fvk, account_key).
    """
    account_key = s_coin_key.child(hardened(account))
    fvk = account_key.to_extended_fvk()
    fvk_bytes = b"".join([
        bytes(fvk.ak()),
        bytes(fvk.nk()),
        fvk.ovk(),
        fvk.dk()
    ])
    return (fvk_bytes, fvk, account_key)


def derive_sapling_ivk(s_coin_key, account):
    """Derive Sapling IVK encoding: dk || ivk (64 bytes).

    Returns (ivk_bytes, extended_fvk, account_key).
    """
    account_key = s_coin_key.child(hardened(account))
    fvk = account_key.to_extended_fvk()
    ivk_bytes = fvk.dk() + bytes(fvk.ivk())
    return (ivk_bytes, fvk, account_key)


def derive_orchard_fvk(o_coin_key, account):
    """Derive Orchard FVK encoding: ak || nk || rivk (96 bytes).

    Returns (fvk_bytes, full_viewing_key).
    """
    account_key = o_coin_key.child(hardened(account))
    fvk = orchard_key_components.FullViewingKey.from_spending_key(account_key)
    fvk_bytes = b"".join([
        bytes(fvk.ak),
        bytes(fvk.nk),
        bytes(fvk.rivk)
    ])
    return (fvk_bytes, fvk)


def derive_orchard_ivk(o_coin_key, account):
    """Derive Orchard IVK encoding: dk || ivk (64 bytes).

    Returns (ivk_bytes, full_viewing_key).
    """
    account_key = o_coin_key.child(hardened(account))
    fvk = orchard_key_components.FullViewingKey.from_spending_key(account_key)
    ivk_bytes = fvk.dk + bytes(fvk.ivk())
    return (ivk_bytes, fvk)
