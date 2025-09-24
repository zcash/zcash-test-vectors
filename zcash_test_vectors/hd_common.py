# Common definitions for hierarchical derivation.

ZCASH_MAIN_COINTYPE = 133
ZCASH_TEST_COINTYPE = 1

ADDRESS_CONSTANTS = {
    "mainnet": {
        "coin_type": ZCASH_MAIN_COINTYPE,
        "p2pkh_lead": [0x1c, 0xb8],
        "p2sh_lead": [0x1c, 0xbd],
        "xpub_lead": [0x04, 0x88, 0xb2, 0x1e],
        "xprv_lead": [0x04, 0x88, 0xad, 0xe4],
        "tex_hrp": "tex",
    },
    "testnet": {
        "coin_type": ZCASH_TEST_COINTYPE,
        "p2pkh_lead": [0x1d, 0x25],
        "p2sh_lead": [0x1c, 0xba],
        "xpub_lead": [0x04, 0x35, 0x87, 0xcf],
        "xprv_lead": [0x04, 0x35, 0x83, 0x94],
        "tex_hrp": "textest",
    },
    "regtest": {
        "coin_type": ZCASH_TEST_COINTYPE,
        "p2pkh_lead": [0x1d, 0x25],
        "p2sh_lead": [0x1c, 0xba],
        "xpub_lead": [0x04, 0x35, 0x87, 0xcf],
        "xprv_lead": [0x04, 0x35, 0x83, 0x94],
        "tex_hrp": "texregtest",
    },
}

def hardened(i):
    assert 0 <= i and i < (1<<31)
    return i + (1<<31)
