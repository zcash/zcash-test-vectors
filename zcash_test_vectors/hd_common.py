# Common definitions for hierarchical derivation.

ZCASH_MAIN_COINTYPE = 133
ZCASH_TEST_COINTYPE = 1

ADDRESS_CONSTANTS = {
    "mainnet": {
        "coin_type": ZCASH_MAIN_COINTYPE,
        "p2pkh_lead": [0x1c, 0xb8],
        "tex_hrp": "tex",
    },
    "testnet": {
        "coin_type": ZCASH_TEST_COINTYPE,
        "p2pkh_lead": [0x1d, 0x25],
        "tex_hrp": "textest",
    },
    "regtest": {
        "coin_type": ZCASH_TEST_COINTYPE,
        "p2pkh_lead": [0x1d, 0x25],
        "tex_hrp": "texregtest",
    },
}

def hardened(i):
    assert 0 <= i and i < (1<<31)
    return i + (1<<31)
