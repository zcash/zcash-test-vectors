# Common definitions for hierarchical derivation.

ZCASH_MAIN_COINTYPE = 133

def hardened(i):
    assert 0 <= i and i < (1<<31)
    return i + (1<<31)
