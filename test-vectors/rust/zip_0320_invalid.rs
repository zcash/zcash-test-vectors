// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/transparent/zip_0320_invalid.py

pub(crate) struct TestVector {
    pub(crate) network: &'static str,
    pub(crate) direction: &'static str,
    pub(crate) encoded: &'static str,
    pub(crate) reason: &'static str,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9rtaywm",
        reason: "Bech32 checksum; ZIP 320 requires Bech32m",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slskscxv8q42",
        reason: "19-byte payload",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9qqf37tgt",
        reason: "21-byte payload",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1rjug9p4l0yyxdqznjl36j3mypdm6g0ctgwjsfe3q96",
        reason: "22-byte payload: the P2PKH lead bytes were encoded with the validating key hash",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex156uev0",
        reason: "empty payload",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9qsjp53u",
        reason: "excess padding: one more 5-bit group than a 20-byte payload needs (ZIP 173 allows at most 4 padding bits)",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9pdy4pvw",
        reason: "non-zero padding: one more 5-bit group than a 20-byte payload needs, and it is not zero (ZIP 173 requires padding bits to be zero)",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1S2rt77ggv6q989lr49rkgzmh5slsksa9khdgte",
        reason: "mixed case",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgtf",
        reason: "checksum error (last character changed)",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgtb",
        reason: "character outside the Bech32 alphabet",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgtе",
        reason: "non-ASCII character (Cyrillic small letter ie, which looks like 'e')",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "texs2rt77ggv6q989lr49rkgzmh5slsksa9khdgte",
        reason: "no separator",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "tex1qqqqq",
        reason: "fewer than 6 characters after the separator",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "textestnet1s2rt77ggv6q989lr49rkgzmh5slsksa9gjvfrq",
        reason: "unknown HRP",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "textest1s2rt77ggv6q989lr49rkgzmh5slsksa90ej7wz",
        reason: "Testnet TEX address given to a Mainnet Consumer",
    },
    TestVector {
        network: "testnet",
        direction: "decode",
        encoded: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte",
        reason: "Mainnet TEX address given to a Testnet Consumer",
    },
    TestVector {
        network: "mainnet",
        direction: "decode",
        encoded: "texregtest1s2rt77ggv6q989lr49rkgzmh5slsksa990zqpk",
        reason: "unknown HRP (texregtest; ZIPs do not specify Regtest)",
    },
    TestVector {
        network: "mainnet",
        direction: "from_transparent",
        encoded: "t3WTnCGUB3Gxaq7v17mnWzPz5J3Gi8q95vs",
        reason: "P2SH address: ZIP 320 defines TEX addresses for P2PKH only",
    },
    TestVector {
        network: "testnet",
        direction: "from_transparent",
        encoded: "t2JSyEwaJujZxNpVk3WnZY2AiQXVt1MoMjB",
        reason: "Testnet P2SH address: no TEX form either",
    },
    TestVector {
        network: "mainnet",
        direction: "from_transparent",
        encoded: "tmMcWbZU8t39htCR1fQRfRSHtkW4p3Ax5Se",
        reason: "Testnet P2PKH address given to a Mainnet Consumer",
    },
    TestVector {
        network: "mainnet",
        direction: "from_transparent",
        encoded: "t1u7NFqH2CZ75ZPMf26TF3ttvn2EwEU795i",
        reason: "t1-looking address whose prefix (0x1CB9) is not a Zcash transparent prefix",
    },
    TestVector {
        network: "mainnet",
        direction: "from_transparent",
        encoded: "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yD",
        reason: "Base58Check checksum error",
    },
];
