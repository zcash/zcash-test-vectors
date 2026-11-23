// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/frost_member_backup_v2_ks02.py

pub(crate) struct TestVector {
    pub(crate) encoding: &'static str,
    pub(crate) wallet_network: &'static str,
    pub(crate) verifying_share: Option<[u8; 32]>,
    pub(crate) fvk: Option<[u8; 96]>,
    pub(crate) step: Option<u8>,
    pub(crate) reason: &'static str,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        wallet_network: "testnet",
        verifying_share: Some([
            0xcb, 0x57, 0xb7, 0x9d, 0xf3, 0xa4, 0x54, 0x2e, 0xe3, 0x7b, 0xd2, 0x68, 0x73, 0x13, 0x9a, 0x6a, 0xe4, 0xda, 0xc8, 0x94, 0x54, 0xf9, 0x85, 0x8e, 0x12, 0xc4, 0xc8, 0xaa, 0xf8, 0xb8, 0x54, 0x2e
        ]),
        fvk: Some([
            0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        step: None,
        reason: "valid, Testnet string on a Testnet wallet, the wallet knows the member's verifying share",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: Some([
            0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        step: None,
        reason: "valid, verifying shares not known",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrq8ryw2fa6tmnacw9ljzrdstll3842ret8azwkugehl08fj3vhtyzs870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gum07jty",
        wallet_network: "testnet",
        verifying_share: Some([
            0x64, 0xef, 0x67, 0xce, 0x85, 0x25, 0xb8, 0x76, 0x2e, 0x1f, 0xd2, 0x23, 0xc0, 0x82, 0xfd, 0x93, 0x3c, 0x82, 0xe0, 0x0d, 0x2a, 0xf7, 0x6c, 0xcb, 0x01, 0x74, 0x7a, 0x96, 0xda, 0xda, 0x6d, 0xbd
        ]),
        fvk: Some([
            0x59, 0x28, 0x8e, 0x1d, 0x1e, 0x2a, 0xb7, 0xce, 0xcc, 0x17, 0xe4, 0xd2, 0x19, 0x01, 0xaf, 0xd2, 0x62, 0xbb, 0x18, 0x1b, 0x8d, 0x9d, 0x71, 0x70, 0xb1, 0x84, 0x1c, 0x5e, 0x3c, 0x28, 0x76, 0x1e, 0xfa, 0xc7, 0x0d, 0xad, 0x5c, 0x6a, 0x07, 0x84, 0xb9, 0xab, 0x6e, 0xf7, 0xe5, 0xb0, 0xfe, 0x4d, 0xeb, 0x2c, 0x8b, 0x9f, 0x3c, 0xfe, 0x93, 0x26, 0x29, 0x14, 0x06, 0x81, 0xe7, 0x2c, 0xa9, 0x3f, 0x44, 0xff, 0xd1, 0x50, 0x3d, 0xf9, 0x74, 0x4a, 0xd3, 0xdb, 0xc3, 0x34, 0xad, 0x75, 0x74, 0x15, 0x57, 0xe1, 0xa2, 0x6d, 0xf6, 0xd4, 0xb0, 0x0e, 0x8e, 0x34, 0x53, 0x4a, 0x6a, 0x23, 0x9d, 0x1c
        ]),
        step: None,
        reason: "valid, full identifier",
    },
    TestVector {
        encoding: "zkfrost1qgpqqqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgtdzymqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qhkpylj",
        wallet_network: "mainnet",
        verifying_share: Some([
            0xcb, 0x57, 0xb7, 0x9d, 0xf3, 0xa4, 0x54, 0x2e, 0xe3, 0x7b, 0xd2, 0x68, 0x73, 0x13, 0x9a, 0x6a, 0xe4, 0xda, 0xc8, 0x94, 0x54, 0xf9, 0x85, 0x8e, 0x12, 0xc4, 0xc8, 0xaa, 0xf8, 0xb8, 0x54, 0x2e
        ]),
        fvk: Some([
            0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        step: None,
        reason: "valid, Mainnet string on a Mainnet wallet",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqhks89t7ye3tfstq0dxq7zwhzunm8apvr3pjw9u7ngytd4cerxx85zy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62quap4y3",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: Some([
            0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        step: None,
        reason: "signing share with the wrong sign, verifying share not known: passes the restore, fails at first signing",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u64wc46t",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(1),
        reason: "step 1: the string does not decode (138-byte payload, decoding rule 5)",
    },
    TestVector {
        encoding: "zkfrost1qgpqyqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qavpltg",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(1),
        reason: "step 1: the string does not decode (network byte 0x02, decoding rule 4): no wallet restores it",
    },
    TestVector {
        encoding: "zkfrost1qgpqqqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgtdzymqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qhkpylj",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(2),
        reason: "step 2: Mainnet string, Testnet wallet",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        wallet_network: "mainnet",
        verifying_share: None,
        fvk: None,
        step: Some(2),
        reason: "step 2: Testnet string, Mainnet wallet",
    },
    TestVector {
        encoding: "zkfrost1qgpqqqsrqqqszqqqqqs7k35vmk5fgz0unprzyqqqqqqqqqqqqqqqqqqqqqqqqsyzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qpfac7u",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(2),
        reason: "step 2: two steps: Mainnet string on a Testnet wallet AND a non-canonical signing share; the network is first",
    },
    TestVector {
        encoding: "zkfrost1qgpqqqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qzfamfg",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(2),
        reason: "step 2: two steps: Mainnet string on a Testnet wallet AND a viewing key whose ak is all zero; the network is first",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqszqqqqqs7k35vmk5fgz0unprzyqqqqqqqqqqqqqqqqqqqqqqqqsyzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qgfvkju",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(3),
        reason: "step 3: non-canonical signing share (the Pallas scalar modulus)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqszqqqqqs7k35vmk5fgz0unprzyqqqqqqqqqqqqqqqqqqqqqqqqsyzy9zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q9vmwgu",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(3),
        reason: "step 3: two steps: a non-canonical signing share AND a viewing key whose ak is all zero; the share is first",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v74enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qwlmajk",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(4),
        reason: "step 4: viewing key whose ak has the sign bit set (the raw odd-y group key)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qtfv49g",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(4),
        reason: "step 4: viewing key whose ak is all zero (the identity)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q798pjx",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(4),
        reason: "step 4: viewing key whose ak is not the x-coordinate of a Pallas point",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73eqyqqqq8dxqkejxlefsylexzxygqqqqqqqqqqqqqqqqqqqqqqqpq90y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q858ncz",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(4),
        reason: "step 4: viewing key whose nk is the Pallas base field modulus (non-canonical)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku5qzqqqqqs7k35vmk5fgz0unprzyqqqqqqqqqqqqqqqqqqqqqqqqsqkpvzzz",
        wallet_network: "testnet",
        verifying_share: None,
        fvk: None,
        step: Some(4),
        reason: "step 4: viewing key whose rivk is the Pallas scalar modulus (non-canonical)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqhks89t7ye3tfstq0dxq7zwhzunm8apvr3pjw9u7ngytd4cerxx85zy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62quap4y3",
        wallet_network: "testnet",
        verifying_share: Some([
            0xcb, 0x57, 0xb7, 0x9d, 0xf3, 0xa4, 0x54, 0x2e, 0xe3, 0x7b, 0xd2, 0x68, 0x73, 0x13, 0x9a, 0x6a, 0xe4, 0xda, 0xc8, 0x94, 0x54, 0xf9, 0x85, 0x8e, 0x12, 0xc4, 0xc8, 0xaa, 0xf8, 0xb8, 0x54, 0x2e
        ]),
        fvk: None,
        step: Some(5),
        reason: "step 5: signing share with the wrong sign, verifying share known",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        wallet_network: "testnet",
        verifying_share: Some([
            0xab, 0xb1, 0xe2, 0x6f, 0xeb, 0x1a, 0x12, 0x5a, 0x14, 0x72, 0xfe, 0x0c, 0x85, 0xb9, 0xb4, 0x37, 0x6b, 0xa1, 0x7b, 0xfd, 0xfa, 0x11, 0x79, 0x9e, 0x5d, 0xec, 0x5e, 0xcd, 0x8a, 0xfe, 0x94, 0x19
        ]),
        fvk: None,
        step: Some(5),
        reason: "step 5: member 1's string checked against member 2's verifying share",
    },
];
