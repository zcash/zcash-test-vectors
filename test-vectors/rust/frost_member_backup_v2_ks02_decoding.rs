// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/frost_member_backup_v2_ks02.py

pub(crate) struct TestVector {
    pub(crate) encoding: &'static str,
    pub(crate) payload: Option<&'static [u8]>,
    pub(crate) rule: Option<u8>,
    pub(crate) reason: &'static str,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x00, 0x01, 0x86, 0xbf, 0x1a, 0xa0, 0x97, 0x52, 0x99, 0x5b, 0x85, 0x8a, 0xc1, 0x05, 0x3a, 0x23, 0x81, 0x58, 0x13, 0x02, 0xf4, 0xf8, 0xef, 0x36, 0x3a, 0x18, 0x59, 0x7d, 0xd2, 0x4a, 0x39, 0xb9, 0x9c, 0x21, 0x82, 0x21, 0x44, 0x00, 0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        rule: None,
        reason: "valid, lowercase (group A member 1, Testnet)",
    },
    TestVector {
        encoding: "ZKFROST1QGPQZQSRQQQCD0C65ZT49X2MSK9VZPF6YWQ4SYCZ7NUW7D36RPVHM5J28XUECGVZY9ZQQ7V3NXQYFPM8PQJA8ALHQYSUCKRVLQ8VTHQ7N5H7A4TCRWY8V73ENM5TEFR9NGA2NQYK9XJSLAHTJVEARLSZ934MXM05H8C4SJKZKU590Y25QKWUZNM7E6M9FMXVD0V40ZN8UG9UTKS03YVD62AGU00U62QXVMDLG",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x00, 0x01, 0x86, 0xbf, 0x1a, 0xa0, 0x97, 0x52, 0x99, 0x5b, 0x85, 0x8a, 0xc1, 0x05, 0x3a, 0x23, 0x81, 0x58, 0x13, 0x02, 0xf4, 0xf8, 0xef, 0x36, 0x3a, 0x18, 0x59, 0x7d, 0xd2, 0x4a, 0x39, 0xb9, 0x9c, 0x21, 0x82, 0x21, 0x44, 0x00, 0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        rule: None,
        reason: "valid, uppercase",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrq8ryw2fa6tmnacw9ljzrdstll3842ret8azwkugehl08fj3vhtyzs870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gum07jty",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x01, 0xc6, 0x47, 0x29, 0x3d, 0xd2, 0xf7, 0x3e, 0xe1, 0xc5, 0xfc, 0x84, 0x36, 0xc1, 0x7f, 0xfc, 0x4f, 0x55, 0x0f, 0x2b, 0x3f, 0x44, 0xeb, 0x71, 0x19, 0xbf, 0xde, 0x74, 0xca, 0x2c, 0xba, 0xc8, 0x28, 0x1f, 0xcf, 0x1e, 0x1c, 0xa3, 0xe8, 0x6a, 0x98, 0xaf, 0x46, 0x99, 0x0e, 0x8e, 0xc6, 0x01, 0xb8, 0x5a, 0x10, 0xbb, 0x61, 0x87, 0xdf, 0x8e, 0x6b, 0x5f, 0x17, 0x3e, 0x86, 0x0a, 0xca, 0x87, 0x24, 0x82, 0x21, 0x44, 0x00, 0x59, 0x28, 0x8e, 0x1d, 0x1e, 0x2a, 0xb7, 0xce, 0xcc, 0x17, 0xe4, 0xd2, 0x19, 0x01, 0xaf, 0xd2, 0x62, 0xbb, 0x18, 0x1b, 0x8d, 0x9d, 0x71, 0x70, 0xb1, 0x84, 0x1c, 0x5e, 0x3c, 0x28, 0x76, 0x1e, 0xfa, 0xc7, 0x0d, 0xad, 0x5c, 0x6a, 0x07, 0x84, 0xb9, 0xab, 0x6e, 0xf7, 0xe5, 0xb0, 0xfe, 0x4d, 0xeb, 0x2c, 0x8b, 0x9f, 0x3c, 0xfe, 0x93, 0x26, 0x29, 0x14, 0x06, 0x81, 0xe7, 0x2c, 0xa9, 0x3f, 0x44, 0xff, 0xd1, 0x50, 0x3d, 0xf9, 0x74, 0x4a, 0xd3, 0xdb, 0xc3, 0x34, 0xad, 0x75, 0x74, 0x15, 0x57, 0xe1, 0xa2, 0x6d, 0xf6, 0xd4, 0xb0, 0x0e, 0x8e, 0x34, 0x53, 0x4a, 0x6a, 0x23, 0x9d, 0x1c
        ]),
        rule: None,
        reason: "valid, full identifier (group B member 1, Testnet)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecggqqqqqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qtur8e9",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x00, 0x01, 0x86, 0xbf, 0x1a, 0xa0, 0x97, 0x52, 0x99, 0x5b, 0x85, 0x8a, 0xc1, 0x05, 0x3a, 0x23, 0x81, 0x58, 0x13, 0x02, 0xf4, 0xf8, 0xef, 0x36, 0x3a, 0x18, 0x59, 0x7d, 0xd2, 0x4a, 0x39, 0xb9, 0x9c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        rule: None,
        reason: "valid, birthday height 0 (unknown)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqzgd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q5ulfdk",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x00, 0x04, 0x86, 0xbf, 0x1a, 0xa0, 0x97, 0x52, 0x99, 0x5b, 0x85, 0x8a, 0xc1, 0x05, 0x3a, 0x23, 0x81, 0x58, 0x13, 0x02, 0xf4, 0xf8, 0xef, 0x36, 0x3a, 0x18, 0x59, 0x7d, 0xd2, 0x4a, 0x39, 0xb9, 0x9c, 0x21, 0x82, 0x21, 0x44, 0x00, 0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        rule: None,
        reason: "decodes: identifier 4 greater than n = 3 is not checked in version 2",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqrlcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62quy0v0u",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x00, 0xff, 0x86, 0xbf, 0x1a, 0xa0, 0x97, 0x52, 0x99, 0x5b, 0x85, 0x8a, 0xc1, 0x05, 0x3a, 0x23, 0x81, 0x58, 0x13, 0x02, 0xf4, 0xf8, 0xef, 0x36, 0x3a, 0x18, 0x59, 0x7d, 0xd2, 0x4a, 0x39, 0xb9, 0x9c, 0x21, 0x82, 0x21, 0x44, 0x00, 0x79, 0x91, 0x99, 0x80, 0x44, 0x87, 0x67, 0x08, 0x25, 0xd3, 0xf7, 0xf7, 0x01, 0x21, 0xcc, 0x58, 0x6c, 0xf8, 0x0e, 0xc5, 0xdc, 0x1e, 0x9d, 0x2f, 0xee, 0xd5, 0x78, 0x1b, 0x88, 0x76, 0x7a, 0x39, 0x9e, 0xe8, 0xbc, 0xa4, 0x65, 0x9a, 0x3a, 0xa9, 0x80, 0x96, 0x29, 0xa5, 0x0f, 0xf6, 0xeb, 0x93, 0x33, 0xd1, 0xfe, 0x02, 0x2c, 0x6b, 0xb3, 0x6d, 0xf4, 0xb9, 0xf1, 0x58, 0x4a, 0xc2, 0xb7, 0x28, 0x57, 0x91, 0x54, 0x05, 0x9d, 0xc1, 0x4f, 0x7e, 0xce, 0xb6, 0x54, 0xec, 0xcc, 0x6b, 0xd9, 0x57, 0x8a, 0x67, 0xe2, 0x0b, 0xc5, 0xda, 0x0f, 0x89, 0x18, 0xdd, 0x2b, 0xa8, 0xe3, 0xdf, 0xcd, 0x28
        ]),
        rule: None,
        reason: "decodes: short identifier 255, the largest the short form holds",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqyqqzqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gutpdswx",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xcf, 0x1e, 0x1c, 0xa3, 0xe8, 0x6a, 0x98, 0xaf, 0x46, 0x99, 0x0e, 0x8e, 0xc6, 0x01, 0xb8, 0x5a, 0x10, 0xbb, 0x61, 0x87, 0xdf, 0x8e, 0x6b, 0x5f, 0x17, 0x3e, 0x86, 0x0a, 0xca, 0x87, 0x24, 0x82, 0x21, 0x44, 0x00, 0x59, 0x28, 0x8e, 0x1d, 0x1e, 0x2a, 0xb7, 0xce, 0xcc, 0x17, 0xe4, 0xd2, 0x19, 0x01, 0xaf, 0xd2, 0x62, 0xbb, 0x18, 0x1b, 0x8d, 0x9d, 0x71, 0x70, 0xb1, 0x84, 0x1c, 0x5e, 0x3c, 0x28, 0x76, 0x1e, 0xfa, 0xc7, 0x0d, 0xad, 0x5c, 0x6a, 0x07, 0x84, 0xb9, 0xab, 0x6e, 0xf7, 0xe5, 0xb0, 0xfe, 0x4d, 0xeb, 0x2c, 0x8b, 0x9f, 0x3c, 0xfe, 0x93, 0x26, 0x29, 0x14, 0x06, 0x81, 0xe7, 0x2c, 0xa9, 0x3f, 0x44, 0xff, 0xd1, 0x50, 0x3d, 0xf9, 0x74, 0x4a, 0xd3, 0xdb, 0xc3, 0x34, 0xad, 0x75, 0x74, 0x15, 0x57, 0xe1, 0xa2, 0x6d, 0xf6, 0xd4, 0xb0, 0x0e, 0x8e, 0x34, 0x53, 0x4a, 0x6a, 0x23, 0x9d, 0x1c
        ]),
        rule: None,
        reason: "decodes: full identifier 256, the smallest integer the short form cannot hold",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqyqqqqqqy845drxa4z2qnlycgc3qqqqqqqqqqqqqqqqqqqqqqqqyq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gu9q582j",
        payload: Some(&[
            0x02, 0x02, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c, 0xdd, 0xa8, 0x94, 0x09, 0xfc, 0x98, 0x46, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x1f, 0xcf, 0x1e, 0x1c, 0xa3, 0xe8, 0x6a, 0x98, 0xaf, 0x46, 0x99, 0x0e, 0x8e, 0xc6, 0x01, 0xb8, 0x5a, 0x10, 0xbb, 0x61, 0x87, 0xdf, 0x8e, 0x6b, 0x5f, 0x17, 0x3e, 0x86, 0x0a, 0xca, 0x87, 0x24, 0x82, 0x21, 0x44, 0x00, 0x59, 0x28, 0x8e, 0x1d, 0x1e, 0x2a, 0xb7, 0xce, 0xcc, 0x17, 0xe4, 0xd2, 0x19, 0x01, 0xaf, 0xd2, 0x62, 0xbb, 0x18, 0x1b, 0x8d, 0x9d, 0x71, 0x70, 0xb1, 0x84, 0x1c, 0x5e, 0x3c, 0x28, 0x76, 0x1e, 0xfa, 0xc7, 0x0d, 0xad, 0x5c, 0x6a, 0x07, 0x84, 0xb9, 0xab, 0x6e, 0xf7, 0xe5, 0xb0, 0xfe, 0x4d, 0xeb, 0x2c, 0x8b, 0x9f, 0x3c, 0xfe, 0x93, 0x26, 0x29, 0x14, 0x06, 0x81, 0xe7, 0x2c, 0xa9, 0x3f, 0x44, 0xff, 0xd1, 0x50, 0x3d, 0xf9, 0x74, 0x4a, 0xd3, 0xdb, 0xc3, 0x34, 0xad, 0x75, 0x74, 0x15, 0x57, 0xe1, 0xa2, 0x6d, 0xf6, 0xd4, 0xb0, 0x0e, 0x8e, 0x34, 0x53, 0x4a, 0x6a, 0x23, 0x9d, 0x1c
        ]),
        rule: None,
        reason: "decodes: full identifier q - 1, the largest canonical scalar",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlq",
        payload: None,
        rule: Some(1),
        reason: "rule 1: invalid checksum",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qnstp62",
        payload: None,
        rule: Some(1),
        reason: "rule 1: Bech32 checksum instead of Bech32m",
    },
    TestVector {
        encoding: "ZKFROST1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        payload: None,
        rule: Some(1),
        reason: "rule 1: mixed case (upper-case prefix, lower-case rest)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqQcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qxvmdlg",
        payload: None,
        rule: Some(1),
        reason: "rule 1: mixed case in the data part",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62pm60cz6",
        payload: None,
        rule: Some(1),
        reason: "rule 1: non-zero padding bit (short form, 3 leftover bits)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrq8ryw2fa6tmnacw9ljzrdstll3842ret8azwkugehl08fj3vhtyzs870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88guqyfftqf",
        payload: None,
        rule: Some(1),
        reason: "rule 1: more than 4 padding bits (full form plus one character, 5 leftover bits)",
    },
    TestVector {
        encoding: "zkfros1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62ppses8d",
        payload: None,
        rule: Some(1),
        reason: "rule 1: two rules: non-zero padding bit AND wrong prefix `zkfros`; the padding is first in order",
    },
    TestVector {
        encoding: "zkfros1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62quxd96q",
        payload: None,
        rule: Some(1),
        reason: "rule 1: two rules: invalid checksum AND wrong prefix `zkfros`; the checksum is first in order",
    },
    TestVector {
        encoding: "zkfros1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62quxd96l",
        payload: None,
        rule: Some(2),
        reason: "rule 2: prefix `zkfros` instead of `zkfrost`",
    },
    TestVector {
        encoding: "zkfrostx1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q0ekn45",
        payload: None,
        rule: Some(2),
        reason: "rule 2: prefix `zkfrostx`",
    },
    TestVector {
        encoding: "zkfros1qvpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qa5nfkn",
        payload: None,
        rule: Some(2),
        reason: "rule 2: two rules: wrong prefix AND version 3; the prefix is first in order",
    },
    TestVector {
        encoding: "zkfrost1qypqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q9nsetu",
        payload: None,
        rule: Some(3),
        reason: "rule 3: version byte 0x01 on a version 2 payload; version 1's checks also reject it, for its length (139 bytes, not 68)",
    },
    TestVector {
        encoding: "zkfrost1qypqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7umgp76t",
        payload: None,
        rule: Some(3),
        reason: "rule 3: a 68-byte payload starting 0x01: the version is checked before the length; version 1's checks also reject it, for t < 2 (member 2, threshold 1 of 2)",
    },
    TestVector {
        encoding: "zkfrost1qvpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q879pny",
        payload: None,
        rule: Some(3),
        reason: "rule 3: version 3",
    },
    TestVector {
        encoding: "zkfrost1qvpszqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u6nmdnhw",
        payload: None,
        rule: Some(3),
        reason: "rule 3: three rules: version 3, key source 0x03 AND a 138-byte payload; the version is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpszqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q7eap8t",
        payload: None,
        rule: Some(4),
        reason: "rule 4: key source 0x03",
    },
    TestVector {
        encoding: "zkfrost1qgpqyqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qavpltg",
        payload: None,
        rule: Some(4),
        reason: "rule 4: network byte 0x02: only 0x00 Mainnet and 0x01 Testnet are values (no Regtest value)",
    },
    TestVector {
        encoding: "zkfrost1qgpqxqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q5vs38g",
        payload: None,
        rule: Some(4),
        reason: "rule 4: network 0x03",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqgqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q744zu4",
        payload: None,
        rule: Some(4),
        reason: "rule 4: identifier form 0x02",
    },
    TestVector {
        encoding: "zkfrost1qgpszqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u645cs3s",
        payload: None,
        rule: Some(4),
        reason: "rule 4: two rules: key source 0x03 AND a 138-byte payload; the unknown value is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpszqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qqqkv5ap",
        payload: None,
        rule: Some(4),
        reason: "rule 4: two rules: key source 0x03 AND a 140-byte payload (a length no layout has); the unknown value is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqxqgrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qluqqwz",
        payload: None,
        rule: Some(4),
        reason: "rule 4: two rules: network 0x03 AND threshold 1; the unknown value is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqgqgd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qwscssx",
        payload: None,
        rule: Some(4),
        reason: "rule 4: two rules: identifier form 0x02 AND identifier byte 0; the unknown value is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpsxqsrqgqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62q5qcjuk",
        payload: None,
        rule: Some(4),
        reason: "rule 4: key source 0x03, network 0x03 and identifier form 0x02 together",
    },
    TestVector {
        encoding: "zkfrost1qgrsd63gau",
        payload: None,
        rule: Some(4),
        reason: "rule 4: payload `02 07`: key source 7 is present and unknown, and wins over the length",
    },
    TestVector {
        encoding: "zkfrost1jgy4p0",
        payload: None,
        rule: Some(5),
        reason: "rule 5: empty payload: it ends before the version, so rule 3 has nothing to check",
    },
    TestVector {
        encoding: "zkfrost1qgpm7xe9",
        payload: None,
        rule: Some(5),
        reason: "rule 5: payload `02` alone: it ends before the key source, so rule 4 has nothing to check",
    },
    TestVector {
        encoding: "zkfrost1qgpqzfud6dz",
        payload: None,
        rule: Some(5),
        reason: "rule 5: payload `02 02 01`: known key source and network, but it ends before the identifier form",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqqkj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj6tfd95kj60xgenqzysanssfwn7lmszgwvtpk0srk9ms0f6tlw64uphzrk0guea69u53je5w4fsztznfg07m4exv73lcpzc6andh6tnu2cftptw2zhj92qt8wpfalvadj5anxxhk2h3fn7yz79mg8cjxxa9w5w8h7d9q9znd7m",
        payload: None,
        rule: Some(5),
        reason: "rule 5: key source 0x02 with a 32-byte sk field before the viewing key (171 bytes)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73e67mknw",
        payload: None,
        rule: Some(5),
        reason: "rule 5: key source 0x02 with a 32-byte ak instead of the 96-byte viewing key (75 bytes)",
    },
    TestVector {
        encoding: "zkfrost1qgqszqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qytalns",
        payload: None,
        rule: Some(5),
        reason: "rule 5: key source 0x01 on a 139-byte payload with no sk",
    },
    TestVector {
        encoding: "zkfrost1qgqqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qu7mntn",
        payload: None,
        rule: Some(5),
        reason: "rule 5: key source 0x00 on a 139-byte payload with no sk",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u64wc46t",
        payload: None,
        rule: Some(5),
        reason: "rule 5: payload of 138 bytes for key source 0x02, short form",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qq79vc40",
        payload: None,
        rule: Some(5),
        reason: "rule 5: payload of 140 bytes for key source 0x02, short form",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqgrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u622a9fe",
        payload: None,
        rule: Some(5),
        reason: "rule 5: two rules: 138 bytes AND threshold 1; the length is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqgd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u6tf87wk",
        payload: None,
        rule: Some(5),
        reason: "rule 5: two rules: 138 bytes AND identifier 0; the length is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqgrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qdutukz",
        payload: None,
        rule: Some(6),
        reason: "rule 6: threshold 1",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqqrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qntun3y",
        payload: None,
        rule: Some(6),
        reason: "rule 6: threshold 0",
    },
    TestVector {
        encoding: "zkfrost1qgpqzpqrqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qnmu0kz",
        payload: None,
        rule: Some(6),
        reason: "rule 6: threshold 4 greater than n = 3",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsqqqqcd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qeg45ux",
        payload: None,
        rule: Some(6),
        reason: "rule 6: group size 0",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqgrqqqgd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qaexw63",
        payload: None,
        rule: Some(6),
        reason: "rule 6: two rules: threshold 1 AND short identifier 0; the threshold is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqzpqrqyqsqqqqy845drxa4z2qnlycgc3qqqqqqqqqqqqqqqqqqqqqqqqyq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88guyna6pa",
        payload: None,
        rule: Some(6),
        reason: "rule 6: two rules: threshold 4 > n = 3 AND a non-canonical full identifier; the threshold is first in order",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqqqgd0c65zt49x2msk9vzpf6ywq4sycz7nuw7d36rpvhm5j28xuecgvzy9zqq7v3nxqyfpm8pqja8alhqysuckrvlq8vthq7n5h7a4tcrwy8v73enm5tefr9nga2nqyk9xjslahtjvearlsz934mxm05h8c4sjkzku590y25qkwuznm7e6m9fmxvd0v40zn8ug9utks03yvd62agu00u62qkfklnm",
        payload: None,
        rule: Some(7),
        reason: "rule 7: short identifier 0",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqyqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gugsvt9v",
        payload: None,
        rule: Some(7),
        reason: "rule 7: full identifier 1, which the short form holds",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrq8lsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88guyktu9h",
        payload: None,
        rule: Some(7),
        reason: "rule 7: full identifier 255, which the short form holds",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88gufhnf8l",
        payload: None,
        rule: Some(7),
        reason: "rule 7: full identifier 0",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrqyqsqqqqy845drxa4z2qnlycgc3qqqqqqqqqqqqqqqqqqqqqqqqyq870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88guy8t9gp",
        payload: None,
        rule: Some(7),
        reason: "rule 7: full identifier equal to the Pallas scalar modulus (non-canonical)",
    },
    TestVector {
        encoding: "zkfrost1qgpqzqsrq8llllllllllllllllllllllllllllllllllllllllllllllllll7870rcw286r2nzh5dxgw3mrqrwz6zzakrp7l3e4479e7sc9v4peysgs5gqze9z8p6832kl8vc9ly6gvsrt7jv2a3sxudn4chpvvyr30rc2rkrmavwrddt34q0p9e4dh00edslex7ktytnu70ayex9y2qdq089j5n738l69grm7t5ftfahse5446hg92hux3xmak5kq8gudznff4z88guq9ugcq",
        payload: None,
        rule: Some(7),
        reason: "rule 7: full identifier of 32 bytes 0xff (non-canonical)",
    },
];
