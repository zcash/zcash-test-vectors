// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/frost_member_backup.py

pub(crate) struct TestVector {
    pub(crate) encoding: &'static str,
    pub(crate) payload: Option<[u8; 68]>,
    pub(crate) reason: &'static str,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        payload: Some([
            0x01, 0x01, 0x02, 0x03, 0x2c, 0xaa, 0xa5, 0xad, 0xfc, 0xad, 0x8a, 0xc0, 0xbb, 0x8c, 0x50, 0xdc, 0xdb, 0xbc, 0x1e, 0x95, 0x48, 0x25, 0xbe, 0x40, 0x3f, 0x97, 0xf4, 0x4b, 0xc1, 0xd6, 0xc5, 0x43, 0xe1, 0x5d, 0x4f, 0x3b, 0x24, 0xcf, 0x13, 0xc7, 0x24, 0x75, 0x88, 0x86, 0x04, 0x8e, 0x05, 0x83, 0x4d, 0x5d, 0x0a, 0x64, 0x4e, 0x9c, 0x8e, 0x15, 0x5d, 0x7e, 0x0b, 0xac, 0x3f, 0x25, 0x58, 0x6b, 0x6c, 0xaa, 0x11, 0xc3
        ]),
        reason: "valid, lowercase",
    },
    TestVector {
        encoding: "ZKFROST1QYQSYQEV42J6ML9D3TQTHRZSMNDMC854FQJMUSPLJL6YHSWKC4P7ZH208VJV7Y78Y36C3PSY3CZCXN2APFJYA8YWZ4WHUZAV8UJ4S6MV4GGUXM4KTP7",
        payload: Some([
            0x01, 0x01, 0x02, 0x03, 0x2c, 0xaa, 0xa5, 0xad, 0xfc, 0xad, 0x8a, 0xc0, 0xbb, 0x8c, 0x50, 0xdc, 0xdb, 0xbc, 0x1e, 0x95, 0x48, 0x25, 0xbe, 0x40, 0x3f, 0x97, 0xf4, 0x4b, 0xc1, 0xd6, 0xc5, 0x43, 0xe1, 0x5d, 0x4f, 0x3b, 0x24, 0xcf, 0x13, 0xc7, 0x24, 0x75, 0x88, 0x86, 0x04, 0x8e, 0x05, 0x83, 0x4d, 0x5d, 0x0a, 0x64, 0x4e, 0x9c, 0x8e, 0x15, 0x5d, 0x7e, 0x0b, 0xac, 0x3f, 0x25, 0x58, 0x6b, 0x6c, 0xaa, 0x11, 0xc3
        ]),
        reason: "valid, uppercase",
    },
    TestVector {
        encoding: "zkfros1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxj5zv7a",
        payload: None,
        reason: "wrong human-readable part",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktpq",
        payload: None,
        reason: "invalid checksum",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxwfx8yu",
        payload: None,
        reason: "Bech32 checksum instead of Bech32m",
    },
    TestVector {
        encoding: "ZKFROST1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        payload: None,
        reason: "mixed case",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42J6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        payload: None,
        reason: "mixed case in the data part",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4ggu8xrz7uv",
        payload: None,
        reason: "non-zero padding bit",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxq7psp6f",
        payload: None,
        reason: "more than 4 padding bits",
    },
    TestVector {
        encoding: "zkfrost1qqqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxvn9wls",
        payload: None,
        reason: "version 0",
    },
    TestVector {
        encoding: "zkfrost1qgqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxtl2y2v",
        payload: None,
        reason: "version 2",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4ggs2jtyl7",
        payload: None,
        reason: "payload of 67 bytes",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxqqcmvflp",
        payload: None,
        reason: "payload of 69 bytes",
    },
    TestVector {
        encoding: "zkfrost1qyqqyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxxh50p3",
        payload: None,
        reason: "identifier 0",
    },
    TestVector {
        encoding: "zkfrost1qyzqyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4ggux2ef5a0",
        payload: None,
        reason: "identifier greater than n",
    },
    TestVector {
        encoding: "zkfrost1qyqsqqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxnxkmvq",
        payload: None,
        reason: "threshold 0",
    },
    TestVector {
        encoding: "zkfrost1qyqszqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxhmkn70",
        payload: None,
        reason: "threshold 1",
    },
    TestVector {
        encoding: "zkfrost1qyqsgqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxrfkjk4",
        payload: None,
        reason: "threshold greater than n",
    },
    TestVector {
        encoding: "zkfrost1qyqszqpv42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4ggux8e6jef",
        payload: None,
        reason: "group size 0",
    },
];
