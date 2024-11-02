        struct TestVector {
            sk: [u8; 32],
            c: [u8; 32],
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0032_arbitrary.py
        let test_vectors = vec![
            TestVector {
                sk: [
                    0xe9, 0xda, 0x88, 0x06, 0x40, 0x9d, 0xc3, 0xc3, 0xeb, 0xd1, 0xfc, 0x2a, 0x71, 0xc8, 0x79, 0xc1, 0x3d, 0xd7, 0xaa, 0x93, 0xed, 0xe8, 0x03, 0xbf, 0x1a, 0x83, 0x41, 0x4b, 0x9d, 0x3b, 0x15, 0x8a
                ],
                c: [
                    0x65, 0xa7, 0x48, 0xf2, 0x90, 0x5f, 0x7a, 0x8a, 0xab, 0x9f, 0x3d, 0x02, 0xf1, 0xb2, 0x6c, 0x3d, 0x65, 0xc8, 0x29, 0x94, 0xce, 0x59, 0xa0, 0x86, 0xd4, 0xc6, 0x51, 0xd8, 0xa8, 0x1c, 0xec, 0x51
                ],
            },
            TestVector {
                sk: [
                    0xe8, 0x40, 0x9a, 0xaa, 0x83, 0x2c, 0xc2, 0x37, 0x8f, 0x2b, 0xad, 0xeb, 0x77, 0x15, 0x05, 0x62, 0x15, 0x37, 0x42, 0xfe, 0xe8, 0x76, 0xdc, 0xf4, 0x78, 0x3a, 0x6c, 0xcd, 0x11, 0x9d, 0xa6, 0x6a
                ],
                c: [
                    0xcc, 0x08, 0x49, 0x22, 0xa0, 0xea, 0xd2, 0xda, 0x53, 0x38, 0xbd, 0x82, 0x20, 0x0a, 0x19, 0x46, 0xbc, 0x85, 0x85, 0xb8, 0xd9, 0xee, 0x41, 0x6d, 0xf6, 0xa0, 0x9a, 0x71, 0xab, 0x0e, 0x5b, 0x58
                ],
            },
            TestVector {
                sk: [
                    0x46, 0x4f, 0x90, 0xa3, 0x64, 0xcf, 0xf8, 0x05, 0xfe, 0xe9, 0x3a, 0x85, 0xb7, 0x2f, 0x48, 0x94, 0xce, 0x4e, 0x13, 0x58, 0xdc, 0xdc, 0x1e, 0x61, 0xa3, 0xd4, 0x30, 0x30, 0x1c, 0x60, 0x91, 0x0e
                ],
                c: [
                    0xf9, 0xd2, 0x54, 0x4a, 0x55, 0x28, 0xae, 0x6b, 0xd9, 0xf0, 0x36, 0xf4, 0x2f, 0x9f, 0x05, 0xd8, 0x3d, 0xff, 0x50, 0x7a, 0xeb, 0x2a, 0x81, 0x41, 0xaf, 0x11, 0xd9, 0xf1, 0x67, 0xe2, 0x21, 0xae
                ],
            },
            TestVector {
                sk: [
                    0xfc, 0x4b, 0x6e, 0x93, 0xb0, 0xe4, 0x2f, 0x7a, 0x76, 0x2c, 0xa0, 0xc6, 0x52, 0x2c, 0xcd, 0x10, 0x45, 0xca, 0xb5, 0x06, 0xb3, 0x72, 0x45, 0x2a, 0xf7, 0x30, 0x6c, 0x87, 0x38, 0x9a, 0xb6, 0x2c
                ],
                c: [
                    0xe8, 0x9b, 0xf2, 0xed, 0x73, 0xf5, 0xe0, 0x88, 0x75, 0x42, 0xe3, 0x67, 0x93, 0xfa, 0xc8, 0x2c, 0x50, 0x8a, 0xb5, 0xd9, 0x91, 0x98, 0x57, 0x82, 0x27, 0xb2, 0x41, 0xfb, 0xac, 0x19, 0x84, 0x29
                ],
            },
        ];