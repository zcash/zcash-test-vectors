        struct TestVector {
            input: [[u8; 32]; 2],
            output: [u8; 32],
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/poseidon_fq_hash.py
        let test_vectors = vec![
            TestVector {
                input: [
                    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                ],
                output: [
                    0x4e, 0x68, 0xf6, 0x85, 0x70, 0x29, 0x57, 0xf3, 0xbf, 0x54, 0x6b, 0x7a, 0x09, 0x01, 0x31, 0x4e, 0x51, 0x4f, 0x19, 0x5e, 0xe3, 0xb1, 0x64, 0x46, 0x22, 0x77, 0x9d, 0x93, 0xdf, 0x96, 0xba, 0x15
                ],
            },
            TestVector {
                input: [
                    [0x5c, 0x7a, 0x8f, 0x73, 0x79, 0x42, 0x57, 0x08, 0x7e, 0x63, 0x4c, 0x49, 0xac, 0x6b, 0x57, 0x07, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x08],
                    [0x1a, 0xdd, 0x86, 0xb3, 0x8a, 0x6d, 0x8a, 0xc0, 0xa6, 0xfd, 0x9e, 0x0d, 0x98, 0x2b, 0x77, 0xe6, 0xb0, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x0d],
                ],
                output: [
                    0x0c, 0x0a, 0xd9, 0x0a, 0x2e, 0x0c, 0xba, 0x0e, 0xe6, 0xa5, 0x5a, 0xc5, 0x38, 0xa4, 0x35, 0xc9, 0x39, 0x04, 0x98, 0xae, 0xb5, 0x30, 0x3e, 0x3d, 0xad, 0x70, 0x3a, 0xd1, 0xdc, 0xdb, 0x43, 0x2b
                ],
            },
            TestVector {
                input: [
                    [0xbd, 0x69, 0xb8, 0x25, 0xca, 0x41, 0x61, 0x29, 0x6e, 0xfa, 0x7f, 0x66, 0x9b, 0xa9, 0xc7, 0x27, 0x1f, 0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e, 0x30, 0xa7, 0x35, 0x14],
                    [0xbc, 0x50, 0x98, 0x42, 0xb9, 0xa7, 0x62, 0xe5, 0x58, 0xea, 0x51, 0x47, 0xed, 0x5a, 0xc0, 0x08, 0x62, 0xc2, 0xfa, 0x7b, 0x2f, 0xec, 0xbc, 0xb6, 0x4b, 0x69, 0x68, 0x91, 0x2a, 0x63, 0x81, 0x0e],
                ],
                output: [
                    0xa6, 0x0c, 0xc8, 0xb8, 0x53, 0xaf, 0xce, 0xdb, 0xa1, 0x44, 0x65, 0xd5, 0x31, 0xc7, 0x3c, 0xbc, 0xe1, 0x9e, 0x46, 0x0b, 0xa8, 0x04, 0x62, 0x2d, 0xf5, 0x21, 0x23, 0x1d, 0xa1, 0x21, 0xc6, 0x08
                ],
            },
            TestVector {
                input: [
                    [0x3d, 0xc1, 0x66, 0xd5, 0x6a, 0x1d, 0x62, 0xf5, 0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56, 0xd5, 0x9a, 0xf8, 0x0d],
                    [0x05, 0xa7, 0x45, 0xf4, 0x29, 0xc5, 0xdc, 0xe8, 0x4e, 0x0c, 0x20, 0xfd, 0xf0, 0xf0, 0x3e, 0xbf, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97, 0xb0, 0xe4, 0xe4, 0xc7, 0x63, 0xcc, 0xb8, 0xf6, 0x36],
                ],
                output: [
                    0xad, 0xa8, 0xca, 0xe4, 0x6a, 0x04, 0x2d, 0x00, 0xb0, 0x2e, 0x33, 0xc3, 0x6e, 0x65, 0x8c, 0x22, 0x13, 0xfe, 0x81, 0x34, 0x53, 0x8b, 0x56, 0x03, 0x19, 0xe9, 0x99, 0xf3, 0xf5, 0x82, 0x90, 0x00
                ],
            },
            TestVector {
                input: [
                    [0x49, 0x5c, 0x22, 0x2f, 0x7f, 0xba, 0x1e, 0x31, 0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d, 0x94, 0x90, 0x3d, 0x3c],
                    [0x3d, 0x0a, 0xd3, 0x36, 0xeb, 0x31, 0xf0, 0x83, 0xce, 0x29, 0x77, 0x0e, 0x42, 0x98, 0x8d, 0x7d, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0, 0x4b, 0xe3, 0x4a, 0x98, 0x11],
                ],
                output: [
                    0x19, 0x94, 0x9f, 0xc7, 0x74, 0x04, 0x99, 0x37, 0x00, 0x58, 0x12, 0x7d, 0x04, 0x0f, 0x11, 0x24, 0x5e, 0xba, 0x6c, 0x37, 0x80, 0xe9, 0x3e, 0x26, 0x16, 0xf4, 0xc1, 0x77, 0x56, 0x30, 0x78, 0x2d
                ],
            },
            TestVector {
                input: [
                    [0xa4, 0xaf, 0x9d, 0xb6, 0x36, 0x4d, 0x03, 0x99, 0x3d, 0x50, 0x35, 0x3d, 0x88, 0x39, 0x5e, 0xd7, 0xa4, 0x1b, 0x00, 0x52, 0xad, 0x80, 0x84, 0xa8, 0xb9, 0xda, 0x94, 0x8d, 0x32, 0x0d, 0xad, 0x16],
                    [0x4d, 0x54, 0x31, 0xe6, 0xdb, 0x08, 0xd8, 0x74, 0x69, 0x5c, 0x3e, 0xaf, 0x34, 0x5b, 0x86, 0xc4, 0x12, 0x1f, 0xc0, 0x0f, 0xe7, 0xf2, 0x35, 0x73, 0x42, 0x76, 0xd3, 0x8d, 0x47, 0xf1, 0xe1, 0x11],
                ],
                output: [
                    0x29, 0x6e, 0xba, 0xb4, 0xb4, 0x5a, 0xb9, 0x20, 0x97, 0xa7, 0xe6, 0xe7, 0xcc, 0x6d, 0xd7, 0xd4, 0x7a, 0x12, 0x3e, 0x85, 0x50, 0xa3, 0x3d, 0xf1, 0x20, 0xcc, 0xa5, 0x38, 0x90, 0x67, 0x1b, 0x21
                ],
            },
            TestVector {
                input: [
                    [0xdd, 0x0c, 0x7a, 0x1d, 0xe5, 0xed, 0x2f, 0xc3, 0x8e, 0x5e, 0x60, 0x7a, 0x3f, 0xde, 0xab, 0x3f, 0xb6, 0x79, 0xf3, 0xdc, 0x60, 0x1d, 0x00, 0x82, 0x85, 0xed, 0xcb, 0xda, 0xe6, 0x9c, 0xe8, 0x3c],
                    [0x19, 0xe4, 0xaa, 0xc0, 0xcd, 0x1b, 0xe4, 0x05, 0x02, 0x42, 0xf4, 0xd1, 0x20, 0x53, 0xdb, 0x33, 0xf7, 0x34, 0x76, 0xf2, 0x1a, 0x48, 0x2e, 0xc9, 0x37, 0x83, 0x65, 0xc8, 0xf7, 0x39, 0x3c, 0x14],
                ],
                output: [
                    0xa8, 0x87, 0x6e, 0x8d, 0x2f, 0x30, 0x0a, 0x62, 0x05, 0x4b, 0x49, 0x4c, 0x8f, 0x21, 0xc1, 0xd0, 0xad, 0xbd, 0xac, 0x89, 0xbf, 0x2a, 0xad, 0x9f, 0x3c, 0x1b, 0x10, 0xc4, 0x78, 0x8c, 0x2d, 0x3d
                ],
            },
            TestVector {
                input: [
                    [0xe2, 0x88, 0x53, 0x15, 0xeb, 0x46, 0x71, 0x09, 0x8b, 0x79, 0x53, 0x5e, 0x79, 0x0f, 0xe5, 0x3e, 0x29, 0xfe, 0xf2, 0xb3, 0x76, 0x66, 0x97, 0xac, 0x32, 0xb4, 0xf4, 0x73, 0xf4, 0x68, 0xa0, 0x08],
                    [0xe6, 0x23, 0x89, 0xfc, 0xe2, 0x9c, 0xc6, 0xeb, 0x2e, 0x07, 0xeb, 0xc5, 0xae, 0x25, 0xf9, 0xf7, 0x83, 0xb2, 0x7d, 0xb5, 0x9a, 0x4a, 0x15, 0x3d, 0x88, 0x2d, 0x2b, 0x21, 0x03, 0x59, 0x65, 0x15],
                ],
                output: [
                    0xc2, 0xda, 0xcb, 0x1e, 0xea, 0xed, 0x88, 0x0b, 0x87, 0xd0, 0x4d, 0xd9, 0x61, 0x95, 0x73, 0x0e, 0x98, 0xbd, 0x0f, 0x14, 0x77, 0x7b, 0x3e, 0xf0, 0xda, 0x40, 0xe4, 0xc0, 0x87, 0xb1, 0x9d, 0x28
                ],
            },
            TestVector {
                input: [
                    [0xeb, 0x94, 0x94, 0xc6, 0x6a, 0xb3, 0xae, 0x30, 0xb7, 0xe6, 0x09, 0xd9, 0x91, 0xf4, 0x33, 0xbf, 0x94, 0x86, 0xa7, 0xaf, 0xcf, 0x4a, 0x0d, 0x9c, 0x73, 0x1e, 0x98, 0x5d, 0x99, 0x58, 0x9c, 0x0b],
                    [0xb7, 0x38, 0xe8, 0xaa, 0xd6, 0x5a, 0x0c, 0xb2, 0xfb, 0x3f, 0x1a, 0x31, 0x20, 0x37, 0x2e, 0x83, 0x1a, 0x20, 0xda, 0x8a, 0xba, 0x18, 0xd1, 0xdb, 0xeb, 0xbc, 0x86, 0x2d, 0xed, 0x42, 0x43, 0x1e],
                ],
                output: [
                    0x5a, 0x55, 0xe3, 0x08, 0x2e, 0x55, 0xa5, 0x66, 0xb9, 0xca, 0xb1, 0xca, 0xf4, 0x48, 0xf7, 0x0f, 0x8c, 0x9a, 0x53, 0xa1, 0xc9, 0xf6, 0x9e, 0x2a, 0x80, 0xdd, 0xb8, 0x58, 0x3f, 0x99, 0x01, 0x26
                ],
            },
            TestVector {
                input: [
                    [0x91, 0x47, 0x69, 0x30, 0xaf, 0x7e, 0x42, 0xe0, 0x21, 0x88, 0x56, 0x38, 0x53, 0xd9, 0x34, 0x67, 0xe0, 0x01, 0xaf, 0xa2, 0xfb, 0x8d, 0xc3, 0x43, 0x6d, 0x75, 0xa4, 0xa6, 0xf2, 0x65, 0x72, 0x10],
                    [0x4b, 0x19, 0x22, 0x32, 0xec, 0xb9, 0xf0, 0xc0, 0x24, 0x11, 0xe5, 0x25, 0x96, 0xbc, 0x5e, 0x90, 0x45, 0x7e, 0x74, 0x59, 0x39, 0xff, 0xed, 0xbd, 0x12, 0x86, 0x3c, 0xe7, 0x1a, 0x02, 0xaf, 0x11],
                ],
                output: [
                    0xca, 0xc6, 0x68, 0x8a, 0x3d, 0x2a, 0x7d, 0xca, 0xe1, 0xd4, 0x60, 0x1f, 0x9b, 0xf0, 0x6d, 0x58, 0x00, 0x8f, 0x24, 0x85, 0x6a, 0xe6, 0x00, 0xf0, 0xe0, 0x90, 0x07, 0x23, 0xaf, 0xa1, 0x20, 0x03
                ],
            },
            TestVector {
                input: [
                    [0x7b, 0x41, 0x7a, 0xdb, 0xfb, 0x3e, 0x3e, 0x3c, 0x21, 0x60, 0xd3, 0xd1, 0x6f, 0x1e, 0x7f, 0x26, 0x8f, 0xb8, 0x6b, 0x12, 0xb5, 0x6d, 0xa9, 0xc3, 0x82, 0x85, 0x7d, 0xee, 0xcc, 0x40, 0xa9, 0x0d],
                    [0x5e, 0x29, 0x35, 0x39, 0x3d, 0xf9, 0x2f, 0xa1, 0xf4, 0x71, 0x68, 0xb2, 0x61, 0xae, 0xb3, 0x78, 0x6d, 0xd9, 0x84, 0xd5, 0x67, 0xdb, 0x28, 0x57, 0xb9, 0x27, 0xb7, 0xfa, 0xe2, 0xdb, 0x58, 0x31],
                ],
                output: [
                    0xd7, 0xe7, 0x83, 0x91, 0x97, 0x83, 0xb0, 0x8b, 0x5f, 0xad, 0x08, 0x9d, 0x57, 0x1e, 0xc1, 0x8f, 0xb4, 0x63, 0x28, 0x53, 0x99, 0x3f, 0x35, 0xe3, 0xee, 0x54, 0x3d, 0x4e, 0xed, 0xf6, 0x5f, 0x38
                ],
            },
        ];
