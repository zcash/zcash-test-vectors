        struct TestVector {
            sk: [u8; 32],
            vk: [u8; 32],
            alpha: [u8; 32],
            rsk: [u8; 32],
            rvk: [u8; 32],
            m: [u8; 32],
            sig: [u8; 64],
            rsig: [u8; 64],
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_signatures.py
        let test_vectors = vec![
            TestVector {
                sk: [
                    0x18, 0xe2, 0x8d, 0xea, 0x5c, 0x11, 0x81, 0x7a, 0xee, 0xb2, 0x1a, 0x19, 0x98, 0x1d, 0x28, 0x36, 0x8e, 0xc4, 0x38, 0xaf, 0xc2, 0x5a, 0x8d, 0xb9, 0x4e, 0xbe, 0x08, 0xd7, 0xa0, 0x28, 0x8e, 0x09
                ],
                vk: [
                    0x9b, 0x01, 0x53, 0xb0, 0x3d, 0x32, 0x0f, 0xe2, 0x3e, 0x28, 0x34, 0xd5, 0xd6, 0x1d, 0xbb, 0x1f, 0x51, 0x9b, 0x3f, 0x41, 0xf8, 0xf9, 0x46, 0x15, 0x2b, 0xf0, 0xc3, 0xf2, 0x47, 0xd1, 0x18, 0x07
                ],
                alpha: [
                    0xff, 0xd1, 0xa1, 0x27, 0x32, 0x52, 0xb1, 0x87, 0xf4, 0xed, 0x32, 0x6d, 0xfc, 0x98, 0x85, 0x3e, 0x29, 0x17, 0xc2, 0xb3, 0x63, 0x79, 0xb1, 0x75, 0xda, 0x63, 0xb9, 0xef, 0x6d, 0xda, 0x6c, 0x08
                ],
                rsk: [
                    0x60, 0x87, 0x38, 0x3b, 0x30, 0x55, 0x9b, 0x31, 0x60, 0x90, 0x85, 0xb9, 0x00, 0x96, 0x45, 0xce, 0xb6, 0xa0, 0xc6, 0x61, 0x25, 0x99, 0xd7, 0x28, 0x80, 0x72, 0x8e, 0x61, 0x24, 0x4e, 0x7d, 0x03
                ],
                rvk: [
                    0xc1, 0xba, 0xbc, 0xb6, 0xea, 0xe2, 0xb9, 0x94, 0xee, 0x6d, 0x65, 0xc1, 0x0b, 0x9d, 0xad, 0x59, 0x40, 0xdc, 0x73, 0x5b, 0x07, 0x50, 0x4d, 0xae, 0xd1, 0xe4, 0x6b, 0x07, 0x09, 0xb4, 0x51, 0x36
                ],
                m: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                sig: [
                    0xdc, 0xa3, 0xbb, 0x2c, 0xb8, 0xf0, 0x48, 0xcc, 0xab, 0x10, 0xae, 0xd7, 0x75, 0x46, 0xc1, 0xdb, 0xb1, 0x0c, 0xc4, 0xfb, 0x15, 0xab, 0x02, 0xac, 0xae, 0xf9, 0x44, 0xdd, 0xab, 0x8b, 0x67, 0x22, 0x54, 0x5f, 0xda, 0x4c, 0x62, 0x04, 0x6d, 0x69, 0xd9, 0x8f, 0x92, 0x2f, 0x4e, 0x8c, 0x21, 0x0b, 0xc4, 0x7b, 0x4f, 0xdd, 0xe0, 0xa1, 0x94, 0x71, 0x79, 0x80, 0x4c, 0x1a, 0xce, 0x56, 0x90, 0x05
                ],
                rsig: [
                    0x70, 0xc2, 0x84, 0x50, 0x4e, 0x90, 0xf0, 0x00, 0x8e, 0x8e, 0xd2, 0x20, 0x8f, 0x49, 0x69, 0x72, 0x7a, 0x41, 0x5e, 0xc3, 0x10, 0x2c, 0x29, 0x9e, 0x39, 0x8b, 0x6c, 0x16, 0x57, 0x2b, 0xd9, 0x64, 0x3e, 0xe1, 0x01, 0x17, 0x66, 0x68, 0x1e, 0x40, 0x6e, 0xe6, 0xbe, 0xe3, 0xd0, 0x3e, 0xe8, 0xf2, 0x71, 0x76, 0xe3, 0x2f, 0xba, 0xbd, 0xde, 0xd2, 0x0b, 0x0d, 0x17, 0x86, 0xa4, 0xee, 0x18, 0x01
                ],
            },
            TestVector {
                sk: [
                    0x05, 0x96, 0x54, 0xf9, 0x61, 0x27, 0x3d, 0xaf, 0xda, 0x3b, 0x26, 0x77, 0xb3, 0x5c, 0x18, 0xaf, 0x6b, 0x11, 0xad, 0xfb, 0x9e, 0xe9, 0x0b, 0x48, 0x93, 0x5e, 0x55, 0x7c, 0x8d, 0x5d, 0x9c, 0x04
                ],
                vk: [
                    0xfa, 0xf6, 0xc3, 0xb7, 0x37, 0xe8, 0xe6, 0x11, 0xaa, 0xfe, 0xa5, 0x2f, 0x03, 0xbb, 0x27, 0x86, 0xe1, 0x83, 0x53, 0xeb, 0xe0, 0xd3, 0x13, 0x9e, 0x3c, 0x54, 0x49, 0x87, 0x80, 0xc8, 0xc1, 0x99
                ],
                alpha: [
                    0xc3, 0x0b, 0x96, 0x20, 0x8d, 0xa8, 0x00, 0xe1, 0x0a, 0xf0, 0x25, 0x42, 0xce, 0x69, 0x4b, 0x7e, 0xd7, 0x6a, 0x28, 0x29, 0x9f, 0x85, 0x99, 0x8e, 0x5d, 0x61, 0x08, 0x12, 0x68, 0x1b, 0xf0, 0x03
                ],
                rsk: [
                    0xc8, 0xa1, 0xea, 0x19, 0xef, 0xcf, 0x3d, 0x90, 0xe5, 0x2b, 0x4c, 0xb9, 0x81, 0xc6, 0x63, 0x2d, 0x43, 0x7c, 0xd5, 0x24, 0x3e, 0x6f, 0xa5, 0xd6, 0xf0, 0xbf, 0x5d, 0x8e, 0xf5, 0x78, 0x8c, 0x08
                ],
                rvk: [
                    0xd5, 0x24, 0xdc, 0xe7, 0x73, 0x40, 0x69, 0x75, 0x8a, 0x91, 0xf0, 0x07, 0xa8, 0x69, 0x50, 0x5d, 0xfc, 0x4a, 0xba, 0x17, 0x20, 0x59, 0x4d, 0x4d, 0x74, 0xf0, 0x07, 0x70, 0x0e, 0x62, 0xee, 0x00
                ],
                m: [
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                ],
                sig: [
                    0xb5, 0xa1, 0xf3, 0x2d, 0x3d, 0x50, 0xfc, 0x73, 0x8b, 0x5c, 0x3b, 0x4e, 0x99, 0x60, 0x72, 0x9c, 0xe4, 0x31, 0x6b, 0xa7, 0x72, 0x1a, 0x12, 0x68, 0x66, 0x04, 0xfe, 0xba, 0x6b, 0xd7, 0x48, 0x45, 0x00, 0x70, 0xcb, 0x92, 0x24, 0x06, 0xfd, 0xfc, 0x5d, 0x60, 0xde, 0xa9, 0xbe, 0x3a, 0x52, 0x6a, 0x16, 0xcf, 0xeb, 0x87, 0x77, 0x79, 0xfb, 0x78, 0x2d, 0x5d, 0x41, 0x39, 0x5b, 0x45, 0x5f, 0x04
                ],
                rsig: [
                    0x5a, 0x5a, 0x20, 0xd2, 0x00, 0xef, 0xdd, 0xd4, 0x98, 0xdf, 0xae, 0x2a, 0x9e, 0xf8, 0xcf, 0x01, 0x28, 0x1a, 0x89, 0x19, 0x01, 0x8a, 0x82, 0x4c, 0xc7, 0xa4, 0x98, 0x3b, 0x9a, 0x0d, 0x4a, 0x06, 0xff, 0x17, 0x20, 0x79, 0xe0, 0x13, 0xd4, 0x2a, 0x2a, 0x3a, 0x88, 0xa6, 0x52, 0x0c, 0x86, 0xfc, 0xe3, 0xb9, 0x8e, 0x1e, 0xfa, 0xa3, 0x25, 0x83, 0x2a, 0x6a, 0x56, 0x58, 0xd8, 0xdd, 0x7c, 0x0a
                ],
            },
            TestVector {
                sk: [
                    0xad, 0xe7, 0xab, 0xb5, 0x51, 0xc7, 0x9d, 0x0f, 0x0e, 0x42, 0xef, 0x7f, 0x12, 0x06, 0xb8, 0x77, 0x12, 0xa8, 0x4a, 0x61, 0xde, 0xa3, 0xf3, 0x7b, 0x42, 0x49, 0x6d, 0x7e, 0xfd, 0x12, 0x52, 0x0c
                ],
                vk: [
                    0x36, 0x9e, 0xa7, 0x51, 0x76, 0x2f, 0x83, 0x9d, 0x25, 0x70, 0x1a, 0x5e, 0xeb, 0x55, 0x1e, 0xc4, 0xf0, 0x6c, 0x12, 0x90, 0xb3, 0xb9, 0xc3, 0xa7, 0x24, 0x40, 0x2d, 0xec, 0x02, 0x73, 0x92, 0x21
                ],
                alpha: [
                    0x81, 0x92, 0x25, 0x29, 0xa6, 0x3e, 0xe7, 0x43, 0xfc, 0x4f, 0xbb, 0xac, 0x45, 0xc4, 0x98, 0x83, 0x16, 0xbc, 0x9b, 0x6e, 0x42, 0x8b, 0x01, 0xa8, 0xd3, 0x1f, 0xc1, 0xc2, 0xa6, 0xca, 0x62, 0x05
                ],
                rsk: [
                    0x77, 0x4d, 0xda, 0x07, 0x99, 0xf7, 0xed, 0x82, 0x87, 0x81, 0xe2, 0x5f, 0xc4, 0xa9, 0xe8, 0x54, 0x28, 0x29, 0xb2, 0xce, 0x1f, 0xf4, 0x8d, 0x1d, 0x6d, 0xb9, 0xfa, 0xdb, 0xb9, 0x28, 0x37, 0x03
                ],
                rvk: [
                    0x0d, 0x92, 0xad, 0x6d, 0x46, 0xed, 0xac, 0xd0, 0x23, 0xd4, 0xd2, 0xef, 0x70, 0x3a, 0x6c, 0xa0, 0xa7, 0x92, 0xcf, 0xc4, 0xb7, 0xda, 0x11, 0xc2, 0x35, 0x3b, 0xc8, 0x45, 0xa2, 0x7a, 0x97, 0x4d
                ],
                m: [
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
                ],
                sig: [
                    0x1f, 0x3e, 0x8a, 0x94, 0x31, 0x0c, 0x20, 0x71, 0xa7, 0x0f, 0x9d, 0xf5, 0xe7, 0x9a, 0xa9, 0xe8, 0x48, 0x5d, 0xec, 0xcb, 0x17, 0x8b, 0xdf, 0xf9, 0x80, 0x5f, 0xcb, 0xe6, 0xf7, 0xd5, 0x51, 0xee, 0xe3, 0xc3, 0x54, 0x2c, 0xa7, 0x5c, 0x9d, 0x8d, 0x4a, 0xdc, 0x54, 0xd7, 0x2c, 0x3d, 0xbe, 0x28, 0x62, 0x6d, 0x20, 0x78, 0x5b, 0xb7, 0xf5, 0x88, 0xc1, 0xa5, 0x82, 0xb8, 0x93, 0xdb, 0xb6, 0x01
                ],
                rsig: [
                    0xd1, 0x36, 0x21, 0x4c, 0x5d, 0x52, 0x8e, 0xa3, 0xd4, 0xcb, 0x7b, 0x63, 0x1a, 0x6b, 0xb0, 0x36, 0x06, 0x49, 0x73, 0xa1, 0x08, 0xb7, 0x33, 0xa5, 0xe3, 0xa4, 0x52, 0xab, 0x52, 0xa6, 0x59, 0xe5, 0x67, 0xcb, 0x55, 0xd2, 0x64, 0x4e, 0x74, 0xb6, 0xe8, 0x42, 0x6f, 0x2a, 0x7d, 0xd2, 0xa0, 0x4d, 0x2d, 0xda, 0x49, 0x35, 0xcc, 0x38, 0x20, 0xb7, 0x7a, 0x9c, 0x1a, 0xb6, 0x19, 0x86, 0x3c, 0x05
                ],
            },
            TestVector {
                sk: [
                    0xc9, 0xd2, 0xae, 0x1f, 0x6d, 0x32, 0xa6, 0x75, 0xd0, 0x9e, 0xb0, 0x82, 0x3f, 0x46, 0x7f, 0xa9, 0x21, 0xb3, 0x28, 0x4a, 0xcb, 0x35, 0xfa, 0xbd, 0xfc, 0x99, 0x4d, 0xe5, 0x49, 0xb8, 0x59, 0x0d
                ],
                vk: [
                    0x2d, 0x2f, 0x31, 0x6e, 0x5c, 0x36, 0x9a, 0xe4, 0xdd, 0x2c, 0x82, 0x5f, 0x3d, 0x86, 0x46, 0x00, 0x58, 0x40, 0x71, 0x84, 0x60, 0x3b, 0x21, 0x2c, 0xf3, 0x45, 0x9f, 0x36, 0xc8, 0x69, 0x7f, 0xd8
                ],
                alpha: [
                    0xeb, 0xbc, 0x89, 0x03, 0x11, 0x07, 0xc4, 0x4f, 0x47, 0x88, 0x9e, 0xd4, 0xd4, 0x37, 0x5a, 0x41, 0x14, 0xcf, 0x8a, 0x75, 0xdd, 0x33, 0xb9, 0x62, 0xf2, 0xd7, 0x59, 0xd3, 0xf4, 0xc6, 0xdf, 0x06
                ],
                rsk: [
                    0xfd, 0x62, 0x41, 0x4c, 0x1f, 0x2b, 0xd3, 0xf4, 0x94, 0x16, 0x87, 0x8a, 0x80, 0x5d, 0x71, 0x44, 0x35, 0x47, 0x7f, 0xbe, 0xa7, 0x2e, 0x4c, 0x1a, 0x46, 0xc2, 0x73, 0x53, 0x54, 0xca, 0xbb, 0x05
                ],
                rvk: [
                    0xf0, 0x43, 0x0e, 0x95, 0x3b, 0xe6, 0x0b, 0xf4, 0x38, 0xdb, 0xdc, 0xc2, 0x30, 0x3f, 0x0e, 0x32, 0xa6, 0xf7, 0xce, 0x2f, 0xbe, 0xdf, 0xb1, 0x3a, 0xc5, 0x18, 0xf7, 0x5a, 0x3f, 0xd1, 0x0e, 0xb5
                ],
                m: [
                    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
                ],
                sig: [
                    0x12, 0xc7, 0x8d, 0xdd, 0x20, 0xd3, 0x0a, 0x61, 0xf8, 0x93, 0x0c, 0x6f, 0xe0, 0x85, 0x0f, 0xd1, 0x12, 0xbb, 0x7b, 0xe8, 0x8b, 0x12, 0x38, 0xea, 0x33, 0xd6, 0xbe, 0xf8, 0x81, 0xc1, 0x02, 0xd1, 0x04, 0xaa, 0x36, 0x54, 0x4a, 0x78, 0x47, 0x1c, 0x9e, 0x28, 0x42, 0xe6, 0xfd, 0x42, 0x55, 0x83, 0x46, 0xcf, 0xf4, 0x31, 0x27, 0x03, 0x26, 0x66, 0xeb, 0x11, 0x6f, 0x44, 0x2a, 0x28, 0x48, 0x0c
                ],
                rsig: [
                    0x01, 0xba, 0xaa, 0x26, 0x27, 0x4c, 0x14, 0x9a, 0xcf, 0x12, 0xe1, 0xcc, 0xf5, 0x50, 0x7d, 0x56, 0x79, 0x04, 0x82, 0xf0, 0x67, 0xe5, 0xc9, 0x2b, 0x32, 0x19, 0xad, 0x6b, 0xf9, 0x11, 0x18, 0xcc, 0x3f, 0xce, 0x8d, 0x2a, 0x23, 0x19, 0x8a, 0x3b, 0x29, 0x0a, 0x7b, 0xf6, 0x8c, 0x2a, 0xc0, 0x7b, 0x5d, 0x90, 0x62, 0xb9, 0xf8, 0x68, 0x66, 0x2b, 0xb2, 0x52, 0x49, 0x12, 0xd4, 0x85, 0x6e, 0x0c
                ],
            },
            TestVector {
                sk: [
                    0x33, 0xbc, 0xd2, 0x86, 0x45, 0x41, 0xb8, 0xbb, 0x7f, 0xdc, 0x77, 0xa1, 0x9d, 0x97, 0x0f, 0x92, 0x4e, 0xae, 0xec, 0xf4, 0x10, 0x3c, 0x38, 0xc8, 0xd2, 0xb0, 0x66, 0x81, 0x42, 0xf2, 0x7d, 0x09
                ],
                vk: [
                    0x74, 0x17, 0x94, 0xe6, 0x2c, 0xf9, 0x32, 0x0c, 0x58, 0xba, 0xc5, 0x94, 0xa2, 0xb9, 0x0e, 0x34, 0x0a, 0x6d, 0x8a, 0x68, 0x05, 0x6f, 0x6e, 0xd5, 0xc7, 0x86, 0x8c, 0x5f, 0xf3, 0xe4, 0xd6, 0x16
                ],
                alpha: [
                    0x7c, 0xe7, 0x25, 0xa5, 0xfe, 0xf6, 0x1b, 0xd4, 0xa1, 0xe9, 0xc7, 0x73, 0x28, 0xe8, 0x21, 0x0e, 0xb7, 0x29, 0x2d, 0x95, 0x4c, 0x64, 0xe9, 0x9e, 0x8b, 0xed, 0xd0, 0x7a, 0xb3, 0xab, 0x0e, 0x0d
                ],
                rsk: [
                    0xf8, 0x76, 0x01, 0x55, 0xe5, 0x29, 0x3d, 0xbf, 0x9e, 0xb5, 0x77, 0x48, 0x32, 0x5f, 0xc9, 0xf9, 0x04, 0x9d, 0xe5, 0x88, 0x5c, 0x65, 0xba, 0x60, 0xb5, 0xee, 0x03, 0x97, 0x0b, 0xe9, 0x0e, 0x08
                ],
                rvk: [
                    0x66, 0x62, 0xba, 0x09, 0x95, 0x0a, 0xcc, 0xd2, 0xce, 0xa3, 0xc7, 0xa8, 0x12, 0x90, 0xcd, 0x59, 0x78, 0xa6, 0x2b, 0x5a, 0xc5, 0xbb, 0xc4, 0x8d, 0x9f, 0x58, 0x19, 0xcd, 0xc9, 0x64, 0x6f, 0x0a
                ],
                m: [
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
                ],
                sig: [
                    0x77, 0x4a, 0xc4, 0x67, 0x3f, 0x09, 0xf3, 0xac, 0x57, 0x89, 0xb2, 0x86, 0xb5, 0xee, 0xcb, 0xed, 0xb2, 0x57, 0x23, 0x4e, 0x8c, 0xdf, 0xd9, 0x3f, 0x02, 0x89, 0x09, 0x78, 0xa6, 0xbb, 0xa6, 0x11, 0x69, 0xed, 0x48, 0xf9, 0xe1, 0xc9, 0xfd, 0x13, 0x19, 0xbd, 0x33, 0x0d, 0x2c, 0xf5, 0xb4, 0x91, 0x01, 0x0d, 0x69, 0xb0, 0x43, 0xf4, 0x64, 0x8b, 0xff, 0x55, 0x41, 0x62, 0xc6, 0xa6, 0xdc, 0x09
                ],
                rsig: [
                    0x7c, 0x6c, 0x49, 0x8d, 0xe0, 0x01, 0x78, 0x61, 0x09, 0xb3, 0x03, 0xa4, 0xc5, 0xdc, 0xb7, 0xfd, 0x07, 0x57, 0x50, 0xa0, 0xb9, 0xdf, 0x5e, 0x1e, 0x2a, 0x8e, 0x75, 0x47, 0xb7, 0xed, 0x70, 0xcc, 0x0b, 0x56, 0xa5, 0xbf, 0xa9, 0x65, 0x78, 0x43, 0xef, 0xd8, 0x9c, 0x66, 0xa8, 0x4f, 0x41, 0xd2, 0xb1, 0xb5, 0x07, 0x51, 0x19, 0x6b, 0x1e, 0x8c, 0x0c, 0x44, 0x98, 0x60, 0x06, 0x96, 0xa4, 0x04
                ],
            },
            TestVector {
                sk: [
                    0xca, 0x35, 0x06, 0xd6, 0xaf, 0x77, 0x67, 0xb5, 0x79, 0x0e, 0xf0, 0xc5, 0x19, 0x0f, 0xb3, 0xf3, 0x87, 0x7c, 0x4a, 0xab, 0x40, 0xe0, 0xdd, 0x65, 0x1a, 0xbb, 0xda, 0xcb, 0x54, 0x4e, 0xd0, 0x05
                ],
                vk: [
                    0xba, 0xb6, 0xcf, 0xb5, 0xc8, 0xea, 0x34, 0x91, 0x25, 0x1b, 0x46, 0xd5, 0x2a, 0xca, 0x25, 0xd9, 0xe9, 0xaf, 0x69, 0xfa, 0xa9, 0xb4, 0xe4, 0x0b, 0x03, 0xad, 0x00, 0x86, 0xde, 0x59, 0xb5, 0x1f
                ],
                alpha: [
                    0xbe, 0xa3, 0x87, 0x20, 0x3f, 0x43, 0x76, 0x0a, 0xd3, 0x7d, 0x61, 0xde, 0x0e, 0xb5, 0x9f, 0xca, 0x6c, 0xab, 0x75, 0x60, 0xdf, 0x64, 0xfa, 0xbb, 0x95, 0x11, 0x57, 0x9f, 0x6f, 0x68, 0x26, 0x06
                ],
                rsk: [
                    0x88, 0xd9, 0x8d, 0xf6, 0xee, 0xba, 0xdd, 0xbf, 0x4c, 0x8c, 0x51, 0xa4, 0x28, 0xc4, 0x52, 0xbe, 0xf4, 0x27, 0xc0, 0x0b, 0x20, 0x45, 0xd8, 0x21, 0xb0, 0xcc, 0x31, 0x6b, 0xc4, 0xb6, 0xf6, 0x0b
                ],
                rvk: [
                    0x11, 0x26, 0x7d, 0x14, 0xd5, 0xe0, 0xb2, 0xbb, 0x3c, 0xe0, 0x99, 0xe8, 0xef, 0x84, 0x49, 0x47, 0x1c, 0xbc, 0xfc, 0x69, 0x39, 0xa4, 0xb3, 0x48, 0xde, 0xa2, 0xc1, 0x73, 0x56, 0xa1, 0xe8, 0xdd
                ],
                m: [
                    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
                ],
                sig: [
                    0x9a, 0x25, 0x42, 0x9f, 0x3e, 0xfd, 0x9b, 0x2f, 0x7d, 0xe2, 0x9e, 0x45, 0x12, 0x8d, 0xd7, 0xb7, 0x60, 0xf0, 0x50, 0x8c, 0xd9, 0x58, 0x21, 0x82, 0xab, 0xaf, 0x53, 0xdd, 0x76, 0xc0, 0x34, 0x2c, 0xe4, 0x1b, 0x4a, 0xcf, 0x8e, 0x0a, 0x48, 0x24, 0xe4, 0x11, 0x08, 0xc2, 0x02, 0x65, 0x73, 0x11, 0x4b, 0x60, 0xbe, 0xec, 0xb1, 0x74, 0x01, 0x2a, 0x2b, 0xdb, 0xee, 0xcb, 0xaa, 0x00, 0xb5, 0x06
                ],
                rsig: [
                    0xcf, 0xf5, 0x83, 0x57, 0x13, 0xbe, 0x07, 0xfb, 0xe1, 0x25, 0xbb, 0xf2, 0x7a, 0x63, 0x6a, 0xdd, 0x13, 0x1c, 0x90, 0x81, 0x71, 0x6c, 0x52, 0xfd, 0xa8, 0x75, 0x42, 0x6d, 0x03, 0x98, 0x2c, 0xd2, 0x7e, 0xbd, 0x14, 0xb4, 0x22, 0x7b, 0x83, 0x96, 0x15, 0xfd, 0x03, 0x71, 0xbf, 0xdb, 0x8a, 0x30, 0xab, 0xdd, 0xff, 0x74, 0xd7, 0x95, 0xf3, 0xe2, 0x7d, 0x1d, 0x47, 0xc6, 0x29, 0x46, 0x9b, 0x08
                ],
            },
            TestVector {
                sk: [
                    0xbc, 0x27, 0x83, 0x8d, 0xe2, 0xa6, 0x14, 0xcf, 0xba, 0x6c, 0x3e, 0x92, 0x2a, 0x8f, 0x84, 0x24, 0xd9, 0x85, 0x6f, 0x68, 0x16, 0xf3, 0xbc, 0x61, 0x02, 0x31, 0x3b, 0x7f, 0xaf, 0x5c, 0x3a, 0x0c
                ],
                vk: [
                    0xd7, 0x9b, 0xe9, 0xff, 0x22, 0x9a, 0x2e, 0x35, 0xf5, 0xbc, 0xa4, 0x48, 0xe5, 0xeb, 0x4a, 0x8a, 0xa9, 0x7f, 0xb4, 0x18, 0x02, 0x91, 0x25, 0xcf, 0xba, 0xa7, 0x8a, 0x91, 0xa3, 0x82, 0xb0, 0x94
                ],
                alpha: [
                    0x21, 0xa7, 0x15, 0x0e, 0x19, 0x4f, 0xed, 0xfe, 0xf9, 0x0c, 0x5d, 0x10, 0xe4, 0x20, 0x85, 0x8b, 0xca, 0x40, 0x04, 0x04, 0x0e, 0xb6, 0x81, 0xd1, 0x4e, 0x75, 0xc4, 0x47, 0x13, 0x51, 0xcb, 0x02
                ],
                rsk: [
                    0x26, 0xa2, 0xa1, 0xc4, 0x9c, 0xe7, 0x6a, 0xfd, 0x31, 0x69, 0xd3, 0xd5, 0x7a, 0x8f, 0xa1, 0x09, 0xa3, 0x8b, 0x3f, 0x6b, 0x23, 0x6e, 0xd7, 0x2c, 0xa8, 0xf6, 0xcb, 0x61, 0xd8, 0xf8, 0x87, 0x00
                ],
                rvk: [
                    0x54, 0xbf, 0x1b, 0xe7, 0x2e, 0x6d, 0x41, 0x20, 0x8b, 0x8a, 0xec, 0x11, 0x61, 0xd3, 0xba, 0x59, 0x51, 0x9f, 0xb9, 0x3d, 0xa0, 0x1a, 0x55, 0xe6, 0x78, 0xe2, 0x75, 0x20, 0x06, 0x60, 0x36, 0xc9
                ],
                m: [
                    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06
                ],
                sig: [
                    0xbb, 0xe0, 0x23, 0x59, 0x87, 0xc6, 0xe0, 0xec, 0x68, 0x6d, 0xdb, 0x8a, 0x65, 0x72, 0x66, 0xad, 0x60, 0x5f, 0x7b, 0x75, 0x95, 0x5b, 0xb0, 0xe8, 0x02, 0xf8, 0x81, 0x64, 0xa0, 0xff, 0xe1, 0x0c, 0x3b, 0x73, 0x85, 0x04, 0xab, 0xb3, 0xd1, 0x05, 0x62, 0xb9, 0x27, 0xb3, 0xd2, 0x9f, 0xe9, 0xb0, 0xd3, 0x56, 0x28, 0x6a, 0xea, 0xe5, 0xa2, 0xac, 0x9e, 0x43, 0x5f, 0x20, 0x79, 0x1a, 0xf8, 0x00
                ],
                rsig: [
                    0x6d, 0xe3, 0x2b, 0x54, 0x15, 0xd7, 0x7a, 0x90, 0x5f, 0x09, 0x03, 0x90, 0x2a, 0x11, 0x7e, 0xda, 0x79, 0x3c, 0x70, 0x8e, 0x23, 0xa5, 0x42, 0x45, 0xba, 0x8a, 0x8d, 0x1f, 0xe0, 0x26, 0x75, 0x23, 0x23, 0x15, 0x65, 0xe0, 0x57, 0x09, 0xae, 0xd9, 0x6c, 0x22, 0x1f, 0xb1, 0xf3, 0xd0, 0x42, 0x04, 0x35, 0x03, 0xff, 0x33, 0x85, 0x85, 0xa9, 0xbb, 0x98, 0x9c, 0x9d, 0xd4, 0x30, 0xd6, 0xd6, 0x0b
                ],
            },
            TestVector {
                sk: [
                    0xb2, 0x08, 0x59, 0xb8, 0x8e, 0xe3, 0x33, 0x8a, 0x64, 0x95, 0x4f, 0x8a, 0x9e, 0x8e, 0x9b, 0xf3, 0xe7, 0x11, 0x5a, 0xcf, 0x7c, 0x6e, 0x7f, 0x01, 0x43, 0x2c, 0x5f, 0x76, 0x96, 0xd2, 0xd0, 0x05
                ],
                vk: [
                    0xa8, 0x1f, 0xe6, 0x84, 0x6d, 0xbe, 0x0a, 0x75, 0xc0, 0xf4, 0x9b, 0x21, 0x32, 0x32, 0xbe, 0xad, 0xd1, 0xf9, 0xa5, 0x64, 0x67, 0x3d, 0x25, 0xb9, 0x1e, 0xe0, 0xf1, 0x7c, 0xe9, 0xca, 0xa3, 0x63
                ],
                alpha: [
                    0x44, 0xd9, 0x08, 0xe1, 0xc1, 0x5e, 0x6b, 0xd9, 0x38, 0x0a, 0x8b, 0x23, 0x5a, 0xce, 0x02, 0xfa, 0xc1, 0xc0, 0x87, 0x94, 0x45, 0x4b, 0xcd, 0xb4, 0xa6, 0xf4, 0x8c, 0xea, 0x78, 0xa7, 0x4a, 0x04
                ],
                rsk: [
                    0xf6, 0xe1, 0x61, 0x99, 0x50, 0x42, 0x9f, 0x63, 0x9d, 0x9f, 0xda, 0xad, 0xf8, 0x5c, 0x9e, 0xed, 0xa9, 0xd2, 0xe1, 0x63, 0xc2, 0xb9, 0x4c, 0xb6, 0xe9, 0x20, 0xec, 0x60, 0x0f, 0x7a, 0x1b, 0x0a
                ],
                rvk: [
                    0x0b, 0x68, 0xd5, 0x0f, 0x91, 0x3c, 0xd1, 0xb7, 0x8b, 0x59, 0x92, 0x1e, 0x16, 0x56, 0xd5, 0x76, 0xb0, 0xeb, 0x17, 0x1e, 0xd3, 0x87, 0x0d, 0x39, 0xfe, 0xc6, 0x94, 0x41, 0xb3, 0x4b, 0x25, 0x38
                ],
                m: [
                    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
                ],
                sig: [
                    0x44, 0x6d, 0x67, 0x7c, 0x4c, 0xfe, 0xfd, 0x02, 0x4b, 0x0a, 0xeb, 0x37, 0xa5, 0x98, 0xcc, 0x2e, 0xb3, 0xd2, 0x9b, 0x02, 0x94, 0xfe, 0x5b, 0xb6, 0x97, 0x8e, 0x8b, 0x43, 0xd3, 0x2b, 0x2e, 0x4f, 0x09, 0x56, 0xac, 0xd1, 0x3e, 0x7e, 0x3a, 0x63, 0xa1, 0x8f, 0xca, 0x32, 0xd6, 0xab, 0x94, 0xb9, 0x4e, 0xd0, 0x33, 0xe9, 0xa1, 0x0f, 0xc5, 0x69, 0x28, 0xbc, 0x8a, 0x0f, 0x4f, 0x8e, 0x95, 0x00
                ],
                rsig: [
                    0x8d, 0xe0, 0x41, 0xe7, 0x09, 0xdb, 0x62, 0x4a, 0xe2, 0xbe, 0x16, 0x48, 0xb6, 0x62, 0x23, 0x9c, 0xde, 0xdf, 0x85, 0xec, 0xd3, 0x82, 0x26, 0x8b, 0x0e, 0x35, 0x54, 0xbf, 0xa0, 0xf2, 0x08, 0x1c, 0xd6, 0x41, 0xbc, 0xa0, 0x40, 0x78, 0xaa, 0x89, 0xf7, 0xdd, 0x25, 0x40, 0x58, 0x7c, 0xed, 0x6b, 0x45, 0x89, 0x16, 0xb1, 0x3e, 0x4b, 0x6a, 0x36, 0x30, 0xda, 0x69, 0x76, 0x46, 0xdb, 0xbf, 0x09
                ],
            },
            TestVector {
                sk: [
                    0x32, 0x16, 0xae, 0x47, 0xe9, 0xf5, 0x3e, 0x8a, 0x52, 0x79, 0x6f, 0x24, 0xb6, 0x24, 0x60, 0x77, 0x6b, 0xd5, 0xf2, 0x05, 0xa7, 0x8e, 0x15, 0x95, 0xbc, 0x8e, 0xfe, 0xdc, 0x51, 0x9d, 0x36, 0x0b
                ],
                vk: [
                    0xdf, 0x74, 0xbf, 0x04, 0x79, 0x61, 0xcc, 0x5c, 0xda, 0xc8, 0x28, 0x90, 0xc7, 0x6e, 0xc6, 0x75, 0xbd, 0x4e, 0x89, 0xea, 0xd2, 0x80, 0xc9, 0x52, 0xd7, 0xc3, 0x3e, 0xea, 0xf2, 0xb5, 0xa6, 0x6b
                ],
                alpha: [
                    0xc9, 0x61, 0xf2, 0xdd, 0x93, 0x68, 0x2a, 0xdb, 0x93, 0xf5, 0xc0, 0x5a, 0x73, 0xfd, 0xbc, 0x6d, 0x43, 0xc7, 0x0e, 0x1b, 0x15, 0xe8, 0xd5, 0x3e, 0x3f, 0x17, 0xa8, 0x24, 0x94, 0xe3, 0xf2, 0x09
                ],
                rsk: [
                    0x44, 0x4b, 0xa9, 0x4e, 0x1e, 0x50, 0xd2, 0x94, 0x63, 0x5e, 0x68, 0xb2, 0x95, 0x01, 0xb5, 0x3e, 0xae, 0x61, 0xcd, 0x1f, 0xbb, 0x3b, 0x84, 0xcd, 0x52, 0xf6, 0x72, 0x9c, 0xfb, 0xcb, 0xab, 0x06
                ],
                rvk: [
                    0x0a, 0xfb, 0xe4, 0x06, 0xa8, 0x91, 0xc3, 0xb8, 0xc3, 0x10, 0xc2, 0x15, 0xbc, 0x68, 0xa9, 0x13, 0xde, 0x7c, 0xda, 0x06, 0xaf, 0x29, 0x42, 0x00, 0x56, 0x46, 0x8d, 0x0c, 0x08, 0x85, 0x5b, 0x28
                ],
                m: [
                    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
                ],
                sig: [
                    0x99, 0x35, 0x80, 0xef, 0x93, 0x34, 0x9a, 0x1c, 0x9e, 0xe9, 0x60, 0xca, 0x3e, 0x7c, 0xd0, 0x4c, 0x13, 0xb4, 0xa0, 0xec, 0x4f, 0xd1, 0x80, 0x53, 0xa1, 0x9c, 0xff, 0x77, 0x63, 0x62, 0x09, 0x65, 0xfb, 0xee, 0x96, 0xc1, 0x64, 0x72, 0x30, 0xe3, 0x73, 0xcb, 0x82, 0xb8, 0x1d, 0x00, 0x03, 0x92, 0x23, 0xd3, 0x0b, 0x39, 0x3e, 0xd1, 0x72, 0xc9, 0xb3, 0xc5, 0x63, 0xc6, 0x11, 0x79, 0x22, 0x05
                ],
                rsig: [
                    0xcc, 0x7a, 0xae, 0x1c, 0xed, 0xad, 0x2d, 0x7f, 0x6c, 0xe0, 0x4c, 0x19, 0xc5, 0xa5, 0xb6, 0xb7, 0xa6, 0xa0, 0x82, 0x78, 0x5c, 0x54, 0x0c, 0x14, 0xf6, 0x30, 0x9b, 0x06, 0x4d, 0x1f, 0xfa, 0x68, 0x17, 0x29, 0x53, 0xfb, 0xa0, 0xc2, 0xfc, 0xfb, 0x87, 0x5c, 0xa7, 0xf7, 0xea, 0x98, 0xef, 0x55, 0xa0, 0x40, 0x2f, 0xd5, 0x29, 0xcf, 0xcd, 0xdf, 0x99, 0x6c, 0xa2, 0xb8, 0xca, 0x89, 0x90, 0x0a
                ],
            },
            TestVector {
                sk: [
                    0x85, 0x83, 0x6f, 0x98, 0x32, 0xb2, 0x8d, 0xe7, 0xc6, 0x36, 0x13, 0xe2, 0xa6, 0xed, 0x36, 0xfb, 0x1a, 0xb4, 0x4f, 0xb0, 0xc1, 0x3f, 0xa8, 0x79, 0x8c, 0xd9, 0xcd, 0x30, 0x30, 0xd4, 0x55, 0x03
                ],
                vk: [
                    0xbf, 0xd5, 0xbc, 0x00, 0xc7, 0xc0, 0x22, 0xaa, 0x89, 0x01, 0xae, 0x08, 0x3c, 0x12, 0xd5, 0x4b, 0x82, 0xf0, 0xdd, 0xff, 0x8e, 0xd6, 0xdb, 0x9a, 0x12, 0xd5, 0x9a, 0x5e, 0xf6, 0xa5, 0xa2, 0xe0
                ],
                alpha: [
                    0xa2, 0xe8, 0xb9, 0xe1, 0x6d, 0x6f, 0xf3, 0xca, 0x6c, 0x53, 0xd4, 0xe8, 0x8a, 0xbb, 0xb9, 0x9b, 0xe7, 0xaf, 0x7e, 0x36, 0x59, 0x63, 0x1f, 0x1e, 0xae, 0x1e, 0xff, 0x23, 0x87, 0x4d, 0x8e, 0x0c
                ],
                rsk: [
                    0x70, 0x3f, 0x32, 0xa3, 0x41, 0x13, 0xea, 0xe1, 0xb0, 0x79, 0x1f, 0xfe, 0x9d, 0x88, 0x88, 0xf0, 0x01, 0x29, 0x9a, 0xe5, 0x19, 0x68, 0x60, 0x91, 0x91, 0x48, 0x99, 0xef, 0xcc, 0x6c, 0x66, 0x01
                ],
                rvk: [
                    0xeb, 0x92, 0x97, 0x03, 0x6c, 0xf5, 0x17, 0xe1, 0x5e, 0x9e, 0xfe, 0x39, 0x75, 0x32, 0x8d, 0xb4, 0x8e, 0xe7, 0xc2, 0x69, 0x4e, 0x94, 0x6d, 0xb2, 0x5f, 0x52, 0x87, 0x88, 0xf6, 0xa1, 0xdb, 0x14
                ],
                m: [
                    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09
                ],
                sig: [
                    0xce, 0x90, 0xdd, 0xf4, 0xaf, 0x21, 0xaa, 0xc4, 0xd9, 0x41, 0x93, 0xea, 0x16, 0xff, 0x35, 0xcd, 0x93, 0x79, 0x20, 0x4e, 0x7d, 0x8f, 0xf4, 0xc0, 0xf5, 0x41, 0x17, 0xab, 0xb1, 0x6b, 0x7c, 0x85, 0xa0, 0xb1, 0x97, 0xcf, 0x13, 0xab, 0x14, 0xd7, 0xc3, 0xba, 0x68, 0x01, 0x0a, 0xb8, 0x05, 0x12, 0x25, 0x91, 0x3b, 0xdb, 0xc3, 0x9a, 0x51, 0xf6, 0x03, 0x7a, 0xfc, 0x6c, 0xee, 0xcb, 0x0b, 0x06
                ],
                rsig: [
                    0xa8, 0x47, 0x74, 0x2e, 0x94, 0x01, 0xcf, 0x22, 0x39, 0x21, 0x3d, 0xc8, 0x81, 0x3e, 0x97, 0x72, 0xe9, 0x7a, 0xf8, 0xd6, 0x7a, 0xdf, 0xfe, 0xab, 0xc8, 0xe6, 0x7f, 0x5d, 0x2d, 0x90, 0xd0, 0xb4, 0x1b, 0xc2, 0x5b, 0x05, 0xf9, 0x4a, 0xce, 0x16, 0x8a, 0xec, 0xc6, 0x58, 0x3e, 0x18, 0xf7, 0x63, 0x74, 0x92, 0xf3, 0x7a, 0x9c, 0xa3, 0x00, 0x20, 0x2b, 0xc0, 0x65, 0xab, 0xd3, 0x80, 0xec, 0x00
                ],
            },
        ];
