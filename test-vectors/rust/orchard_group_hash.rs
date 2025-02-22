        struct TestVector {
            domain: Vec<u8>,
            msg: Vec<u8>,
            point: [u8; 32],
        }

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/orchard_group_hash.py
        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0x54, 0x72, 0x61, 0x6e, 0x73, 0x20, 0x72, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6e, 0x6f, 0x77, 0x21
                ],
                point: [
                    0xd3, 0x6b, 0x0b, 0x64, 0x9b, 0x5c, 0x69, 0x36, 0x02, 0x7a, 0x18, 0x0f, 0x7d, 0x25, 0x40, 0x23, 0x95, 0x6f, 0xc2, 0x88, 0x3d, 0xdf, 0x23, 0xff, 0xc3, 0xc8, 0xfd, 0x1f, 0xa3, 0xcd, 0x18, 0x18
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72
                ],
                msg: vec![
                    0x8f, 0x73, 0x9a, 0x2d, 0x9e, 0x94, 0x5b, 0x0c, 0xe1, 0x52, 0xa8, 0x04, 0x9e, 0x29, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3, 0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90, 0x5d, 0x04, 0x2b, 0xb1, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x8d, 0xbf, 0x69, 0xb8, 0x25, 0x0c, 0x18, 0xef, 0x41, 0x29, 0x4c, 0xa9, 0x79, 0x93, 0xdb, 0x54, 0x6c, 0x1f, 0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e, 0x30, 0xa7, 0x35, 0x94, 0xbf, 0x50, 0x98, 0x42, 0x1c, 0x69, 0x37, 0x8a, 0xf1, 0xe4, 0x0f, 0x64, 0xe1, 0x25, 0x94, 0x6f, 0x62, 0xc2, 0xfa, 0x7b, 0x2f, 0xec, 0xbc, 0xb6, 0x4b, 0x69, 0x68, 0x91
                ],
                point: [
                    0xd3, 0x60, 0x3e, 0x4f, 0x26, 0x67, 0xe7, 0x7c, 0x77, 0x24, 0x8f, 0xd5, 0xbe, 0x8d, 0x80, 0x77, 0x23, 0xd7, 0x27, 0xe2, 0x2f, 0xc4, 0xa1, 0x1d, 0x1f, 0xf5, 0x57, 0xdd, 0x61, 0xdd, 0x4d, 0xb4
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0x81, 0xce, 0x3d, 0xc1, 0x66, 0xd5, 0x6a, 0x1d, 0x62, 0xf5, 0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56, 0xd5, 0x9a, 0xf8, 0x0d, 0x06, 0xa7, 0x45, 0xf4, 0x4a, 0xb0, 0x23, 0x75, 0x2c, 0xb5, 0xb4, 0x06, 0xed, 0x89, 0x85, 0xe1, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97, 0xb0, 0xe4, 0xe4, 0xc7, 0x63, 0xcc, 0xb8, 0xf6, 0x76, 0x49, 0x5c, 0x22, 0x2f, 0x7f, 0xba, 0x1e, 0x31, 0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d, 0x94, 0x90, 0x3d, 0x3c, 0x3e
                ],
                point: [
                    0xf6, 0x1d, 0x4d, 0xe9, 0x90, 0x7a, 0x65, 0x93, 0xd4, 0xc6, 0xb6, 0x42, 0x47, 0x5f, 0x51, 0xca, 0x28, 0x93, 0xfc, 0xcf, 0x9c, 0x48, 0xf5, 0x28, 0x2d, 0xf2, 0x5c, 0x9b, 0xb6, 0xda, 0xd9, 0x03
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0x36, 0x0c, 0x1d, 0x37, 0x10, 0xac, 0xd2, 0x0b, 0x18, 0x3e, 0x31, 0xd4, 0x9f, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0, 0x4b, 0xe3, 0x4a, 0x98, 0x51, 0xa7, 0xaf, 0x9d, 0xb6, 0x99, 0x0e, 0xd8, 0x3d, 0xd6, 0x4a, 0xf3, 0x59, 0x7c, 0x04, 0x32, 0x3e, 0xa5, 0x1b, 0x00, 0x52, 0xad, 0x80, 0x84, 0xa8, 0xb9, 0xda, 0x94, 0x8d, 0x32, 0x0d, 0xad, 0xd6, 0x4f, 0x54, 0x31, 0xe6, 0x1d, 0xdf, 0x65, 0x8d, 0x24, 0xae, 0x67, 0xc2, 0x2c, 0x8d, 0x13, 0x09, 0x13, 0x1f, 0xc0, 0x0f, 0xe7, 0xf2, 0x35, 0x73, 0x42, 0x76, 0xd3, 0x8d, 0x47, 0xf1, 0xe1, 0x91, 0xe0, 0x0c, 0x7a, 0x1d, 0x48, 0xaf, 0x04, 0x68, 0x27, 0x59, 0x1e, 0x97, 0x33, 0xa9, 0x7f, 0xa6, 0xb6, 0x79, 0xf3, 0xdc, 0x60, 0x1d, 0x00, 0x82, 0x85, 0xed, 0xcb, 0xda, 0xe6, 0x9c, 0xe8, 0xfc, 0x1b, 0xe4, 0xaa, 0xc0, 0x0f, 0xf2, 0x71, 0x1e, 0xbd, 0x93, 0x1d, 0xe5, 0x18, 0x85, 0x68, 0x78, 0xf7, 0x34, 0x76, 0xf2, 0x1a, 0x48, 0x2e, 0xc9, 0x37, 0x83, 0x65, 0xc8, 0xf7, 0x39, 0x3c, 0x94, 0xe2, 0x88, 0x53, 0x15, 0xeb, 0x46, 0x71, 0x09, 0x8b, 0x79, 0x53, 0x5e, 0x79, 0x0f, 0xe5, 0x3e, 0x29, 0xfe, 0xf2, 0xb3, 0x76, 0x66, 0x97, 0xac, 0x32, 0xb4, 0xf4, 0x73, 0xf4, 0x68, 0xa0, 0x08, 0xe7, 0x23, 0x89, 0xfc, 0x03, 0x88, 0x0d, 0x78, 0x0c, 0xb0, 0x7f, 0xcf, 0xaa, 0xbe, 0x3f, 0x1a, 0x84, 0xb2, 0x7d, 0xb5, 0x9a, 0x4a
                ],
                point: [
                    0xe9, 0xdc, 0xf5, 0xfd, 0x98, 0xcb, 0x6f, 0xd4, 0xfd, 0xc0, 0xf8, 0xf9, 0xdd, 0x46, 0x2d, 0x59, 0xe1, 0xde, 0x9c, 0x69, 0xc6, 0x04, 0x2d, 0x1a, 0xee, 0x40, 0xd1, 0xb5, 0xf8, 0x2e, 0xf9, 0x34
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72
                ],
                msg: vec![
                    0x88, 0x2d, 0x2b, 0x21, 0x03, 0x59, 0x65, 0x55, 0xed, 0x94, 0x94, 0xc6, 0xac, 0x89, 0x3c, 0x49, 0x72, 0x38, 0x33, 0xec, 0x89, 0x26, 0xc1, 0x03, 0x95, 0x86, 0xa7, 0xaf, 0xcf, 0x4a, 0x0d, 0x9c, 0x73, 0x1e, 0x98, 0x5d, 0x99, 0x58, 0x9c, 0x8b, 0xb8, 0x38, 0xe8, 0xaa, 0xf7, 0x45, 0x53, 0x3e, 0xd9, 0xe8, 0xae, 0x3a, 0x1c, 0xd0, 0x74, 0xa5, 0x1a, 0x20, 0xda, 0x8a, 0xba
                ],
                point: [
                    0xf3, 0x8c, 0xb5, 0xe1, 0x60, 0x7c, 0x71, 0x22, 0xce, 0xf7, 0x31, 0xc8, 0xe6, 0x18, 0x75, 0xb8, 0xc1, 0xf3, 0xe2, 0xec, 0x06, 0xc5, 0x9e, 0x9c, 0xca, 0xdb, 0xd3, 0xa2, 0xca, 0xe8, 0x68, 0x3f
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0xdb, 0xeb, 0xbc, 0x86, 0x2d, 0xed, 0x42, 0x43, 0x5e, 0x92, 0x47, 0x69, 0x30, 0xd0, 0x69, 0x89, 0x6c, 0xff, 0x30, 0xeb, 0x41, 0x4f, 0x72, 0x7b, 0x89, 0xe0, 0x01, 0xaf, 0xa2, 0xfb, 0x8d, 0xc3, 0x43, 0x6d, 0x75, 0xa4, 0xa6, 0xf2, 0x65, 0x72, 0x50, 0x4b, 0x19, 0x22, 0x32, 0xec, 0xb9, 0xf0, 0xc0, 0x24, 0x11, 0xe5, 0x25, 0x96, 0xbc, 0x5e, 0x90, 0x45, 0x7e, 0x74, 0x59, 0x39, 0xff, 0xed, 0xbd, 0x12, 0x86, 0x3c, 0xe7, 0x1a, 0x02, 0xaf, 0x11, 0x7d, 0x41, 0x7a, 0xdb, 0x3d, 0x15, 0xcc, 0x54, 0xdc, 0xb1, 0xfc, 0xe4, 0x67, 0x50, 0x0c, 0x6b, 0x8f, 0xb8, 0x6b, 0x12, 0xb5, 0x6d, 0xa9, 0xc3, 0x82, 0x85, 0x7d, 0xee, 0xcc, 0x40, 0xa9, 0x8d, 0x5f, 0x29, 0x35, 0x39, 0x5e, 0xe4, 0x76, 0x2d, 0xd2, 0x1a, 0xfd, 0xbb, 0x5d, 0x47, 0xfa, 0x9a, 0x6d, 0xd9, 0x84, 0xd5, 0x67, 0xdb, 0x28, 0x57, 0xb9, 0x27, 0xb7, 0xfa, 0xe2, 0xdb, 0x58, 0x71, 0x05, 0x41, 0x5d, 0x46, 0x42, 0x78, 0x9d, 0x38, 0xf5, 0x0b, 0x8d, 0xbc, 0xc1, 0x29, 0xca, 0xb3, 0xd1, 0x7d, 0x19, 0xf3, 0x35, 0x5b, 0xcf, 0x73, 0xce, 0xcb, 0x8c, 0xb8, 0xa5, 0xda, 0x01, 0x30, 0x71, 0x52, 0xf1, 0x39, 0x36, 0xa2, 0x70, 0x57, 0x26, 0x70, 0xdc, 0x82, 0xd3, 0x90, 0x26, 0xc6, 0xcb, 0x4c, 0xd4, 0xb0, 0xf7, 0xf5, 0xaa, 0x2a, 0x4f, 0x5a, 0x53, 0x41, 0xec, 0x5d, 0xd7, 0x15, 0x40, 0x6f, 0x2f, 0xdd, 0x2a, 0xfa, 0x73, 0x3f
                ],
                point: [
                    0x3d, 0xec, 0x03, 0x28, 0x60, 0xf1, 0xa8, 0x51, 0x51, 0x6a, 0xf3, 0x7b, 0x68, 0xac, 0xcc, 0xf3, 0x6e, 0x2a, 0x80, 0xbe, 0x13, 0xee, 0x36, 0x7e, 0xac, 0x1a, 0xac, 0x72, 0x5d, 0xbc, 0xf6, 0x85
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72
                ],
                msg: vec![
                    0x1c, 0x8c, 0x21, 0x86, 0x2a, 0x1b, 0xaf, 0xce, 0x26, 0x09, 0xd9, 0xee, 0xcf, 0xa1, 0x58, 0xcf, 0xb5, 0xcd, 0x79, 0xf8, 0x80, 0x08, 0xe3, 0x15, 0xdc, 0x7d, 0x83, 0x88, 0xe7, 0x6c, 0x17, 0x82, 0xfd, 0x27, 0x95, 0xd1, 0x8a, 0x76, 0x36, 0x24, 0xc2, 0x5f, 0xa9, 0x59, 0xcc, 0x97, 0x48, 0x9c, 0xe7, 0x57, 0x45, 0x82, 0x4b, 0x77, 0x86, 0x8c, 0x53, 0x23, 0x9c, 0xfb, 0xdf, 0x73, 0xca, 0xec, 0x65, 0x60, 0x40, 0x37, 0x31, 0x4f, 0xaa, 0xce, 0xb5, 0x62, 0x18, 0xc6, 0xbd, 0x30, 0xf8, 0x37, 0x4a, 0xc1, 0x33, 0x86, 0x79, 0x3f, 0x21, 0xa9, 0xfb, 0x80, 0xad, 0x03, 0xbc, 0x0c, 0xda, 0x4a, 0x44, 0x94, 0x6c, 0x00
                ],
                point: [
                    0xae, 0x52, 0x88, 0x72, 0xf0, 0x6c, 0xc1, 0x79, 0xa1, 0x54, 0xee, 0xc2, 0xdd, 0xf7, 0x4d, 0xcf, 0x5c, 0x49, 0xc4, 0x11, 0x5c, 0x6a, 0xb7, 0x4d, 0x7f, 0x31, 0x6e, 0x46, 0xb1, 0x64, 0x8e, 0x19
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72
                ],
                msg: vec![
                    0xa1, 0xdf, 0x0e, 0x5b, 0x87, 0xb5, 0xbe, 0xce, 0x47, 0x7a, 0x70, 0x96, 0x49, 0xe9, 0x50, 0x06, 0x05, 0x91, 0x39, 0x48, 0x12, 0x95, 0x1e, 0x1f, 0xe3, 0x89, 0x5b, 0x8c, 0xc3, 0xd1, 0x4d, 0x2c, 0xf6, 0x55, 0x6d, 0xf6, 0xed, 0x4b, 0x4d, 0xdd, 0x3d, 0x9a, 0x69, 0xf5, 0x33, 0x57, 0xd7, 0x76, 0x7f, 0x4f, 0x5c, 0xcb, 0xdb, 0xc5, 0x96, 0x63, 0x12, 0x77, 0xf8, 0xfe, 0xcd, 0x08, 0xcb, 0x05, 0x6b, 0x95, 0xe3, 0x02, 0x5b, 0x97, 0x92, 0xff, 0xf7, 0xf2, 0x44, 0xfc, 0x71, 0x62, 0x69, 0xb9, 0x26, 0xd6, 0x2e, 0x95, 0x96, 0xfa, 0x82, 0x5c, 0x6b, 0xf2, 0x1a, 0xff, 0x9e, 0x68, 0x62, 0x5a, 0x19, 0x24, 0x40, 0xea, 0x06, 0x82, 0x81, 0x23, 0xd9, 0x78, 0x84, 0x80, 0x6f, 0x15, 0xfa, 0x08, 0xda, 0x52, 0x75, 0x4a, 0x10, 0x95, 0xe3, 0xff, 0x1a, 0xbd, 0x5c, 0xe4, 0xfd, 0xdf, 0xcc, 0xfc, 0x3a, 0x61, 0x28, 0xae, 0xf7, 0x84, 0xa6, 0x46, 0x10, 0xa8, 0x9d, 0x1a, 0x70, 0x99, 0x21, 0x6d, 0x08, 0x14, 0xd3, 0xa2, 0xd4, 0x52, 0x43, 0x1c, 0x32, 0xd4, 0x11, 0xac, 0x1c, 0xce, 0x82, 0xad, 0x02, 0x29, 0x40, 0x7b, 0xbc, 0x48, 0x98, 0x56, 0x75, 0xe3, 0xf8, 0x74, 0xa4, 0x53, 0x3f, 0x1d, 0x63
                ],
                point: [
                    0xcc, 0x90, 0x4e, 0x5e, 0x31, 0x83, 0x4b, 0x4f, 0x85, 0xd6, 0xa6, 0x62, 0xc5, 0x4e, 0x7d, 0xaa, 0x8d, 0x3e, 0x34, 0xce, 0x22, 0x42, 0x8c, 0x3e, 0x8a, 0x53, 0xcc, 0x6e, 0xe8, 0x33, 0x87, 0xa9
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0xfa, 0x3e, 0x0f, 0x46, 0x0f, 0xe2, 0xf5, 0x7e, 0x34, 0xfb, 0xc7, 0x54, 0x23, 0xc3, 0x73, 0x7f, 0x5b, 0x2a, 0x06, 0x15, 0xf5, 0x72, 0x2d, 0xb0, 0x41, 0xa3, 0xef, 0x66, 0xfa, 0x48, 0x3a, 0xfd, 0x3c, 0x2e, 0x19, 0xe5, 0x94, 0x44, 0xa6, 0x4a, 0xdd, 0x6d, 0xf1, 0xd9, 0x63, 0xf5, 0xdd, 0x5b, 0x50, 0x10, 0xd3, 0xd0, 0x25, 0xf0, 0x28, 0x7c, 0x4c, 0xf1, 0x9c, 0x75, 0xf3, 0x3d, 0x51, 0xdd, 0xdd, 0xba, 0x5d, 0x65, 0x7b, 0x43, 0xee, 0x8d, 0xa6, 0x45, 0x44, 0x38, 0x14
                ],
                point: [
                    0xb0, 0x5e, 0xb0, 0xcc, 0x20, 0xef, 0x29, 0xfd, 0xb9, 0xf5, 0x8f, 0x6b, 0x55, 0x99, 0x11, 0x4d, 0x1b, 0xf8, 0x21, 0x49, 0x7a, 0xf7, 0xc1, 0x07, 0xea, 0x0b, 0xdf, 0xf9, 0x74, 0xf1, 0x7f, 0x3b
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0x29, 0xf3, 0xe9, 0xb4, 0xe5, 0x4c, 0x23, 0x6c, 0x29, 0xaf, 0x39, 0x23, 0x10, 0x17, 0x56, 0xd9, 0xfa, 0x4b, 0xd0, 0xf7, 0xd2, 0xdd, 0xaa, 0xcb, 0x6b, 0x0f, 0x86, 0xa2, 0x65, 0x8e, 0x0a, 0x07, 0xa0, 0x5a, 0xc5, 0xb9, 0x50, 0x05, 0x1c, 0xd2, 0x4c, 0x47, 0xa8, 0x8d, 0x13, 0xd6, 0x59, 0xba, 0x2a, 0x46, 0xca, 0x18, 0x30, 0x81, 0x6d, 0x09, 0xcd, 0x76, 0x46, 0xf7, 0x6f, 0x71, 0x6a, 0xbe, 0xc5, 0xde, 0x07, 0xfe, 0x9b, 0x52, 0x34, 0x10, 0x80, 0x6e, 0xa6, 0xf2, 0x88, 0xf8, 0x73, 0x6c, 0x23, 0x35, 0x7c, 0x85, 0xf4, 0x57, 0x91, 0xe1, 0x70, 0x80, 0x29, 0xd9, 0x82, 0x4d, 0x90, 0x70, 0x46, 0x07, 0xf3, 0x87, 0xa0, 0x3e, 0x49, 0xbf, 0x98, 0x36, 0x57, 0x44, 0x31, 0x34, 0x5a, 0x78, 0x77, 0xef, 0xaa
                ],
                point: [
                    0x52, 0x71, 0xbe, 0xd5, 0x91, 0x13, 0x39, 0xa7, 0xc6, 0x17, 0x97, 0xa9, 0x9e, 0x87, 0xc6, 0xb4, 0xcd, 0x85, 0xae, 0x10, 0xd0, 0xd4, 0xaa, 0x7e, 0x7a, 0xdb, 0x07, 0x49, 0x81, 0x63, 0x05, 0xae
                ],
            },
            TestVector {
                domain: vec![
                    0x7a, 0x2e, 0x63, 0x61, 0x73, 0x68, 0x3a, 0x74, 0x65, 0x73, 0x74
                ],
                msg: vec![
                    0xe7, 0x30, 0x81, 0xef, 0x8d, 0x62, 0xcb, 0x78
                ],
                point: [
                    0xb6, 0x17, 0x44, 0xc0, 0xc7, 0x0d, 0x65, 0x4c, 0x02, 0x53, 0x70, 0x55, 0x7a, 0xac, 0x7f, 0xbe, 0x42, 0x1a, 0x49, 0x70, 0x77, 0x18, 0xba, 0x90, 0xff, 0x7d, 0x9e, 0xbd, 0xc5, 0x1d, 0x19, 0x19
                ],
            },
        ];
