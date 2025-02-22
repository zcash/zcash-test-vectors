        struct TestVector {
            t_addr: &'static str,
            p2pkh_bytes: [u8; 20],
            tex_addr: &'static str,
            account: u32,
            child_index: u32,
        }

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zcash_test_vectors/transparent/zip_0320.py
        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                t_addr: "t1V9mnyk5Z5cTNMCkLbaDwSskgJZucTLdgW",
                p2pkh_bytes: [
                    0x7b, 0xb8, 0x35, 0x70, 0xb8, 0xfa, 0xe1, 0x46, 0xe0, 0x3c, 0x53, 0x31, 0xa0, 0x20, 0xb1, 0xe0, 0x89, 0x2f, 0x63, 0x1d
                ],
                tex_addr: "tex10wur2u9clts5dcpu2vc6qg93uzyj7cca2xm732",
                account: 0,
                child_index: 0,
            },
            TestVector {
                t_addr: "t1LZdE42PAt1wREUv1YMYRFwJDPHPW8toLL",
                p2pkh_bytes: [
                    0x1d, 0x81, 0xe8, 0x67, 0x91, 0xc7, 0x2d, 0x29, 0x2f, 0x90, 0x6e, 0x7c, 0x03, 0x9a, 0x72, 0x9e, 0x4b, 0x1f, 0xf7, 0xfc
                ],
                tex_addr: "tex1rkq7seu3cukjjtusde7q8xnjne93laluyvdxu7",
                account: 0,
                child_index: 1,
            },
            TestVector {
                t_addr: "t1M5AgJw56FNFRBNGtzAGX4AHfQh7ZCxd4w",
                p2pkh_bytes: [
                    0x23, 0x18, 0x39, 0xe3, 0x05, 0xc0, 0xa0, 0x2e, 0xd6, 0x81, 0x40, 0x6f, 0xaf, 0x22, 0x25, 0x85, 0xf6, 0x62, 0x39, 0x04
                ],
                tex_addr: "tex1yvvrncc9czsza45pgph67g39shmxywgyvsypwn",
                account: 0,
                child_index: 2,
            },
            TestVector {
                t_addr: "t1bh6KjXccz6Ed45vFc3GeqoxWbwPxe8w2n",
                p2pkh_bytes: [
                    0xc3, 0x75, 0x53, 0x98, 0xb8, 0xb7, 0x7f, 0x63, 0x3f, 0xca, 0x7c, 0xcb, 0xda, 0x90, 0x08, 0x31, 0x47, 0x89, 0x79, 0xc9
                ],
                tex_addr: "tex1cd648x9ckalkx0720n9a4yqgx9rcj7wfvjcq63",
                account: 1,
                child_index: 0,
            },
            TestVector {
                t_addr: "t1WvCtHojWHSHBdDtCFgorUN1TzUFV8sCth",
                p2pkh_bytes: [
                    0x8f, 0x17, 0x95, 0x0e, 0x22, 0xb0, 0x88, 0x86, 0xac, 0x48, 0x32, 0xe2, 0x2e, 0x24, 0xf2, 0xe8, 0xf3, 0xcb, 0x6b, 0x21
                ],
                tex_addr: "tex13ute2r3zkzygdtzgxt3zuf8jareuk6ep7qd8ty",
                account: 1,
                child_index: 1,
            },
            TestVector {
                t_addr: "t1U2MF7f81qrXkWouT3Xt4hLDAMjC9LniTK",
                p2pkh_bytes: [
                    0x6f, 0x58, 0xad, 0xaf, 0x02, 0xbb, 0x48, 0xe6, 0xb3, 0x98, 0xa4, 0x42, 0xa2, 0xb2, 0x94, 0x58, 0x9e, 0x04, 0x16, 0x20
                ],
                tex_addr: "tex1dav2mtczhdywdvuc53p29v55tz0qg93qvfjp46",
                account: 1,
                child_index: 2,
            },
            TestVector {
                t_addr: "t1awMYfhispKsnJPHn7jgUxNnVW1DTpTJx9",
                p2pkh_bytes: [
                    0xbb, 0x2f, 0xbb, 0x54, 0x0f, 0x0f, 0x7e, 0x43, 0x46, 0x36, 0x68, 0x0e, 0xae, 0xa2, 0xee, 0xfe, 0x37, 0x5a, 0x75, 0x91
                ],
                tex_addr: "tex1hvhmk4q0palyx33kdq82aghwlcm45av3ezlrzn",
                account: 2,
                child_index: 0,
            },
            TestVector {
                t_addr: "t1Kgn7v5a2rKkxC24LoXNyHRn4q4Gs3KEEF",
                p2pkh_bytes: [
                    0x13, 0xe4, 0x1e, 0x47, 0x44, 0x81, 0x22, 0xca, 0xd1, 0x3c, 0x5c, 0x7f, 0x5b, 0xd3, 0x1c, 0x77, 0x63, 0x9a, 0x9f, 0x99
                ],
                tex_addr: "tex1z0jpu36ysy3v45fut3l4h5cuwa3e48uea95pc6",
                account: 2,
                child_index: 1,
            },
            TestVector {
                t_addr: "t1c1ixUTuStCzo19qPg89U9XFYmWDLru9mt",
                p2pkh_bytes: [
                    0xc6, 0xfb, 0x64, 0xd8, 0x75, 0x7e, 0x5c, 0x85, 0xb2, 0x30, 0xa3, 0x35, 0x87, 0x11, 0x69, 0x7a, 0xe6, 0x54, 0x0b, 0x44
                ],
                tex_addr: "tex1cmakfkr40ewgtv3s5v6cwytf0tn9gz6y9j5z8e",
                account: 2,
                child_index: 2,
            },
            TestVector {
                t_addr: "t1WBxR5jNWgg4Cqeot3FvNkBb9ztYyjVELp",
                p2pkh_bytes: [
                    0x87, 0x1a, 0x08, 0x9d, 0x44, 0x62, 0x68, 0xaa, 0x7a, 0xc0, 0x3d, 0x2a, 0x6f, 0x60, 0xae, 0x70, 0x80, 0x8f, 0x39, 0x74
                ],
                tex_addr: "tex1sudq382yvf5257kq854x7c9wwzqg7wt5h2c24u",
                account: 3,
                child_index: 0,
            },
            TestVector {
                t_addr: "t1VEuDXP1QocoNaxrq4gZArTqqKCZdrwjG7",
                p2pkh_bytes: [
                    0x7c, 0xb0, 0x7c, 0x31, 0xb5, 0x80, 0x40, 0xac, 0x7c, 0xc1, 0x2b, 0xfa, 0xaa, 0x13, 0x8c, 0xfb, 0xef, 0xb3, 0x84, 0x57
                ],
                tex_addr: "tex10jc8cvd4spq2clxp90a25yuvl0hm8pzheuufxw",
                account: 3,
                child_index: 1,
            },
            TestVector {
                t_addr: "t1PXVM8oR6qVrVjtcnU1iNmH2CfvZyBai8u",
                p2pkh_bytes: [
                    0x3e, 0x02, 0xe0, 0x8b, 0x59, 0x65, 0xfc, 0xe9, 0xc2, 0x0c, 0xe6, 0xde, 0x6f, 0x94, 0x07, 0x67, 0x4d, 0x01, 0xba, 0x02
                ],
                tex_addr: "tex18cpwpz6evh7wnssvum0xl9q8vaxsrwsz83vght",
                account: 3,
                child_index: 2,
            },
            TestVector {
                t_addr: "t1M3p1MgJCgjq4FMogS84kVvuszJbxPnpSM",
                p2pkh_bytes: [
                    0x22, 0xd6, 0x8d, 0xeb, 0xb3, 0x92, 0x8d, 0xa4, 0x04, 0x63, 0x70, 0xd2, 0x5e, 0xd2, 0xbb, 0xe8, 0xd5, 0xe9, 0x85, 0xd0
                ],
                tex_addr: "tex1yttgm6anj2x6gprrwrf9a54mar27npws73jwdy",
                account: 4,
                child_index: 0,
            },
            TestVector {
                t_addr: "t1aqnebXhA45WpgQHLiXTPU1Kk6rp8vVDDr",
                p2pkh_bytes: [
                    0xba, 0x22, 0x30, 0xb4, 0x1f, 0xdc, 0x81, 0x71, 0x43, 0x28, 0x23, 0x1f, 0x40, 0xab, 0x73, 0xfe, 0xb5, 0x26, 0x45, 0xa4
                ],
                tex_addr: "tex1hg3rpdqlmjqhzsegyv05p2mnl66jv3dykth955",
                account: 4,
                child_index: 1,
            },
            TestVector {
                t_addr: "t1UG6FVxexmJRFXG4gvEmSF9HSTwHMFaSDT",
                p2pkh_bytes: [
                    0x71, 0xf1, 0xfc, 0x6f, 0xd6, 0x93, 0x70, 0xf2, 0x36, 0x11, 0x53, 0x6b, 0x3b, 0x64, 0xe7, 0xdf, 0x1c, 0xeb, 0xef, 0x69
                ],
                tex_addr: "tex1w8clcm7kjdc0yds32d4nke88muwwhmmfunhkhd",
                account: 4,
                child_index: 2,
            },
        ];
