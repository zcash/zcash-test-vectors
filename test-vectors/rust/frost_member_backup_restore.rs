// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/frost_member_backup.py

pub(crate) struct TestVector {
    pub(crate) encoding: &'static str,
    pub(crate) ufvk: &'static str,
    pub(crate) derivation: Option<&'static str>,
    pub(crate) reason: &'static str,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        ufvk: "uview1mvknnjr2s9cuc7z5kjsd3twesswde37tpfw2z4v5a8jmsnwdwsg8sc2hdq302ud7j57d7dvmmt6mtc6c3fk7zkdyx5mrhq8fvyw8xp0dlgzl8kkwawt9j7m9z5adwpuskfscg5fyrpc0sca8lydtxfw7hfaaydtg88ayqj6y89a9jllhupn3hzgp7vq6d",
        derivation: Some("zip2005"),
        reason: "ZIP 2005 group",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqupdyxkvecp0aqkg54rcjsjxlqf7apvw4q600dwwtqgnltgk0l8pe8jaqq84ellmwx7eu88eeggvpzpy2akn2vxp36vxkn40mvvsnemc7jls6u",
        ufvk: "uview1mlytly7fqp0ztxr7zg3hfl4cfhnpphcghkusfvj7mg9zxv6zy558aekax6rtckvnht27vtdk4mpas53p0smx86p4dkfw86tqnsyl65y29t83skyuvnmcgfv8jk3pct3qsk5auhl33atpdvzp7se2a063qgp4dzh00s926xlkdatsypmst9u6y8gfa47mq",
        derivation: Some("legacy"),
        reason: "legacy group",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqupdyxkvecp0aqkg54rcjsjxlqf7apvw4q600dwwtqgnltgk0l8pe8jaqq84ellmwx7eu88eeggvpzpy2akn2vxp36vxkn40mvvsnemc7jls6u",
        ufvk: "uview1ehqx46eu0e32fpxwgzx0dv0f6e6g53v59gpt2dqf40670yn487t3s8rhjlrgzx77k8fzm25x2adrhnqrz96gtka2th67gkawmhxz5q3y4wcuj3yzgj3dr3yf75v0ta8afnhq5xp0qd4rn8efqe2fygqukttsznksgkvchtc7gwuk2jqjv0u3mzghvudz6",
        derivation: Some("zip2005"),
        reason: "legacy group's string with the ZIP 2005 viewing key from the same sk and ak",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        ufvk: "uview1wwwezka5meumwxsrdkaka59edkgq2999traskraugftk89869u5d7c5ypcawzlws74nu2uwfarhrzh3z5ecc7e88lejqvy3fy7fft8ftulvdm8eyg9gysn6pu0pcgrd7f0xklum9ragw0njg3dekwn3akndjulv72a02gwn5m9v3p24gwuaqwvgh57p0k",
        derivation: None,
        reason: "viewing key of another group",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqcpqqqqqg0tg6xdm2y5p87fs33zqqqqqqqqqqqqqqqqqqqqqqqqgqjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxp07z7c",
        ufvk: "uview1mvknnjr2s9cuc7z5kjsd3twesswde37tpfw2z4v5a8jmsnwdwsg8sc2hdq302ud7j57d7dvmmt6mtc6c3fk7zkdyx5mrhq8fvyw8xp0dlgzl8kkwawt9j7m9z5adwpuskfscg5fyrpc0sca8lydtxfw7hfaaydtg88ayqj6y89a9jllhupn3hzgp7vq6d",
        derivation: None,
        reason: "non-canonical signing share (the Pallas scalar modulus)",
    },
    TestVector {
        encoding: "zkfrost1qyqsyqev42j6ml9d3tqthrzsmndmc854fqjmuspljl6yhswkc4p7zh208vjv7y78y36c3psy3czcxn2apfjya8ywz4whuzav8uj4s6mv4gguxm4ktp7",
        ufvk: "uview1fxwd87wc360kpkye42gul65r0yc4qgsn7tnywsf9ngtqqhg4qtv5r5lv0wcd7gghvasxawmccfsah5jqquleahngy3gjeeyslm5l2v7sc6ykjx3psdt8le3g9vjm4ynusrydwl2h2cmsr58r9z5m7cn0u6730d6s6w97gtx2vcp8tfzc3uydg6n5zak7kgz73ck3qhqldd2k7erhwz576p87eexfqr5vq952t9khyvvqwa29",
        derivation: None,
        reason: "viewing key with no Orchard component",
    },
];
