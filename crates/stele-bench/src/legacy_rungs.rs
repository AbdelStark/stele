//! Frozen BLAKE3 hashes of the 60 historical pre-E17-02 development ledgers in
//! `bench/ledger/` that predate the RFC-0018 A2 `model_config.rung` requirement.
//! Any new or edited development ledger must carry a valid `model_config.rung`.

pub(crate) const PRE_E17_02_DEVELOPMENT_LEDGER_BLAKE3: &[&str] = &[
    "9c94fd8c5363156ab63fb27ec25b3e765c4cef1e6e65cbaf981418a705fe944c", // e16-11-dev-stories42m.json
    "7c79147dae4a30b827bf58d9c1311e68effd6679475a026a718e89dbd2031506", // e16-11-dev-synthetic-8layer.json
    "c461470f504fbbc374c8aa0d7fabd87211aff7cc313deefdebb1bfa465567b0b", // e16-18-dev-stories42m.json
    "b287f798fd972258da35059ccb25c1531a874a9ea225f5fca7238f02eb46f49e", // e16-18-dev-synthetic-8layer.json
    "2ee1be62d26f18f3816ca2935719934c54a7c3d1492522ed3359d8efaf2291c3", // e16-20-dev-stories110m.json
    "f5d53277a36b80ebeed75d2605546b260a45c63ad8ab63d77778a974d0cb632b", // e16-40a-dev-zk-stories42m-t32-h100-0.json
    "3c0d40cb5663f498c063d4374fb98c5c5d580c35b0a2ee15fc53779a113735f5", // e16-40a-dev-zk-stories42m-t32-h100-1.json
    "12b11680fe8a11f8044f1318b5ce25db467c7384e5e8fd6c55103f07db44ef86", // e16-40a-dev-zk-stories42m-t32-h100-2.json
    "249ecf3950dff9231cb9b5be7f38fe94997ae0c240811f09a25aa3e019a03fe0", // e16-40o-dev-zk-stories42m-t32-mac-0.json
    "be5fd11bb8a97e59de95bcba73fa0a8f0c029ab567b32db3c970892510654a5a", // e16-40o-dev-zk-stories42m-t32-mac-1.json
    "30a56e4772cab471031d5e723e0ce9171d887aef346829fa96f810262f7dbdbd", // e16-40o-dev-zk-stories42m-t32-mac-2.json
    "348c5179b66ef0e2dcf7d6907f605e04d4c03cdbe763528d490e2ad5004b223c", // e16-41-dev-zk-stories42m-t32-mac-0.json
    "24fba93f8b4712e1240e41c922a43bf9b8f4adee943c1a469b4f20f925f7a939", // e16-41-dev-zk-stories42m-t32-mac-1.json
    "c6c641cfe302edc2a773b2e8e9e03404d4a8316373f52806522f3a89c01fdae1", // e16-41-dev-zk-stories42m-t32-mac-2.json
    "37eb8cf3243ae45f6c081877974d0b9d3a05dfad42194c9ebd9facc3e009d536", // e16-42-dev-zk-stories42m-t32-mac-0.json
    "5355d1948603e5a980a5107d79ca4f477d06993323eee0ebe683e22c3f28dbc1", // e16-42-dev-zk-stories42m-t32-mac-1.json
    "609aa8894a2dbf9c180733f2deef7807a666f4c3527e73e044c0561ba86bf2aa", // e16-42-dev-zk-stories42m-t32-mac-2.json
    "a8de551a0a64b11e4d0ad7aa4839cb4fc053b43054f232840549fd8e616b3be3", // e16-43-dev-zk-stories42m-t32-mac-0.json
    "79d38dcd6af263f1e4599aafda73342d90eec78371892b908eced7dc33ea181d", // e16-43-dev-zk-stories42m-t32-mac-1.json
    "43fcd3557c73ebacb5dc10d2355ac15852bff85fc2eeb27f9f1fb70fe3377164", // e16-43-dev-zk-stories42m-t32-mac-2.json
    "4b09da27a13934f02ee8a7c1f171bf66c21ba74d0993b380591f6626c68c3a21", // e16-44-dev-zk-stories42m-t32-mac-0.json
    "a624aec278dc462de7d0ef878141d0de92aab70a5234b0eb09b23f5969c625c5", // e16-44-dev-zk-stories42m-t32-mac-1.json
    "8f3c896d2864a652cf5159e04fd4b55a8baaa684928e839ea3035d0b05a6b8af", // e16-44-dev-zk-stories42m-t32-mac-2.json
    "115d2d0a85f8e89dba4d2b2bddcc12b7af476efa9710e62306b7352b6820fc40", // e16-45-dev-zk-stories42m-t32-h100-node-cpu-0.json
    "311afcd8f957e34dad8a97ae778e263a617ab23ba1ad7fb86bb9f966b5e51a32", // e16-45-dev-zk-stories42m-t32-h100-node-cpu-1.json
    "211ed9a1e5e919524b7e98e21c060ef494df6dba0331584d69f79710a5781db8", // e16-45-dev-zk-stories42m-t32-h100-node-cpu-2.json
    "8f340db8bd98e21c19f1dfddff93c83c664d7c8f2aedf47812c99e7add350d2a", // e16-45-dev-zk-stories42m-t32-mac-0.json
    "c85b61072e8b4fbefa6e7731ec0617b4d9b1be86ee6c2e0398bac894aed17b1b", // e16-45-dev-zk-stories42m-t32-mac-1.json
    "9705ff19429282db94f3f94d7dc75fad3c6bdc2ef53453ebdd118ab64d32184c", // e16-45-dev-zk-stories42m-t32-mac-2.json
    "3910bb18adc8f51249982ebb752b1e744b70597762b5b6aca5b71e6a28b36346", // e20-12-dev-zk-stories42m-t32-h100-cpu.json
    "20a978863035ac3f79b089af005922ee11e7c3eef77bb894b644a1bd4a973d42", // e20-12-dev-zk-stories42m-t32-h100-cuda.json
    "f98907eb6c7ab7c02fd25f3dc17f3a8d3562ab9683d0c3f0d1f29b09e0cfa726", // e20-12-e45-dev-zk-stories42m-t32-h100-cpu-1.json
    "71b3d7250d835213bd33c98f58fb6348b7ef2e36d4297e4c9db2de97b3b10c17", // e20-12-e45-dev-zk-stories42m-t32-h100-cpu-2.json
    "8b98fe3ac68de0fa945074542314303be0a5320738bba6f84b63409b055141ce", // e20-12-e45-dev-zk-stories42m-t32-h100-cpu-5.json
    "eace3a1a608c1dc66092f406041c33fb8b6dcfc45055458c3c29e444c6a4aee1", // e20-12-e45-dev-zk-stories42m-t32-h100-cuda-0.json
    "ba29ccb0f6c24ede325391920c6c907f650b67d883ac01bc87530c9c3a4ec5c5", // e20-12-e45-dev-zk-stories42m-t32-h100-cuda-3.json
    "b0182e67ad5844acb8e3f3d5cab814012b84965b58656fb200edd9a58e70dc5d", // e20-12-e45-dev-zk-stories42m-t32-h100-cuda-4.json
    "3fa963f16cc3acd8a2636ba3dca5e76c96800c67e4a9b03cf261d86b2be05088", // e20-14-dev-zk-stories42m-t32-h100-cpu.json
    "41086ffd93782175ff711c20bfda57f7ab7a687b4d2f1a482a93ebf067013cd7", // e20-14-dev-zk-stories42m-t32-h100-cuda.json
    "951cf469dc894f15f0d64bf97fb22947b855c4efe49fa8e1b82d210f8a730154", // e20-16-dev-zk-stories42m-t32-h100-cpu.json
    "7327f5cb4bb0720ff5ede60706ea5213ed97804ef5d4bee4b73b7dac10682158", // e20-16-dev-zk-stories42m-t32-h100-cuda.json
    "0b6cf0f0cbfbc5c9b6f8edae762960e83773b9c943e38a8dba6b54dc1d96e184", // e20-18-dev-zk-stories42m-t32-h100-nvl-cpu.json
    "0ce455bcef7c5009120a096e1fe3fccd13488fe8b474ac5f0a8a686d15aeaa1f", // e20-18-dev-zk-stories42m-t32-h100-nvl-cuda.json
    "6fd9b83709bead69e55ac01a617fdefb9bdf9fa6cd8588f3b36c82feb6f27cff", // e20-18-dev-zk-stories42m-t32-h100-sxm-cpu.json
    "a1d883e0a554a1344db3157a376168cb20cfaab8c570ec69bf89a3535fe56996", // e20-18-dev-zk-stories42m-t32-h100-sxm-cuda.json
    "33fcb58fac757ccb72aa5a0fc6d6ec1eb32baedd2e7a23e069dd761a01259c9d", // e20-20-dev-zk-stories42m-t32-h100-cpu.json
    "bf8b31efd514fcd419dbfa6490984331e163e2ab9cd02b1a87a38586bb8dde89", // e20-20-dev-zk-stories42m-t32-h100-cuda.json
    "447dfb431726415d5dd4d6c776111fc060631261b4364c2e45041781767d7175", // e20-22-canonical-dev-zk-stories42m-t32-h100-sxm.json
    "c1b5015256c0ab27705f9f4c4ac70e0504e9d58252571e293bc84bd61d6f7280", // e20-22-dev-zk-stories42m-t32-h100-cpu.json
    "b241eb6e6e3520165a790b42c351a2249ccbf55b6cd3e53be8fc120ba46568c9", // e20-22-dev-zk-stories42m-t32-h100-cuda-profiled.json
    "4cd71aa4bda6378880ad8b7d92529206619bf11b46e06b24b597a7b7a9835130", // e20-22-dev-zk-stories42m-t32-h100-cuda.json
    "ece96fe51702c378238735cff6ef67534615ef2a0468daf9c8e69314ef65d0c3", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-cpu.json
    "dcc65b9d0446f312126944cb6f107b4c9f057636419368c16c4515bcc0b191be", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-cuda-stage-laps.json
    "bda265f02328997daa60c4910061058aa6c297ec7c451d9fcfbe99057e914572", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-cuda.json
    "3e77a96e8ae5130bd1f2194c17e805af41d4946a5159ec2b44a1611b46af1d3c", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-1-cpu.json
    "7ed3ac6e1c384321669e34f1e4b56cd665f678cf2bb016cb916156aa49bd48c6", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-1-cuda.json
    "1c4a0d5096e78060414ba55c58f6275fd1ccf72968c1efb09f9d0204cc585cba", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-2-cpu.json
    "5d27bdac905cc10bee09ecf4de720cf3c7cf25c73e9e519c16d8c47de50431ba", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-2-cuda.json
    "1cb1f7ec49929d870cb3173d0f0b2b84e6b76094c6a2f9b609a9fd249fdc2c36", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-3-cpu.json
    "8112fb2b89b24ae89e2185154592edd3d1e39c3d8658b1b7f23c54985d7fc551", // e20-22-e45-dev-zk-stories42m-t32-h100-sxm-repeat-3-cuda.json
];

pub(crate) fn is_pre_e17_02_record(bytes: &[u8]) -> bool {
    let digest = stele_prover::development::artifact_id(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    PRE_E17_02_DEVELOPMENT_LEDGER_BLAKE3.contains(&hex.as_str())
}
