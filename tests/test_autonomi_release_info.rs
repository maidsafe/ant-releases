// Copyright (C) 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_releases::{AntReleaseRepoActions, BinaryInfo, Platform};
use std::collections::HashMap;

#[tokio::test]
async fn test_get_autonomi_release_info_for_specific_tag() {
    let release_repo = <dyn AntReleaseRepoActions>::default_config();

    let release_info = release_repo
        .get_autonomi_release_info("stable-2025.11.1.1")
        .await
        .unwrap();

    assert_eq!(
        release_info.commit_hash,
        "0291e36a77397051a11ebca94caea4a06d026c8d"
    );
    assert_eq!(release_info.name, "2025.11.1.1");
    assert_eq!(release_info.platform_binaries.len(), 7);

    let expected_versions: HashMap<&str, &str> = [
        ("antnode", "0.4.7"),
        ("antctld", "0.13.3"),
        ("antctl", "0.13.3"),
        ("ant", "0.4.10"),
        ("evm-testnet", "0.1.16"),
        ("nat-detection", "0.2.22"),
        ("node-launchpad", "0.5.11"),
        ("antnode_rpc_client", "unknown"),
    ]
    .iter()
    .cloned()
    .collect();

    let expected_hashes: HashMap<Platform, Vec<(&str, &str)>> = [
        (
            Platform::Windows,
            vec![
                (
                    "nat-detection",
                    "4fe040a49f322af1a2da3dce8b7a65fc2b82bb4bd489d490350a120e990fb46e",
                ),
                (
                    "node-launchpad",
                    "6869c4a31fc3df8abd89c6c8fc5e7932d11ef6d29c5c926f409665f60e70509d",
                ),
                (
                    "ant",
                    "af413fcb06a8b97e03df454415301a201f101bd86e5bf6f32833fa9d43430db0",
                ),
                (
                    "antnode",
                    "7ba75310843aca8172ca58a4dabbab9e93a9915277a575ff7d6b756da968bade",
                ),
                (
                    "antctl",
                    "d761cdfcf2054c8877b220526444ad1728c92701f6e6f18bd9b50d6677c860ac",
                ),
                (
                    "antctld",
                    "dc24d47cf9b2aa7cc1732fd513ace9b2f0744e25a83da4ad847f47a6563cb453",
                ),
                (
                    "antnode_rpc_client",
                    "ac42df5e84b70afc3ffc418be568edadc905260070c674d0612a0d7f0e49c497",
                ),
                (
                    "evm-testnet",
                    "972c142ab5cd5501a6d083f18ece769700a95172fe6471a50f67de4a20009ed0",
                ),
            ],
        ),
        (
            Platform::MacOs,
            vec![
                (
                    "nat-detection",
                    "1e60101b3b16fb1584100f62b998392619613e0f12bb014b85f5105a68a5d4b3",
                ),
                (
                    "node-launchpad",
                    "e876d7b0c3db4d3eedd2b2eb73dd251916b5538d647cd7d7bc097034772b0834",
                ),
                (
                    "ant",
                    "3018d8698eb2c13a00366b7f90dd4f4670c1b8ad6344f46c48f0f315e1611ab6",
                ),
                (
                    "antnode",
                    "6b160519b31461b982f13e01a791cff6a3d26a36955b1f759e046021dc9ca60c",
                ),
                (
                    "antctl",
                    "f832f3d21d613c343729afa80fb40dc1853d5351f2a1d7fda5fcdcecfc17cbae",
                ),
                (
                    "antctld",
                    "9cbee73a45fac741ca9cb297c3b93762afc933a87fb0331ddad4776708ca9e03",
                ),
                (
                    "antnode_rpc_client",
                    "52207ac18c2f72b59e1b02b92c3c1a2e6b6070d2907c381eaa27f43da89deb60",
                ),
                (
                    "evm-testnet",
                    "d5ba88ff4ecdcc7013149d046c89e28022f293e6a1e4c1e06069510ea34b2e3f",
                ),
            ],
        ),
        (
            Platform::MacOsAarch64,
            vec![
                (
                    "nat-detection",
                    "2b26fb6e5bb734270173b7d4172ea9b0528da9af23a13f7ef8593805bab370c8",
                ),
                (
                    "node-launchpad",
                    "9b572eefdeb99585a9d0630aee29caee41a123b42fdcbf46dec821a6cb04e711",
                ),
                (
                    "ant",
                    "f540d00d1e214eeed94ef652fcb98a2b70f18ff7e174682f7d0afe5950c9abcf",
                ),
                (
                    "antnode",
                    "4d1b0cfc1143e0022df68f030cbc38180030ef1ec719565a716c6ea5a7f840e4",
                ),
                (
                    "antctl",
                    "bb7091210d22944d1e28353116e053fcd2007cbeddf79a901baa46ac36985fc4",
                ),
                (
                    "antctld",
                    "9308daa13d8d0d8374cd42c8120145b3816ae4ef6bd8af18e3b99dc24329bf71",
                ),
                (
                    "antnode_rpc_client",
                    "ecc45f7d850deb6aec4ea5f7ef730213cb5d59e2c7395f901c7d96c5c8e9d822",
                ),
                (
                    "evm-testnet",
                    "bc746b0a7e919e5873d9a63720fbf47a218c9c80e7e635cd563d10cb288e7771",
                ),
            ],
        ),
        (
            Platform::LinuxMusl,
            vec![
                (
                    "nat-detection",
                    "8d41fccfa4a2a485c5e9dd9ee5de363c941cde9c94bcc3c81e44e60aefa7dd11",
                ),
                (
                    "node-launchpad",
                    "e8d2da8d7c5fba33bbaf2e17aaf4237983542348f75eed52766f572e1896ed78",
                ),
                (
                    "ant",
                    "df88458332c476f928691ac10eb6c965141b505c94db748fded174f16e68fbcf",
                ),
                (
                    "antnode",
                    "23b9faa329153c2a22a3404c26d45d649c54c19f111b3043efe48f21f269e75c",
                ),
                (
                    "antctl",
                    "bd5de6f6ee1c2d94f56a0ddcacd8e12496c234c1482371b8201247de62e67ce3",
                ),
                (
                    "antctld",
                    "2501ed3667eaa14d5e675595c90eb323c68c4b13f3fd67f42544a80c779936e4",
                ),
                (
                    "antnode_rpc_client",
                    "d7a41e7f5c1ee93a68bd19eb42d1c5b72c78eb1e3a67bf22a1d353e90fe67b3e",
                ),
                (
                    "evm-testnet",
                    "dfcbffaa36ab3d0c8f68e2a02501661767fd31f5c8225e5e742bc2459ed6196b",
                ),
            ],
        ),
        (
            Platform::LinuxMuslArm,
            vec![
                (
                    "nat-detection",
                    "153abb95e3b3e37d3140947afc44f0618ad2306be6a94113f073fc7301e2df87",
                ),
                (
                    "node-launchpad",
                    "dfba61aed42773751453b1d3de5cba12408c19a8dc9959799e6d5c836c7adc49",
                ),
                (
                    "ant",
                    "736274cb9dd2a65ad5ac731ee8434df7ac1f500c1cec43184c19f521a7ebb3fe",
                ),
                (
                    "antnode",
                    "3037876d1ca2df68746a9fc5c08fee4b9538f8eaa8aca4fec8cea49bdc6ab06c",
                ),
                (
                    "antctl",
                    "2775a4064b910fae204c81e791fb7082f4c311d8eb10c0be8fd114da4181387e",
                ),
                (
                    "antctld",
                    "0f533a56cc4bff3b0159f6055246e1174775d01dfe9613ab79ce8d1e937c671d",
                ),
                (
                    "antnode_rpc_client",
                    "2e4fbbb65ae430d2c1190fe17a1ff2c5b4222a9d95855b4fc1f432b7a480b75a",
                ),
                (
                    "evm-testnet",
                    "ca8fbb06e0a3b2f2151a16420ae1171cb65a9e66682984d92cdb7e572e58cc9d",
                ),
            ],
        ),
        (
            Platform::LinuxMuslArmV7,
            vec![
                (
                    "nat-detection",
                    "a7edb8c3e1894084b9148c8e3272c0a462336f4c19af4ea5fee2499a3cce512b",
                ),
                (
                    "node-launchpad",
                    "4f3a70c1da56b74919d92a0db91c5942661535d2f76eb74ebcd48bc2d35d6a17",
                ),
                (
                    "ant",
                    "f896445fd775cf492f170885b424aaf33400a1ea1437ee491a068cb2d379a6f7",
                ),
                (
                    "antnode",
                    "98295b4d3ef1c062f45e0d6ff277a9ef046d4a25ad95cff68e11f6fd4c9cb91b",
                ),
                (
                    "antctl",
                    "44e06aae2ac47abea4fe8ef74fca3cd43f102b93e6cfd5b90c19b14b55982bd2",
                ),
                (
                    "antctld",
                    "a77f9ced69fb82f14552ead1f3910605c8889762e9445cfe6dcca4441bae66c4",
                ),
                (
                    "antnode_rpc_client",
                    "335650edda9b4e69d8fd3ae32794fcf91cc77badc431270eb70897c37695762f",
                ),
                (
                    "evm-testnet",
                    "d6748d9d024e354cb013e50559c40520b61b78862cfb22db3f5490ab42d984b0",
                ),
            ],
        ),
        (
            Platform::LinuxMuslAarch64,
            vec![
                (
                    "nat-detection",
                    "420107959441fda347e6c693a1d8d99d9fb97bb9b81ad1c94e355aa7d97a152c",
                ),
                (
                    "node-launchpad",
                    "03c4b1467072cef6d4a8e07949181da6a68c9cbbe6c24aa22892ca55271712fa",
                ),
                (
                    "ant",
                    "937a7525b2425336f29959b35d1a4f459e3e3f39e128e5682ceebf00bbc4ffbf",
                ),
                (
                    "antnode",
                    "2aa3568e01ef1abeb39f42f8188f74fbe9008d9d7b9b4532c8932a372fb3a494",
                ),
                (
                    "antctl",
                    "3c453f8ce6223f61b52792505f67a5e866774117de0d829f79a61abe5601c3d3",
                ),
                (
                    "antctld",
                    "19f3148c8c3654129593888cb087de87c76b73287535ee9ae920e8bca5b033cb",
                ),
                (
                    "antnode_rpc_client",
                    "00dbb593049b5dbf8ee7202b6f0e55bfa52726a81fe0b93ffdc0b5e1314e3db5",
                ),
                (
                    "evm-testnet",
                    "6ab8f2820bd0135837c5f1b91e310311b7f8d9e6f59e6e8cbe6d7b59ade54e92",
                ),
            ],
        ),
    ]
    .iter()
    .cloned()
    .collect();

    for (platform, expected_binaries) in expected_hashes {
        let platform_binary = release_info
            .platform_binaries
            .iter()
            .find(|pb| pb.platform == platform)
            .unwrap_or_else(|| panic!("Platform {:?} not found", platform));

        assert_eq!(
            platform_binary.binaries.len(),
            8,
            "Platform {:?} should have 8 binaries",
            platform
        );

        // Convert actual binaries to a map for easier lookup
        let actual_binaries: HashMap<&str, &BinaryInfo> = platform_binary
            .binaries
            .iter()
            .map(|b| (b.name.as_str(), b))
            .collect();

        for (binary_name, expected_hash) in expected_binaries {
            let binary = actual_binaries
                .get(binary_name)
                .unwrap_or_else(|| panic!("Binary {} not found in {:?}", binary_name, platform));

            let expected_version = expected_versions
                .get(binary_name)
                .unwrap_or_else(|| panic!("No expected version for {}", binary_name));
            assert_eq!(
                binary.version, *expected_version,
                "Version mismatch for {} on {:?}",
                binary_name, platform
            );
            assert_eq!(
                binary.sha256, expected_hash,
                "Hash mismatch for {} on {:?}",
                binary_name, platform
            );
        }
    }
}
