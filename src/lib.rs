// Copyright (C) 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use crate::error::{Error, Result};

pub mod error;

use async_trait::async_trait;
use lazy_static::lazy_static;
use reqwest::Client;
use semver::Version;
use serde_json::Value;
use std::collections::HashMap;
use std::env::consts::{ARCH, OS};
use std::fmt;
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use zip::ZipArchive;

const ANTCTL_S3_BASE_URL: &str = "https://antctl.s3.eu-west-2.amazonaws.com";
const ANTNODE_S3_BASE_URL: &str = "https://antnode.s3.eu-west-2.amazonaws.com";
const ANTNODE_RPC_CLIENT_S3_BASE_URL: &str =
    "https://antnode-rpc-client.s3.eu-west-2.amazonaws.com";
const ANT_S3_BASE_URL: &str = "https://autonomi-cli.s3.eu-west-2.amazonaws.com";
const GITHUB_API_URL: &str = "https://api.github.com";
const NAT_DETECTION_S3_BASE_URL: &str = "https://nat-detection.s3.eu-west-2.amazonaws.com";
const NODE_LAUNCHPAD_S3_BASE_URL: &str = "https://node-launchpad.s3.eu-west-2.amazonaws.com";
const WINSW_URL: &str = "https://sn-node-manager.s3.eu-west-2.amazonaws.com/WinSW-x64.exe";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ReleaseType {
    Ant,
    AntCtl,
    AntCtlDaemon,
    AntNode,
    AntNodeRpcClient,
    NatDetection,
    NodeLaunchpad,
}

impl fmt::Display for ReleaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ReleaseType::Ant => "ant",
                ReleaseType::AntCtl => "antctl",
                ReleaseType::AntCtlDaemon => "antctld",
                ReleaseType::AntNode => "antnode",
                ReleaseType::AntNodeRpcClient => "antnode_rpc_client",
                ReleaseType::NatDetection => "nat-detection",
                ReleaseType::NodeLaunchpad => "node-launchpad",
            }
        )
    }
}

lazy_static! {
    static ref RELEASE_TYPE_CRATE_NAME_MAP: HashMap<ReleaseType, &'static str> = {
        let mut m = HashMap::new();
        m.insert(ReleaseType::Ant, "ant-cli");
        m.insert(ReleaseType::AntCtl, "ant-node-manager");
        m.insert(ReleaseType::AntCtlDaemon, "ant-node-manager");
        m.insert(ReleaseType::AntNode, "ant-node");
        m.insert(ReleaseType::AntNodeRpcClient, "ant-node-rpc-client");
        m.insert(ReleaseType::NatDetection, "nat-detection");
        m.insert(ReleaseType::NodeLaunchpad, "node-launchpad");
        m
    };
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Platform {
    LinuxMusl,
    LinuxMuslAarch64,
    LinuxMuslArm,
    LinuxMuslArmV7,
    MacOs,
    MacOsAarch64,
    Windows,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::LinuxMusl => write!(f, "x86_64-unknown-linux-musl"),
            Platform::LinuxMuslAarch64 => write!(f, "aarch64-unknown-linux-musl"),
            Platform::LinuxMuslArm => write!(f, "arm-unknown-linux-musleabi"),
            Platform::LinuxMuslArmV7 => write!(f, "armv7-unknown-linux-musleabihf"),
            Platform::MacOs => write!(f, "x86_64-apple-darwin"),
            Platform::MacOsAarch64 => write!(f, "aarch64-apple-darwin"),
            Platform::Windows => write!(f, "x86_64-pc-windows-msvc"), // This appears to be the same as the above, so I'm using the same string.
        }
    }
}

impl Platform {
    /// Parses a platform string from a release into a Platform enum variant.
    pub fn from_release_string(s: &str) -> Result<Self> {
        match s {
            "x86_64-unknown-linux-musl" => Ok(Platform::LinuxMusl),
            "aarch64-unknown-linux-musl" => Ok(Platform::LinuxMuslAarch64),
            "arm-unknown-linux-musleabi" => Ok(Platform::LinuxMuslArm),
            "armv7-unknown-linux-musleabihf" => Ok(Platform::LinuxMuslArmV7),
            "x86_64-apple-darwin" => Ok(Platform::MacOs),
            "aarch64-apple-darwin" => Ok(Platform::MacOsAarch64),
            "x86_64-pc-windows-msvc" => Ok(Platform::Windows),
            _ => Err(Error::UnknownPlatform(s.to_string())),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ArchiveType {
    TarGz,
    Zip,
}

impl fmt::Display for ArchiveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveType::TarGz => write!(f, "tar.gz"),
            ArchiveType::Zip => write!(f, "zip"),
        }
    }
}

pub type ProgressCallback = dyn Fn(u64, u64) + Send + Sync;

/// Information about a specific binary in a release, including its version and SHA256 hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryInfo {
    pub name: String,
    pub version: String,
    pub sha256: String,
}

/// Collection of binaries for a specific platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformBinaries {
    pub platform: Platform,
    pub binaries: Vec<BinaryInfo>,
}

/// Release information from the maidsafe/autonomi GitHub repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutonomiReleaseInfo {
    pub commit_hash: String,
    pub name: String,
    pub platform_binaries: Vec<PlatformBinaries>,
}

#[async_trait]
pub trait AntReleaseRepoActions: Send + Sync {
    async fn get_latest_version(&self, release_type: &ReleaseType) -> Result<Version>;
    async fn download_release_from_s3(
        &self,
        release_type: &ReleaseType,
        version: &Version,
        platform: &Platform,
        archive_type: &ArchiveType,
        dest_path: &Path,
        callback: &ProgressCallback,
    ) -> Result<PathBuf>;
    async fn download_release(
        &self,
        url: &str,
        dest_dir_path: &Path,
        callback: &ProgressCallback,
    ) -> Result<PathBuf>;
    async fn download_winsw(&self, dest_path: &Path, callback: &ProgressCallback) -> Result<()>;
    fn extract_release_archive(&self, archive_path: &Path, dest_dir_path: &Path)
        -> Result<PathBuf>;
    async fn get_latest_autonomi_release_info(&self) -> Result<AutonomiReleaseInfo>;
    async fn get_autonomi_release_info(&self, tag_name: &str) -> Result<AutonomiReleaseInfo>;
}

impl dyn AntReleaseRepoActions {
    pub fn default_config() -> Box<dyn AntReleaseRepoActions> {
        Box::new(AntReleaseRepository {
            github_api_base_url: GITHUB_API_URL.to_string(),
            nat_detection_base_url: NAT_DETECTION_S3_BASE_URL.to_string(),
            node_launchpad_base_url: NODE_LAUNCHPAD_S3_BASE_URL.to_string(),
            ant_base_url: ANT_S3_BASE_URL.to_string(),
            antnode_base_url: ANTNODE_S3_BASE_URL.to_string(),
            antctl_base_url: ANTCTL_S3_BASE_URL.to_string(),
            antnode_rpc_client_base_url: ANTNODE_RPC_CLIENT_S3_BASE_URL.to_string(),
        })
    }
}

pub struct AntReleaseRepository {
    pub ant_base_url: String,
    pub antctl_base_url: String,
    pub antnode_base_url: String,
    pub antnode_rpc_client_base_url: String,
    pub github_api_base_url: String,
    pub nat_detection_base_url: String,
    pub node_launchpad_base_url: String,
}

impl AntReleaseRepository {
    fn get_base_url(&self, release_type: &ReleaseType) -> String {
        match release_type {
            ReleaseType::Ant => self.ant_base_url.clone(),
            ReleaseType::AntCtl => self.antctl_base_url.clone(),
            ReleaseType::AntCtlDaemon => self.antctl_base_url.clone(),
            ReleaseType::AntNode => self.antnode_base_url.clone(),
            ReleaseType::AntNodeRpcClient => self.antnode_rpc_client_base_url.clone(),
            ReleaseType::NatDetection => self.nat_detection_base_url.clone(),
            ReleaseType::NodeLaunchpad => self.node_launchpad_base_url.clone(),
        }
    }

    /// Parses the markdown body of a release to extract binary versions and hashes.
    fn parse_release_body(&self, body: &str) -> Result<Vec<PlatformBinaries>> {
        use regex::Regex;

        // Parse binary versions from "## Binary Versions" section
        let version_regex =
            Regex::new(r"\* `([^`]+)`: v?([0-9.]+)").map_err(|_| Error::RegexError)?;
        let mut binary_versions = HashMap::new();
        for cap in version_regex.captures_iter(body) {
            let name = cap[1].to_string();
            let version = cap[2].to_string();
            binary_versions.insert(name, version);
        }

        // Split body into lines and process line by line
        let lines: Vec<&str> = body.lines().collect();
        let mut platform_binaries = Vec::new();
        let mut current_platform: Option<Platform> = None;
        let mut current_binaries: Vec<BinaryInfo> = Vec::new();
        let mut in_hash_table = false;

        let hash_row_regex =
            Regex::new(r"^\| ([^ ]+) \| `([a-f0-9]{64})` \|$").map_err(|_| Error::RegexError)?;

        for line in lines {
            let trimmed = line.trim();

            // Check for platform header (### platform-name)
            if trimmed.starts_with("### ") {
                // Save previous platform if any
                if let Some(platform) = current_platform.take() {
                    if !current_binaries.is_empty() {
                        platform_binaries.push(PlatformBinaries {
                            platform,
                            binaries: current_binaries.clone(),
                        });
                        current_binaries.clear();
                    }
                }

                let platform_str = trimmed.trim_start_matches("### ");
                if let Ok(platform) = Platform::from_release_string(platform_str) {
                    current_platform = Some(platform);
                    in_hash_table = false;
                }
            } else if trimmed == "| Binary | SHA256 Hash |" {
                in_hash_table = true;
            } else if trimmed.starts_with("|--------") {
                // Continue in table
            } else if in_hash_table && current_platform.is_some() {
                if let Some(cap) = hash_row_regex.captures(trimmed) {
                    let name = cap[1].to_string();
                    let sha256 = cap[2].to_string();
                    let version = binary_versions
                        .get(&name)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    current_binaries.push(BinaryInfo {
                        name,
                        version,
                        sha256,
                    });
                } else if !trimmed.is_empty() && !trimmed.starts_with("|") {
                    // End of table
                    in_hash_table = false;
                }
            }
        }

        // Save last platform if any
        if let Some(platform) = current_platform {
            if !current_binaries.is_empty() {
                platform_binaries.push(PlatformBinaries {
                    platform,
                    binaries: current_binaries,
                });
            }
        }

        Ok(platform_binaries)
    }

    async fn download_url(
        &self,
        url: &str,
        dest_path: &Path,
        callback: &ProgressCallback,
    ) -> Result<()> {
        let client = Client::new();
        let mut response = client.get(url).send().await?;
        if !response.status().is_success() {
            return Err(Error::ReleaseBinaryNotFound(url.to_string()));
        }

        let total_size = response
            .headers()
            .get("content-length")
            .and_then(|ct_len| ct_len.to_str().ok())
            .and_then(|ct_len| ct_len.parse::<u64>().ok())
            .unwrap_or(0);

        let mut downloaded: u64 = 0;
        let mut out_file = File::create(&dest_path).await?;

        while let Some(chunk) = response.chunk().await.unwrap() {
            downloaded += chunk.len() as u64;
            out_file.write_all(&chunk).await?;
            callback(downloaded, total_size);
        }

        Ok(())
    }

    /// Fetches release information from the maidsafe/autonomi repository.
    async fn fetch_autonomi_release(&self, url: &str) -> Result<AutonomiReleaseInfo> {
        let client = Client::new();
        let response = client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "ant-releases")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::LatestReleaseNotFound("autonomi".to_string()));
        }

        let json: Value = response.json().await?;
        let commit_hash = json["target_commitish"]
            .as_str()
            .ok_or_else(|| Error::LatestReleaseNotFound("commit hash not found".to_string()))?
            .to_string();
        let name = json["name"]
            .as_str()
            .ok_or_else(|| Error::LatestReleaseNotFound("release name not found".to_string()))?
            .to_string();
        let body = json["body"]
            .as_str()
            .ok_or_else(|| Error::LatestReleaseNotFound("release body not found".to_string()))?;

        let platform_binaries = self.parse_release_body(body)?;

        Ok(AutonomiReleaseInfo {
            commit_hash,
            name,
            platform_binaries,
        })
    }
}

#[async_trait]
impl AntReleaseRepoActions for AntReleaseRepository {
    /// Uses the crates.io API to obtain the latest version of a crate.
    ///
    /// # Arguments
    ///
    /// * `release_type` - A reference to a `ReleaseType` enum specifying the type of release to look for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a `String` with the latest version number in the semantic format.
    /// Otherwise, returns an `Error`.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The HTTP request to crates.io API fails
    /// - The received JSON data does not have a `crate.newest_version` value
    async fn get_latest_version(&self, release_type: &ReleaseType) -> Result<Version> {
        let crate_name = *RELEASE_TYPE_CRATE_NAME_MAP.get(release_type).unwrap();
        let url = format!("https://crates.io/api/v1/crates/{crate_name}");

        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .header("User-Agent", "reqwest")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::CratesIoResponseError(response.status().as_u16()));
        }

        let body = response.text().await?;
        let json: Value = serde_json::from_str(&body)?;

        if let Some(version) = json["crate"]["newest_version"].as_str() {
            return Ok(Version::parse(version)?);
        }

        Err(Error::LatestReleaseNotFound(release_type.to_string()))
    }

    /// Downloads a release binary archive from S3.
    ///
    /// # Arguments
    ///
    /// - `release_type`: The type of release.
    /// - `version`: The version of the release.
    /// - `platform`: The target platform.
    /// - `archive_type`: The type of archive (e.g., tar.gz, zip).
    /// - `dest_path`: The directory where the downloaded archive will be stored.
    /// - `callback`: A callback function that can be used for download progress.
    ///
    /// # Returns
    ///
    /// A `Result` with `PathBuf` indicating the full path of the downloaded archive, or an error if
    /// the download or file write operation fails.
    async fn download_release_from_s3(
        &self,
        release_type: &ReleaseType,
        version: &Version,
        platform: &Platform,
        archive_type: &ArchiveType,
        dest_path: &Path,
        callback: &ProgressCallback,
    ) -> Result<PathBuf> {
        let archive_ext = archive_type.to_string();
        let url = format!(
            "{}/{}-{}-{}.{}",
            self.get_base_url(release_type),
            release_type.to_string().to_lowercase(),
            version,
            platform,
            archive_type
        );

        let archive_name = format!(
            "{}-{}-{}.{}",
            release_type.to_string().to_lowercase(),
            version,
            platform,
            archive_ext
        );
        let archive_path = dest_path.join(archive_name);

        self.download_url(&url, &archive_path, callback).await?;

        Ok(archive_path)
    }

    async fn download_release(
        &self,
        url: &str,
        dest_dir_path: &Path,
        callback: &ProgressCallback,
    ) -> Result<PathBuf> {
        if !url.ends_with(".tar.gz") && !url.ends_with(".zip") {
            return Err(Error::UrlIsNotArchive);
        }

        let file_name = url
            .split('/')
            .next_back()
            .ok_or_else(|| Error::CannotParseFilenameFromUrl)?;
        let dest_path = dest_dir_path.join(file_name);

        self.download_url(url, &dest_path, callback).await?;

        Ok(dest_path)
    }

    async fn download_winsw(&self, dest_path: &Path, callback: &ProgressCallback) -> Result<()> {
        self.download_url(WINSW_URL, dest_path, callback).await?;
        Ok(())
    }

    /// Extracts a release binary archive.
    ///
    /// The archive will include a single binary file.
    ///
    /// # Arguments
    ///
    /// - `archive_path`: The path of the archive file to extract.
    /// - `dest_dir`: The directory where the archive should be extracted.
    ///
    /// # Returns
    ///
    /// A `Result` with `PathBuf` indicating the full path of the extracted binary.
    fn extract_release_archive(
        &self,
        archive_path: &Path,
        dest_dir_path: &Path,
    ) -> Result<PathBuf> {
        if !archive_path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Archive not found at: {:?}", archive_path),
            )));
        }

        if archive_path.extension() == Some(std::ffi::OsStr::new("gz")) {
            let archive_file = std::fs::File::open(archive_path)?;
            let tarball = flate2::read::GzDecoder::new(archive_file);
            let mut archive = Archive::new(tarball);
            if let Some(file) = (archive.entries()?).next() {
                let mut file = file?;
                let out_path = dest_dir_path.join(file.path()?);
                file.unpack(&out_path)?;
                return Ok(out_path);
            }
        } else if archive_path.extension() == Some(std::ffi::OsStr::new("zip")) {
            let archive_file = std::fs::File::open(archive_path)?;
            let mut archive = ZipArchive::new(archive_file)?;
            if let Some(i) = (0..archive.len()).next() {
                let mut file = archive.by_index(i)?;
                let out_path = dest_dir_path.join(file.name());
                if file.name().ends_with('/') {
                    std::fs::create_dir_all(&out_path)?;
                } else {
                    let mut outfile = std::fs::File::create(&out_path)?;
                    std::io::copy(&mut file, &mut outfile)?;
                }
                return Ok(out_path);
            }
        } else {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported archive format",
            )));
        }

        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to extract archive",
        )))
    }

    async fn get_latest_autonomi_release_info(&self) -> Result<AutonomiReleaseInfo> {
        let url = format!(
            "{}/repos/maidsafe/autonomi/releases/latest",
            self.github_api_base_url
        );
        self.fetch_autonomi_release(&url).await
    }

    async fn get_autonomi_release_info(&self, tag_name: &str) -> Result<AutonomiReleaseInfo> {
        let url = format!(
            "{}/repos/maidsafe/autonomi/releases/tags/{}",
            self.github_api_base_url, tag_name
        );
        self.fetch_autonomi_release(&url).await
    }
}

pub fn get_running_platform() -> Result<Platform> {
    match OS {
        "linux" => match ARCH {
            "x86_64" => Ok(Platform::LinuxMusl),
            "armv7" => Ok(Platform::LinuxMuslArmV7),
            "arm" => Ok(Platform::LinuxMuslArm),
            "aarch64" => Ok(Platform::LinuxMuslAarch64),
            &_ => Err(Error::PlatformNotSupported(format!(
                "We currently do not have binaries for the {OS}/{ARCH} combination"
            ))),
        },
        "windows" => {
            if ARCH != "x86_64" {
                return Err(Error::PlatformNotSupported(
                    "We currently only have x86_64 binaries available for Windows".to_string(),
                ));
            }
            Ok(Platform::Windows)
        }
        "macos" => match ARCH {
            "x86_64" => Ok(Platform::MacOs),
            "aarch64" => Ok(Platform::MacOsAarch64),
            &_ => Err(Error::PlatformNotSupported(format!(
                "We currently do not have binaries for the {OS}/{ARCH} combination"
            ))),
        },
        &_ => Err(Error::PlatformNotSupported(format!(
            "{OS} is not currently supported"
        ))),
    }
}
