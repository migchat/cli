use anyhow::{anyhow, Result};
use semver::Version;
use serde::Deserialize;
use std::env;

const GITHUB_REPO: &str = "migchat/cli";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn check_for_updates() -> Result<Option<String>> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);

    let response = client
        .get(&url)
        .header("User-Agent", "migchat-cli")
        .send()?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let release: GithubRelease = response.json()?;
    let latest_version = release.tag_name.trim_start_matches('v');

    let current = Version::parse(CURRENT_VERSION)?;
    let latest = Version::parse(latest_version)?;

    if latest > current {
        Ok(Some(latest_version.to_string()))
    } else {
        Ok(None)
    }
}

pub fn get_current_version() -> &'static str {
    CURRENT_VERSION
}

fn get_platform_binary_name() -> Result<String> {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let binary_name = match (os, arch) {
        ("linux", "x86_64") => "migchat-linux-x86_64",
        ("linux", "aarch64") => "migchat-linux-aarch64",
        ("macos", "x86_64") => "migchat-macos-x86_64",
        ("macos", "aarch64") => "migchat-macos-aarch64",
        ("windows", "x86_64") => "migchat-windows-x86_64.exe",
        _ => return Err(anyhow!("Unsupported platform: {}-{}", os, arch)),
    };

    Ok(binary_name.to_string())
}

pub fn perform_update() -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);

    let response = client
        .get(&url)
        .header("User-Agent", "migchat-cli")
        .send()?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch latest release"));
    }

    let release: GithubRelease = response.json()?;
    let binary_name = get_platform_binary_name()?;

    // Find the appropriate asset
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == binary_name)
        .ok_or_else(|| anyhow!("Binary not found for this platform"))?;

    // Download the binary
    let binary_response = client
        .get(&asset.browser_download_url)
        .header("User-Agent", "migchat-cli")
        .send()?;

    if !binary_response.status().is_success() {
        return Err(anyhow!("Failed to download binary"));
    }

    let binary_data = binary_response.bytes()?;

    // Write to a temporary file and replace
    let temp_path = std::env::temp_dir().join("migchat-update");
    std::fs::write(&temp_path, &binary_data)?;

    // Make it executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&temp_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp_path, perms)?;
    }

    // Replace the current binary
    self_replace::self_replace(&temp_path)?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    Ok(())
}
