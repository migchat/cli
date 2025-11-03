use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub server_url: String,
    pub username: Option<String>,
    pub token: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default_config());
        }

        let contents = fs::read_to_string(&path)
            .context("Failed to read config file")?;

        let config: Config = serde_json::from_str(&contents)
            .context("Failed to parse config file")?;

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize config")?;

        fs::write(&path, contents)
            .context("Failed to write config file")?;

        Ok(())
    }

    pub fn is_logged_in(&self) -> bool {
        self.token.is_some() && self.username.is_some()
    }

    pub fn logout(&mut self) {
        self.token = None;
        self.username = None;
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Could not determine home directory")?;

        Ok(home.join(".migchat").join("config.json"))
    }

    fn default_config() -> Self {
        Self {
            server_url: "https://server-1ce-la.fly.dev".to_string(),
            username: None,
            token: None,
        }
    }
}
