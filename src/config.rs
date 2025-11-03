use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub username: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub server_url: String,
    pub accounts: HashMap<String, Account>, // key is username
    pub current_account: Option<String>,     // current username
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
        self.current_account.is_some()
    }

    pub fn has_accounts(&self) -> bool {
        !self.accounts.is_empty()
    }

    pub fn get_current_account(&self) -> Option<&Account> {
        self.current_account
            .as_ref()
            .and_then(|username| self.accounts.get(username))
    }

    pub fn get_current_username(&self) -> Option<&String> {
        self.current_account.as_ref()
    }

    pub fn get_current_token(&self) -> Option<&String> {
        self.get_current_account().map(|acc| &acc.token)
    }

    pub fn add_account(&mut self, username: String, token: String) {
        let account = Account {
            username: username.clone(),
            token,
        };
        self.accounts.insert(username.clone(), account);
        self.current_account = Some(username);
    }

    pub fn switch_account(&mut self, username: &str) -> bool {
        if self.accounts.contains_key(username) {
            self.current_account = Some(username.to_string());
            true
        } else {
            false
        }
    }

    pub fn logout_current(&mut self) {
        self.current_account = None;
    }

    pub fn remove_account(&mut self, username: &str) {
        self.accounts.remove(username);
        if self.current_account.as_deref() == Some(username) {
            self.current_account = None;
        }
    }

    pub fn get_account_list(&self) -> Vec<String> {
        self.accounts.keys().cloned().collect()
    }

    fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Could not determine home directory")?;

        Ok(home.join(".migchat").join("config.json"))
    }

    fn default_config() -> Self {
        Self {
            server_url: "https://server-1ce-la.fly.dev".to_string(),
            accounts: HashMap::new(),
            current_account: None,
        }
    }
}
