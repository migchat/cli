use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

const CACHE_FILE: &str = "message_cache.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedMessage {
    message_id: i64,
    encrypted_plaintext: String, // Encrypted with user password
    nonce: String,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageCacheData {
    messages: Vec<CachedMessage>,
}

pub struct MessageCache {
    cache_dir: PathBuf,
    cache: HashMap<i64, CachedMessage>,
}

impl MessageCache {
    pub fn new() -> Result<Self> {
        let cache_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("migchat")
            .join("cache");

        fs::create_dir_all(&cache_dir)?;

        let mut cache_manager = Self {
            cache_dir,
            cache: HashMap::new(),
        };

        cache_manager.load_cache()?;
        Ok(cache_manager)
    }

    pub fn for_account(account_username: &str) -> Result<Self> {
        let cache_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("migchat")
            .join("cache")
            .join(account_username);

        fs::create_dir_all(&cache_dir)?;

        let mut cache_manager = Self {
            cache_dir,
            cache: HashMap::new(),
        };

        cache_manager.load_cache()?;
        Ok(cache_manager)
    }

    fn get_cache_path(&self) -> PathBuf {
        self.cache_dir.join(CACHE_FILE)
    }

    fn load_cache(&mut self) -> Result<()> {
        let path = self.get_cache_path();
        if !path.exists() {
            return Ok(());
        }

        let json = fs::read_to_string(path)?;
        let cache_data: MessageCacheData = serde_json::from_str(&json)?;

        for msg in cache_data.messages {
            self.cache.insert(msg.message_id, msg);
        }

        Ok(())
    }

    fn save_cache(&self) -> Result<()> {
        let messages: Vec<CachedMessage> = self.cache.values().cloned().collect();
        let cache_data = MessageCacheData { messages };
        let json = serde_json::to_string_pretty(&cache_data)?;
        fs::write(self.get_cache_path(), json)?;
        Ok(())
    }

    fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.update(b"MigChat-MessageCache");
        let hash = hasher.finalize();
        Zeroizing::new(hash[..32].to_vec())
    }

    pub fn cache_message(&mut self, message_id: i64, plaintext: &str, password: &str) -> Result<()> {
        // Generate salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key from password
        let key = self.derive_key_from_password(password, &salt);

        // Encrypt plaintext
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Store in cache
        let cached_msg = CachedMessage {
            message_id,
            encrypted_plaintext: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(&nonce_bytes),
            salt: BASE64.encode(&salt),
        };

        self.cache.insert(message_id, cached_msg);
        self.save_cache()?;

        Ok(())
    }

    pub fn get_cached_message(&self, message_id: i64, password: &str) -> Option<String> {
        let cached_msg = self.cache.get(&message_id)?;

        // Decode components
        let ciphertext = BASE64.decode(&cached_msg.encrypted_plaintext).ok()?;
        let nonce_bytes = BASE64.decode(&cached_msg.nonce).ok()?;
        let salt = BASE64.decode(&cached_msg.salt).ok()?;

        // Derive key
        let key = self.derive_key_from_password(password, &salt);

        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).ok()?;
        String::from_utf8(plaintext).ok()
    }

    pub fn has_message(&self, message_id: i64) -> bool {
        self.cache.contains_key(&message_id)
    }

    pub fn clear_cache(&mut self) -> Result<()> {
        self.cache.clear();
        let path = self.get_cache_path();
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn get_cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn get_cache_size_bytes(&self) -> Result<u64> {
        let path = self.get_cache_path();
        if path.exists() {
            Ok(fs::metadata(path)?.len())
        } else {
            Ok(0)
        }
    }
}
