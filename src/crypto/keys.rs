use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as ChaChaOsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const IDENTITY_KEY_FILE: &str = "identity_key.enc";
const SIGNED_PREKEY_FILE: &str = "signed_prekey.enc";
const ONE_TIME_PREKEYS_FILE: &str = "one_time_prekeys.enc";
const KEY_METADATA_FILE: &str = "key_metadata.json";
const VERIFIED_KEYS_FILE: &str = "verified_keys.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity_key: String,
    pub signed_prekey: String,
    pub signed_prekey_signature: String,
    pub one_time_prekeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub identity_key_fingerprint: String,
    pub signed_prekey_created_at: i64,
    pub one_time_prekey_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedKey {
    pub username: String,
    pub identity_key: String,
    pub fingerprint: String,
    pub verified_at: i64,
}

#[derive(Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: StaticSecret,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { public, secret }
    }

    pub fn from_bytes(secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != 32 {
            return Err(anyhow!("Invalid secret key length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { public, secret })
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }
}

#[derive(Clone)]
pub struct SigningKeyPair {
    pub verifying: VerifyingKey,
    pub signing: SigningKey,
}

impl SigningKeyPair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    pub fn from_bytes(secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != 32 {
            return Err(anyhow!("Invalid signing key length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        Ok(Self { verifying, signing })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
        verifying_key
            .verify(message, signature)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))
    }
}

pub struct KeyManager {
    keys_dir: PathBuf,
}

impl KeyManager {
    pub fn new() -> Result<Self> {
        let keys_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("migchat")
            .join("keys");

        fs::create_dir_all(&keys_dir)?;

        Ok(Self { keys_dir })
    }

    fn get_key_path(&self, filename: &str) -> PathBuf {
        self.keys_dir.join(filename)
    }

    fn derive_encryption_key(&self, password: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| anyhow!("Failed to encode salt: {}", e))?;
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| anyhow!("No hash generated"))?
            .as_bytes()
            .to_vec();

        Ok(hash_bytes[..32].to_vec())
    }

    fn encrypt_data(&self, data: &[u8], password: &str) -> Result<Vec<u8>> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let key = self.derive_encryption_key(password, &salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut result = Vec::new();
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_data(&self, encrypted_data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
        if encrypted_data.len() < 28 {
            return Err(anyhow!("Invalid encrypted data"));
        }

        let salt = &encrypted_data[0..16];
        let nonce_bytes = &encrypted_data[16..28];
        let ciphertext = &encrypted_data[28..];

        let key = self.derive_encryption_key(password, salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(Zeroizing::new(plaintext))
    }

    pub fn generate_keys(&self, password: &str) -> Result<()> {
        // Generate identity key pair (long-term)
        let identity_keypair = KeyPair::generate();
        let identity_secret = identity_keypair.secret_bytes();
        let encrypted_identity = self.encrypt_data(&identity_secret, password)?;
        fs::write(self.get_key_path(IDENTITY_KEY_FILE), encrypted_identity)?;

        // Generate signed prekey
        let signed_prekey_keypair = KeyPair::generate();
        let signed_prekey_secret = signed_prekey_keypair.secret_bytes();
        let encrypted_signed_prekey = self.encrypt_data(&signed_prekey_secret, password)?;
        fs::write(self.get_key_path(SIGNED_PREKEY_FILE), encrypted_signed_prekey)?;

        // Generate one-time prekeys (pool of 100)
        let mut one_time_prekeys = Vec::new();
        for _ in 0..100 {
            let keypair = KeyPair::generate();
            one_time_prekeys.extend_from_slice(&keypair.secret_bytes());
        }
        let encrypted_one_time_prekeys = self.encrypt_data(&one_time_prekeys, password)?;
        fs::write(
            self.get_key_path(ONE_TIME_PREKEYS_FILE),
            encrypted_one_time_prekeys,
        )?;

        // Generate fingerprint
        let fingerprint = self.generate_fingerprint(&identity_keypair.public_bytes());

        // Save metadata
        let metadata = KeyMetadata {
            identity_key_fingerprint: fingerprint,
            signed_prekey_created_at: chrono::Utc::now().timestamp(),
            one_time_prekey_count: 100,
        };
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(self.get_key_path(KEY_METADATA_FILE), metadata_json)?;

        Ok(())
    }

    pub fn load_identity_key(&self, password: &str) -> Result<KeyPair> {
        let encrypted_data = fs::read(self.get_key_path(IDENTITY_KEY_FILE))?;
        let decrypted = self.decrypt_data(&encrypted_data, password)?;
        KeyPair::from_bytes(&decrypted)
    }

    pub fn load_signed_prekey(&self, password: &str) -> Result<KeyPair> {
        let encrypted_data = fs::read(self.get_key_path(SIGNED_PREKEY_FILE))?;
        let decrypted = self.decrypt_data(&encrypted_data, password)?;
        KeyPair::from_bytes(&decrypted)
    }

    pub fn load_one_time_prekey(&self, password: &str, index: usize) -> Result<KeyPair> {
        let encrypted_data = fs::read(self.get_key_path(ONE_TIME_PREKEYS_FILE))?;
        let decrypted = self.decrypt_data(&encrypted_data, password)?;

        let offset = index * 32;
        if offset + 32 > decrypted.len() {
            return Err(anyhow!("One-time prekey index out of bounds"));
        }

        KeyPair::from_bytes(&decrypted[offset..offset + 32])
    }

    pub fn get_public_key_bundle(&self, password: &str) -> Result<KeyBundle> {
        let identity_key = self.load_identity_key(password)?;
        let signed_prekey = self.load_signed_prekey(password)?;

        // Sign the prekey with identity key
        let identity_signing = SigningKeyPair::from_bytes(&identity_key.secret_bytes())?;
        let signature = identity_signing.sign(signed_prekey.public_bytes().as_slice());

        // Get available one-time prekeys
        let mut one_time_prekeys = Vec::new();
        let metadata = self.load_metadata()?;
        for i in 0..metadata.one_time_prekey_count.min(10) {
            if let Ok(prekey) = self.load_one_time_prekey(password, i) {
                one_time_prekeys.push(BASE64.encode(prekey.public_bytes()));
            }
        }

        Ok(KeyBundle {
            identity_key: BASE64.encode(identity_key.public_bytes()),
            signed_prekey: BASE64.encode(signed_prekey.public_bytes()),
            signed_prekey_signature: BASE64.encode(signature.to_bytes()),
            one_time_prekeys,
        })
    }

    pub fn load_metadata(&self) -> Result<KeyMetadata> {
        let metadata_json = fs::read_to_string(self.get_key_path(KEY_METADATA_FILE))?;
        let metadata: KeyMetadata = serde_json::from_str(&metadata_json)?;
        Ok(metadata)
    }

    pub fn generate_fingerprint(&self, public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();

        // Format as readable fingerprint: "1234 5678 9ABC DEF0 ..."
        let hex = hex::encode(&hash[..16]);
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
            .to_uppercase()
    }

    pub fn keys_exist(&self) -> bool {
        self.get_key_path(IDENTITY_KEY_FILE).exists()
            && self.get_key_path(SIGNED_PREKEY_FILE).exists()
            && self.get_key_path(ONE_TIME_PREKEYS_FILE).exists()
    }

    pub fn verify_and_save_contact_key(
        &self,
        username: &str,
        identity_key: &str,
        fingerprint: &str,
    ) -> Result<()> {
        let verified_key = VerifiedKey {
            username: username.to_string(),
            identity_key: identity_key.to_string(),
            fingerprint: fingerprint.to_string(),
            verified_at: chrono::Utc::now().timestamp(),
        };

        let mut verified_keys = self.load_verified_keys()?;
        verified_keys.retain(|k| k.username != username);
        verified_keys.push(verified_key);

        let json = serde_json::to_string_pretty(&verified_keys)?;
        fs::write(self.get_key_path(VERIFIED_KEYS_FILE), json)?;

        Ok(())
    }

    pub fn load_verified_keys(&self) -> Result<Vec<VerifiedKey>> {
        let path = self.get_key_path(VERIFIED_KEYS_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let json = fs::read_to_string(path)?;
        let keys: Vec<VerifiedKey> = serde_json::from_str(&json)?;
        Ok(keys)
    }

    pub fn get_verified_key(&self, username: &str) -> Option<VerifiedKey> {
        let verified_keys = self.load_verified_keys().ok()?;
        verified_keys.into_iter().find(|k| k.username == username)
    }

    pub fn check_key_change(&self, username: &str, new_identity_key: &str) -> Result<bool> {
        if let Some(verified_key) = self.get_verified_key(username) {
            Ok(verified_key.identity_key != new_identity_key)
        } else {
            Ok(false)
        }
    }

    pub fn export_keys(&self, password: &str, export_password: &str) -> Result<String> {
        let identity_key = self.load_identity_key(password)?;
        let signed_prekey = self.load_signed_prekey(password)?;

        let export_data = serde_json::json!({
            "identity_key": BASE64.encode(identity_key.secret_bytes()),
            "signed_prekey": BASE64.encode(signed_prekey.secret_bytes()),
            "exported_at": chrono::Utc::now().to_rfc3339(),
        });

        let json = serde_json::to_string(&export_data)?;
        let encrypted = self.encrypt_data(json.as_bytes(), export_password)?;
        Ok(BASE64.encode(encrypted))
    }

    pub fn import_keys(&self, encrypted_backup: &str, export_password: &str, new_password: &str) -> Result<()> {
        let encrypted_data = BASE64.decode(encrypted_backup)?;
        let decrypted = self.decrypt_data(&encrypted_data, export_password)?;
        let json = std::str::from_utf8(&decrypted)?;
        let export_data: serde_json::Value = serde_json::from_str(json)?;

        let identity_key_bytes = BASE64.decode(
            export_data["identity_key"]
                .as_str()
                .ok_or_else(|| anyhow!("Invalid backup format"))?,
        )?;
        let signed_prekey_bytes = BASE64.decode(
            export_data["signed_prekey"]
                .as_str()
                .ok_or_else(|| anyhow!("Invalid backup format"))?,
        )?;

        // Re-encrypt with new password
        let encrypted_identity = self.encrypt_data(&identity_key_bytes, new_password)?;
        fs::write(self.get_key_path(IDENTITY_KEY_FILE), encrypted_identity)?;

        let encrypted_signed_prekey = self.encrypt_data(&signed_prekey_bytes, new_password)?;
        fs::write(self.get_key_path(SIGNED_PREKEY_FILE), encrypted_signed_prekey)?;

        Ok(())
    }
}

// Add hex dependency
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
