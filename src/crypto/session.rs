use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::Hmac;
use hmac::Mac as HmacMac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::keys::{KeyBundle, KeyPair};

const SESSIONS_FILE: &str = "sessions.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    pub root_key: String,
    pub chain_key: String,
    pub message_number: u32,
    pub previous_counter: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub username: String,
    pub identity_key: String,
    pub session_keys: SessionKeys,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub version: u8,
    pub sender_identity_key: String,
    pub receiver_identity_key: String,
    pub ephemeral_key: String,
    pub ciphertext: String,
    pub mac: String,
}

pub struct SessionManager {
    sessions_dir: PathBuf,
    sessions: HashMap<String, Session>,
}

impl SessionManager {
    pub fn new() -> Result<Self> {
        let sessions_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("migchat")
            .join("sessions");

        fs::create_dir_all(&sessions_dir)?;

        let mut manager = Self {
            sessions_dir,
            sessions: HashMap::new(),
        };

        manager.load_sessions()?;
        Ok(manager)
    }

    pub fn for_account(account_username: &str) -> Result<Self> {
        let sessions_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("migchat")
            .join("sessions")
            .join(account_username);

        fs::create_dir_all(&sessions_dir)?;

        let mut manager = Self {
            sessions_dir,
            sessions: HashMap::new(),
        };

        manager.load_sessions()?;
        Ok(manager)
    }

    fn get_sessions_path(&self) -> PathBuf {
        self.sessions_dir.join(SESSIONS_FILE)
    }

    fn load_sessions(&mut self) -> Result<()> {
        let path = self.get_sessions_path();
        if !path.exists() {
            return Ok(());
        }

        let json = fs::read_to_string(path)?;
        let sessions: Vec<Session> = serde_json::from_str(&json)?;

        for session in sessions {
            self.sessions.insert(session.username.clone(), session);
        }

        Ok(())
    }

    fn save_sessions(&self) -> Result<()> {
        let sessions: Vec<Session> = self.sessions.values().cloned().collect();
        let json = serde_json::to_string_pretty(&sessions)?;
        fs::write(self.get_sessions_path(), json)?;
        Ok(())
    }

    pub fn establish_session(
        &mut self,
        username: &str,
        our_identity_key: &KeyPair,
        our_ephemeral_key: &KeyPair,
        their_identity_key: &[u8],
        their_signed_prekey: &[u8],
        their_one_time_prekey: Option<&[u8]>,
    ) -> Result<()> {
        // X3DH key agreement
        let their_identity_pub = PublicKey::from(*array_ref::array_ref![their_identity_key, 0, 32]);
        let their_signed_prekey_pub =
            PublicKey::from(*array_ref::array_ref![their_signed_prekey, 0, 32]);

        // DH1 = DH(IK_A, SPK_B)
        let dh1 = our_identity_key.secret.diffie_hellman(&their_signed_prekey_pub);

        // DH2 = DH(EK_A, IK_B)
        let dh2 = our_ephemeral_key.secret.diffie_hellman(&their_identity_pub);

        // DH3 = DH(EK_A, SPK_B)
        let dh3 = our_ephemeral_key
            .secret
            .diffie_hellman(&their_signed_prekey_pub);

        // Combine DH outputs
        let mut shared_secret = Vec::new();
        shared_secret.extend_from_slice(dh1.as_bytes());
        shared_secret.extend_from_slice(dh2.as_bytes());
        shared_secret.extend_from_slice(dh3.as_bytes());

        // If one-time prekey is available: DH4 = DH(EK_A, OPK_B)
        if let Some(one_time_prekey) = their_one_time_prekey {
            let their_one_time_pub = PublicKey::from(*array_ref::array_ref![one_time_prekey, 0, 32]);
            let dh4 = our_ephemeral_key
                .secret
                .diffie_hellman(&their_one_time_pub);
            shared_secret.extend_from_slice(dh4.as_bytes());
        }

        // Derive root and chain keys using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut root_key = Zeroizing::new([0u8; 32]);
        let mut chain_key = Zeroizing::new([0u8; 32]);

        hkdf.expand(b"MigChat-RootKey", &mut *root_key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;
        hkdf.expand(b"MigChat-ChainKey", &mut *chain_key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

        // Create session
        let session = Session {
            username: username.to_string(),
            identity_key: BASE64.encode(their_identity_key),
            session_keys: SessionKeys {
                root_key: BASE64.encode(&*root_key),
                chain_key: BASE64.encode(&*chain_key),
                message_number: 0,
                previous_counter: 0,
            },
            created_at: chrono::Utc::now().timestamp(),
        };

        self.sessions.insert(username.to_string(), session);
        self.save_sessions()?;

        Ok(())
    }

    pub fn get_session(&self, username: &str) -> Option<&Session> {
        self.sessions.get(username)
    }

    pub fn has_session(&self, username: &str) -> bool {
        self.sessions.contains_key(username)
    }

    // Establish a session as the receiver from an incoming message
    // This is called when we receive a message from someone we don't have a session with
    pub fn establish_session_from_message(
        &mut self,
        username: &str,
        encrypted_msg: &EncryptedMessage,
        our_identity_key: &KeyPair,
        our_signed_prekey: &KeyPair,
    ) -> Result<()> {
        // Decode keys from the message
        let their_identity_key_bytes = BASE64.decode(&encrypted_msg.sender_identity_key)?;
        let their_ephemeral_key_bytes = BASE64.decode(&encrypted_msg.ephemeral_key)?;

        let their_identity_pub = PublicKey::from(*array_ref::array_ref![&their_identity_key_bytes, 0, 32]);
        let their_ephemeral_pub = PublicKey::from(*array_ref::array_ref![&their_ephemeral_key_bytes, 0, 32]);

        // Receiver's X3DH key agreement (matching sender's operations)
        // Sender computed: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B)
        // Receiver computes the same shared secrets (DH is symmetric):

        // DH1 = DH(SPK_B, IK_A) = DH(IK_A, SPK_B) [symmetric]
        let dh1 = our_signed_prekey.secret.diffie_hellman(&their_identity_pub);

        // DH2 = DH(IK_B, EK_A) = DH(EK_A, IK_B) [symmetric]
        let dh2 = our_identity_key.secret.diffie_hellman(&their_ephemeral_pub);

        // DH3 = DH(SPK_B, EK_A) = DH(EK_A, SPK_B) [symmetric]
        let dh3 = our_signed_prekey.secret.diffie_hellman(&their_ephemeral_pub);

        // Combine DH outputs (same order as sender)
        let mut shared_secret = Vec::new();
        shared_secret.extend_from_slice(dh1.as_bytes());
        shared_secret.extend_from_slice(dh2.as_bytes());
        shared_secret.extend_from_slice(dh3.as_bytes());

        // Derive root and chain keys using HKDF (same as sender)
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut root_key = Zeroizing::new([0u8; 32]);
        let mut chain_key = Zeroizing::new([0u8; 32]);

        hkdf.expand(b"MigChat-RootKey", &mut *root_key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;
        hkdf.expand(b"MigChat-ChainKey", &mut *chain_key)
            .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

        // Create session
        let session = Session {
            username: username.to_string(),
            identity_key: BASE64.encode(&their_identity_key_bytes),
            session_keys: SessionKeys {
                root_key: BASE64.encode(&*root_key),
                chain_key: BASE64.encode(&*chain_key),
                message_number: 0,
                previous_counter: 0,
            },
            created_at: chrono::Utc::now().timestamp(),
        };

        self.sessions.insert(username.to_string(), session);
        self.save_sessions()?;

        Ok(())
    }

    fn derive_message_key_static(chain_key: &[u8], message_number: u32) -> Result<Zeroizing<Vec<u8>>> {
        let mut mac = <Hmac::<Sha256> as HmacMac>::new_from_slice(chain_key)
            .map_err(|e| anyhow!("HMAC creation failed: {}", e))?;
        mac.update(&message_number.to_be_bytes());
        mac.update(b"MigChat-MessageKey");

        let result = mac.finalize();
        Ok(Zeroizing::new(result.into_bytes().to_vec()))
    }

    fn advance_chain_key_static(chain_key: &[u8]) -> Result<Vec<u8>> {
        let mut mac = <Hmac::<Sha256> as HmacMac>::new_from_slice(chain_key)
            .map_err(|e| anyhow!("HMAC creation failed: {}", e))?;
        mac.update(b"MigChat-ChainKeyAdvance");

        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    pub fn encrypt_message(
        &mut self,
        username: &str,
        plaintext: &[u8],
        our_identity_key: &KeyPair,
        their_identity_key: &[u8],
    ) -> Result<EncryptedMessage> {
        // Extract data needed before getting mutable borrow
        let (chain_key_str, message_number) = {
            let session = self
                .sessions
                .get(username)
                .ok_or_else(|| anyhow!("No session found for {}", username))?;
            (session.session_keys.chain_key.clone(), session.session_keys.message_number)
        };

        // Derive message key from chain key
        let chain_key = BASE64.decode(&chain_key_str)?;
        let message_key = Self::derive_message_key_static(&chain_key, message_number)?;

        // Encrypt message
        let cipher = ChaCha20Poly1305::new_from_slice(&message_key[..32])
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut nonce_and_ciphertext = Vec::with_capacity(12 + ciphertext.len());
        nonce_and_ciphertext.extend_from_slice(&nonce_bytes);
        nonce_and_ciphertext.extend_from_slice(&ciphertext);

        // Create MAC over nonce + ciphertext
        let mut mac = <Hmac::<Sha256> as HmacMac>::new_from_slice(&message_key[..32])
            .map_err(|e| anyhow!("HMAC creation failed: {}", e))?;
        mac.update(&nonce_and_ciphertext);
        mac.update(our_identity_key.public_bytes().as_slice());
        mac.update(their_identity_key);
        let mac_result = mac.finalize();

        // Advance chain key and update session
        let new_chain_key = Self::advance_chain_key_static(&chain_key)?;
        let session = self.sessions.get_mut(username).unwrap();
        session.session_keys.chain_key = BASE64.encode(&new_chain_key);
        session.session_keys.message_number += 1;

        self.save_sessions()?;

        // Use our identity key public bytes as the ephemeral key field
        // (kept for backwards compatibility with message structure)
        Ok(EncryptedMessage {
            version: 1,
            sender_identity_key: BASE64.encode(our_identity_key.public_bytes()),
            receiver_identity_key: BASE64.encode(their_identity_key),
            ephemeral_key: BASE64.encode(our_identity_key.public_bytes()),
            ciphertext: BASE64.encode(&nonce_and_ciphertext),
            mac: BASE64.encode(mac_result.into_bytes()),
        })
    }

    pub fn decrypt_message(
        &mut self,
        username: &str,
        encrypted_msg: &EncryptedMessage,
        our_identity_key: &KeyPair,
        advance_ratchet: bool,
    ) -> Result<String> {
        // Session must already exist - caller should establish it first
        if !self.has_session(username) {
            return Err(anyhow!("No session exists for {}. Establish a session first.", username));
        }

        // Extract data needed before getting mutable borrow
        let (chain_key_str, message_number) = {
            let session = self
                .sessions
                .get(username)
                .ok_or_else(|| anyhow!("No session found for {}", username))?;
            (session.session_keys.chain_key.clone(), session.session_keys.message_number)
        };

        // Decode the nonce + ciphertext
        let nonce_and_ciphertext = BASE64.decode(&encrypted_msg.ciphertext)?;
        if nonce_and_ciphertext.len() < 12 {
            return Err(anyhow!("Invalid ciphertext: too short"));
        }

        let sender_identity_key = BASE64.decode(&encrypted_msg.sender_identity_key)?;
        let receiver_identity_key = BASE64.decode(&encrypted_msg.receiver_identity_key)?;
        let mac_bytes = BASE64.decode(&encrypted_msg.mac)?;

        // Derive message key
        let chain_key = BASE64.decode(&chain_key_str)?;
        let message_key = Self::derive_message_key_static(&chain_key, message_number)?;

        // Verify MAC over nonce + ciphertext
        let mut mac = <Hmac::<Sha256> as HmacMac>::new_from_slice(&message_key[..32])
            .map_err(|e| anyhow!("HMAC creation failed: {}", e))?;
        mac.update(&nonce_and_ciphertext);
        mac.update(&sender_identity_key);
        mac.update(&receiver_identity_key);

        mac.verify_slice(&mac_bytes)
            .map_err(|_| anyhow!("MAC verification failed"))?;

        // Extract nonce (first 12 bytes) and ciphertext (rest)
        let nonce_bytes = &nonce_and_ciphertext[..12];
        let ciphertext = &nonce_and_ciphertext[12..];
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt message
        let cipher = ChaCha20Poly1305::new_from_slice(&message_key[..32])
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // Only advance chain key and update session if requested
        // This allows viewing old messages without breaking the ratchet
        if advance_ratchet {
            let new_chain_key = Self::advance_chain_key_static(&chain_key)?;
            let session = self.sessions.get_mut(username).unwrap();
            session.session_keys.chain_key = BASE64.encode(&new_chain_key);
            session.session_keys.message_number += 1;
            self.save_sessions()?;
        }

        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }

    pub fn delete_session(&mut self, username: &str) -> Result<()> {
        self.sessions.remove(username);
        self.save_sessions()?;
        Ok(())
    }

    pub fn list_sessions(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }
}

// Helper module for array references
mod array_ref {
    macro_rules! array_ref {
        ($arr:expr, $offset:expr, $len:expr) => {{
            #[inline]
            fn as_array<T>(slice: &[T]) -> &[T; $len] {
                unsafe { &*(slice.as_ptr() as *const [T; $len]) }
            }
            as_array(&$arr[$offset..$offset + $len])
        }};
    }
    pub(crate) use array_ref;
}
