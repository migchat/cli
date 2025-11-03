use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use super::keys::{KeyBundle, KeyManager, KeyPair};
use super::session::{EncryptedMessage, SessionManager};

pub struct EncryptionManager {
    key_manager: KeyManager,
    session_manager: SessionManager,
}

impl EncryptionManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            key_manager: KeyManager::new()?,
            session_manager: SessionManager::new()?,
        })
    }

    pub fn initialize_keys(&self, password: &str) -> Result<()> {
        if self.key_manager.keys_exist() {
            return Ok(());
        }
        self.key_manager.generate_keys(password)
    }

    pub fn keys_exist(&self) -> bool {
        self.key_manager.keys_exist()
    }

    pub fn get_public_key_bundle(&self, password: &str) -> Result<KeyBundle> {
        self.key_manager.get_public_key_bundle(password)
    }

    pub fn get_fingerprint(&self) -> Result<String> {
        let metadata = self.key_manager.load_metadata()?;
        Ok(metadata.identity_key_fingerprint)
    }

    pub fn get_fingerprint_for_key(&self, public_key: &str) -> Result<String> {
        let key_bytes = BASE64.decode(public_key)?;
        Ok(self.key_manager.generate_fingerprint(&key_bytes))
    }

    pub fn establish_session_with_bundle(
        &mut self,
        username: &str,
        password: &str,
        their_bundle: &KeyBundle,
    ) -> Result<()> {
        let our_identity_key = self.key_manager.load_identity_key(password)?;
        let our_ephemeral_key = KeyPair::generate();

        let their_identity_key = BASE64.decode(&their_bundle.identity_key)?;
        let their_signed_prekey = BASE64.decode(&their_bundle.signed_prekey)?;

        let their_one_time_prekey = their_bundle
            .one_time_prekeys
            .first()
            .map(|k| BASE64.decode(k))
            .transpose()?;

        self.session_manager.establish_session(
            username,
            &our_identity_key,
            &our_ephemeral_key,
            &their_identity_key,
            &their_signed_prekey,
            their_one_time_prekey.as_deref(),
        )
    }

    pub fn has_session(&self, username: &str) -> bool {
        self.session_manager.has_session(username)
    }

    pub fn encrypt_message(
        &mut self,
        username: &str,
        password: &str,
        message: &str,
        their_identity_key: &str,
    ) -> Result<String> {
        let our_identity_key = self.key_manager.load_identity_key(password)?;
        let their_identity_key_bytes = BASE64.decode(their_identity_key)?;

        let encrypted_msg = self.session_manager.encrypt_message(
            username,
            message.as_bytes(),
            &our_identity_key,
            &their_identity_key_bytes,
        )?;

        // Serialize to JSON
        let json = serde_json::to_string(&encrypted_msg)?;
        Ok(BASE64.encode(json.as_bytes()))
    }

    pub fn decrypt_message(
        &mut self,
        username: &str,
        password: &str,
        encrypted_message: &str,
    ) -> Result<String> {
        let our_identity_key = self.key_manager.load_identity_key(password)?;

        // Deserialize from base64-encoded JSON
        let json_bytes = BASE64.decode(encrypted_message)?;
        let json_str = std::str::from_utf8(&json_bytes)?;
        let encrypted_msg: EncryptedMessage = serde_json::from_str(json_str)?;

        self.session_manager
            .decrypt_message(username, &encrypted_msg, &our_identity_key)
    }

    pub fn verify_contact_key(
        &self,
        username: &str,
        identity_key: &str,
        fingerprint: &str,
    ) -> Result<()> {
        self.key_manager
            .verify_and_save_contact_key(username, identity_key, fingerprint)
    }

    pub fn is_contact_verified(&self, username: &str) -> bool {
        self.key_manager.get_verified_key(username).is_some()
    }

    pub fn get_verified_key_fingerprint(&self, username: &str) -> Option<String> {
        self.key_manager
            .get_verified_key(username)
            .map(|k| k.fingerprint)
    }

    pub fn check_key_change(&self, username: &str, new_identity_key: &str) -> Result<bool> {
        self.key_manager.check_key_change(username, new_identity_key)
    }

    pub fn export_backup(&self, password: &str, backup_password: &str) -> Result<String> {
        self.key_manager.export_keys(password, backup_password)
    }

    pub fn import_backup(
        &self,
        encrypted_backup: &str,
        backup_password: &str,
        new_password: &str,
    ) -> Result<()> {
        self.key_manager
            .import_keys(encrypted_backup, backup_password, new_password)
    }

    pub fn delete_session(&mut self, username: &str) -> Result<()> {
        self.session_manager.delete_session(username)
    }

    pub fn list_sessions(&self) -> Vec<String> {
        self.session_manager.list_sessions()
    }
}
