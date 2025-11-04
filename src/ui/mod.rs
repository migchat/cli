use crate::api::{ApiClient, MessageResponse};
use crate::config::{Account, Config};
use crate::crypto::EncryptionManager;
use crate::polling::MessagePoller;
use crate::update;
use anyhow::{anyhow, Result};
use chrono::Local;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};

pub struct UI {
    api: ApiClient,
    config: Config,
    update_available: Option<String>,
    poller: Option<MessagePoller>,
    encryption: Option<EncryptionManager>,
    current_password: Option<String>,
}

impl UI {
    pub fn new(config: Config) -> Self {
        let api = ApiClient::new(config.server_url.clone());
        // Initialize encryption manager for current account if logged in
        let encryption = if let Some(username) = config.get_current_username() {
            EncryptionManager::for_account(&username).ok()
        } else {
            None
        };
        Self {
            api,
            config,
            update_available: None,
            poller: None,
            encryption,
            current_password: None,
        }
    }

    fn switch_encryption_manager(&mut self, username: &str) {
        // Switch to account-specific encryption manager
        self.encryption = EncryptionManager::for_account(username).ok();
    }

    fn ensure_encryption(&self) -> Result<&EncryptionManager> {
        self.encryption.as_ref()
            .ok_or_else(|| anyhow!("Encryption manager not initialized"))
    }

    fn ensure_encryption_mut(&mut self) -> Result<&mut EncryptionManager> {
        self.encryption.as_mut()
            .ok_or_else(|| anyhow!("Encryption manager not initialized"))
    }

    fn ensure_password(&mut self) -> Result<String> {
        if let Some(password) = &self.current_password {
            return Ok(password.clone());
        }

        // Prompt for password
        let password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter password for decryption")
            .interact()?;

        self.current_password = Some(password.clone());
        Ok(password)
    }

    fn start_polling(&mut self) {
        if self.config.is_logged_in() {
            let poller = MessagePoller::new();
            let server_url = self.config.server_url.clone();
            let token = self.config.get_current_token().unwrap().clone();
            let username = self.config.get_current_username().unwrap().clone();

            poller.start(server_url, token, username);
            self.poller = Some(poller);
        }
    }

    fn stop_polling(&mut self) {
        if let Some(poller) = self.poller.take() {
            poller.stop();
        }
    }

    pub fn run(&mut self) -> Result<()> {
        self.clear_screen();
        self.print_banner();

        // Check for updates
        match update::check_for_updates() {
            Ok(Some(version)) => {
                self.update_available = Some(version.clone());
                println!(
                    "{}",
                    format!(
                        "⚠ Update available: v{} (current: v{})",
                        version,
                        update::get_current_version()
                    )
                    .yellow()
                    .bold()
                );
                println!();
            }
            Ok(None) => {}
            Err(_) => {
                // Silently ignore update check errors
            }
        }

        // Check server health
        match self.api.health_check() {
            Ok(true) => {
                println!("{}", format!("✓ Connected to server: {}", self.config.server_url).green());
                println!();
            }
            _ => {
                println!("{}", format!("✗ Cannot connect to server: {}", self.config.server_url).red());
                println!();
            }
        }

        loop {
            if !self.config.is_logged_in() {
                if !self.show_auth_menu()? {
                    break;
                }
                // Start polling after login
                self.start_polling();
            } else {
                if !self.show_main_menu()? {
                    break;
                }
            }
        }

        // Stop polling when exiting
        self.stop_polling();

        Ok(())
    }

    fn show_auth_menu(&mut self) -> Result<bool> {
        // If there are existing accounts, show account selection
        if self.config.has_accounts() {
            let mut options: Vec<String> = self.config.get_account_list();
            options.push("Create New Account".to_string());
            options.push("Set Server URL".to_string());
            options.push("Exit".to_string());

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select an account to login")
                .items(&options)
                .default(0)
                .interact()?;

            if selection < self.config.get_account_list().len() {
                // User selected an existing account
                let username = options[selection].clone();

                // Prompt for password for encryption
                let password: String = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Password (for encryption)")
                    .interact()?;

                self.current_password = Some(password.clone());
                self.config.switch_account(&username);
                self.switch_encryption_manager(&username);
                self.config.save()?;

                // Generate encryption keys if they don't exist
                if !self.ensure_encryption()?.keys_exist() {
                    println!("{}", "🔐 Generating encryption keys...".yellow());
                    if let Err(e) = self.ensure_encryption()?.initialize_keys(&password) {
                        println!("{}", format!("⚠ Warning: Failed to generate encryption keys: {}", e).yellow());
                    } else {
                        println!("{}", "✓ Encryption keys generated!".green());

                        // Upload public keys to server
                        if let Some(token) = self.config.get_current_token() {
                            println!("{}", "📤 Uploading public keys...".yellow());
                            if let Ok(key_bundle) = self.ensure_encryption()?.get_public_key_bundle(&password) {
                                let api_key_bundle = crate::api::models::KeyBundle {
                                    identity_key: key_bundle.identity_key,
                                    signed_prekey: key_bundle.signed_prekey,
                                    signed_prekey_signature: key_bundle.signed_prekey_signature,
                                    one_time_prekeys: key_bundle.one_time_prekeys,
                                };

                                if let Err(e) = self.api.upload_keys(token, api_key_bundle) {
                                    println!("{}", format!("⚠ Warning: Failed to upload keys: {}", e).yellow());
                                } else {
                                    println!("{}", "✓ Public keys uploaded!".green());
                                }
                            }
                        }

                        // Show fingerprint
                        if let Ok(fingerprint) = self.ensure_encryption()?.get_fingerprint() {
                            println!();
                            println!("{}", "Your encryption fingerprint:".cyan().bold());
                            println!("{}", fingerprint.bright_white().bold());
                            println!();
                        }

                        println!("{}", "✓ End-to-end encryption enabled! 🔒".green().bold());
                    }
                }

                println!("{}", format!("✓ Logged in as {}!", username).green());
                println!();
                self.wait_for_enter();
                Ok(true)
            } else if selection == self.config.get_account_list().len() {
                // Create new account
                self.create_account()
            } else if selection == self.config.get_account_list().len() + 1 {
                // Set server URL
                self.set_server_url()
            } else {
                // Exit
                Ok(false)
            }
        } else {
            // No accounts exist, prompt to create one
            let options = vec!["Create Account", "Set Server URL", "Exit"];

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Welcome to MigChat")
                .items(&options)
                .default(0)
                .interact()?;

            match selection {
                0 => self.create_account(),
                1 => self.set_server_url(),
                2 => Ok(false),
                _ => Ok(true),
            }
        }
    }

    fn show_main_menu(&mut self) -> Result<bool> {
        self.clear_screen();
        println!("{}", format!("Logged in as: {}", self.config.get_current_username().unwrap()).cyan().bold());
        println!();

        let mut options = vec![
            "View Conversations",
            "Send Message",
            "Security & Encryption",
            "Change Username",
        ];

        // Add update option if update is available
        let update_offset = if self.update_available.is_some() {
            options.push("Update to Latest Version");
            1
        } else {
            0
        };

        options.extend_from_slice(&[
            "Switch Account",
            "Logout",
            "Exit",
        ]);

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Main Menu")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => self.view_conversations(),
            1 => self.send_message(None),
            2 => self.security_menu(),
            3 => self.change_username(),
            4 if update_offset == 1 => self.perform_update(),
            _ => {
                let adjusted = selection - update_offset;
                match adjusted {
                    4 => {
                        self.logout()?;
                        Ok(true)
                    }
                    5 => {
                        self.logout()?;
                        Ok(true)
                    }
                    6 => Ok(false),
                    _ => Ok(true),
                }
            }
        }
    }

    fn create_account(&mut self) -> Result<bool> {
        println!();
        let username: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Username")
            .interact_text()?;

        let password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .interact()?;

        let confirm_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm Password")
            .interact()?;

        if password != confirm_password {
            println!("{}", "✗ Passwords do not match!".red());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        println!("\n{}", "Creating account...".yellow());

        match self.api.create_account(username.clone(), password.clone()) {
            Ok(response) => {
                self.config.add_account(response.username.clone(), response.token.clone());
                self.switch_encryption_manager(&response.username);
                self.config.save()?;

                // Store password temporarily for key operations
                self.current_password = Some(password.clone());

                println!("{}", "✓ Account created successfully!".green());
                println!("{}", "🔐 Generating encryption keys...".yellow());

                // Generate encryption keys
                if let Err(e) = self.ensure_encryption()?.initialize_keys(&password) {
                    println!("{}", format!("⚠ Warning: Failed to generate encryption keys: {}", e).yellow());
                } else {
                    println!("{}", "✓ Encryption keys generated!".green());

                    // Upload public keys to server
                    println!("{}", "📤 Uploading public keys...".yellow());
                    if let Ok(key_bundle) = self.ensure_encryption()?.get_public_key_bundle(&password) {
                        let api_key_bundle = crate::api::models::KeyBundle {
                            identity_key: key_bundle.identity_key,
                            signed_prekey: key_bundle.signed_prekey,
                            signed_prekey_signature: key_bundle.signed_prekey_signature,
                            one_time_prekeys: key_bundle.one_time_prekeys,
                        };

                        if let Err(e) = self.api.upload_keys(&response.token, api_key_bundle) {
                            println!("{}", format!("⚠ Warning: Failed to upload keys: {}", e).yellow());
                        } else {
                            println!("{}", "✓ Public keys uploaded!".green());
                        }
                    }

                    // Show fingerprint
                    if let Ok(fingerprint) = self.ensure_encryption()?.get_fingerprint() {
                        println!();
                        println!("{}", "Your encryption fingerprint:".cyan().bold());
                        println!("{}", fingerprint.bright_white().bold());
                        println!();
                        println!("{}", "⚠ Save this fingerprint! Others can verify it's really you.".yellow());
                    }
                }

                println!();
                println!("{}", "✓ End-to-end encryption enabled! 🔒".green().bold());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
            Err(e) => {
                println!("{}", format!("✗ Error: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }

    fn send_message(&mut self, to_username: Option<String>) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Send Message ═══".cyan().bold());
        println!();

        // Show menu with Send and Cancel options
        let options = vec!["Send Message", "← Cancel"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact()?;

        if selection == 1 {
            // Cancel selected
            return Ok(true);
        }

        println!();
        let to_username: String = match to_username {
            Some(username) => {
                println!("{}", format!("Replying to: {}", username).cyan().bold());
                username
            }
            None => {
                let input: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Send to (username)")
                    .allow_empty(true)
                    .interact_text()?;

                if input.is_empty() {
                    println!("{}", "✗ Cancelled".yellow());
                    println!();
                    self.wait_for_enter();
                    return Ok(true);
                }
                input
            }
        };

        let content: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Message (leave empty to cancel)")
            .allow_empty(true)
            .interact_text()?;

        if content.is_empty() {
            println!("{}", "✗ Cancelled".yellow());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        println!("\n{}", "🔐 Encrypting message...".yellow());

        let token = self.config.get_current_token().unwrap().clone();
        let password = match &self.current_password {
            Some(p) => p.clone(),
            None => {
                println!("{}", "✗ Password required for encryption".red());
                println!();
                self.wait_for_enter();
                return Ok(true);
            }
        };

        // Fetch recipient's public keys and establish session if needed
        if !self.ensure_encryption()?.has_session(&to_username) {
            println!("{}", format!("🔑 Establishing secure session with {}...", to_username).yellow());

            match self.api.get_keys(&token, &to_username) {
                Ok(response) => {
                    let crypto_key_bundle = crate::crypto::keys::KeyBundle {
                        identity_key: response.key_bundle.identity_key.clone(),
                        signed_prekey: response.key_bundle.signed_prekey.clone(),
                        signed_prekey_signature: response.key_bundle.signed_prekey_signature.clone(),
                        one_time_prekeys: response.key_bundle.one_time_prekeys.clone(),
                    };

                    // Check for key changes (security feature)
                    if let Ok(key_changed) = self.ensure_encryption()?.check_key_change(&to_username, &response.key_bundle.identity_key) {
                        if key_changed {
                            println!();
                            println!("{}", format!("⚠️  WARNING: {}'s encryption keys have changed!", to_username).red().bold());
                            println!("{}", "This could indicate:".yellow());
                            println!("{}", "  • They reinstalled the app or got a new device".yellow());
                            println!("{}", "  • Someone is trying to intercept your messages (rare)".yellow());
                            println!();

                            let continue_sending = Confirm::with_theme(&ColorfulTheme::default())
                                .with_prompt("Do you want to continue sending?")
                                .default(false)
                                .interact()?;

                            if !continue_sending {
                                println!("{}", "✗ Message cancelled".yellow());
                                println!();
                                self.wait_for_enter();
                                return Ok(true);
                            }
                        }
                    }

                    if let Err(e) = self.ensure_encryption_mut()?.establish_session_with_bundle(&to_username, &password, &crypto_key_bundle) {
                        println!("{}", format!("✗ Failed to establish secure session: {}", e).red());
                        println!();
                        self.wait_for_enter();
                        return Ok(true);
                    }

                    println!("{}", "✓ Secure session established!".green());
                }
                Err(e) => {
                    println!("{}", format!("✗ Failed to get recipient's keys: {}", e).red());
                    println!("{}", "⚠ Sending unencrypted message...".yellow());

                    // Fallback to unencrypted
                    match self.api.send_message(&token, to_username.clone(), content) {
                        Ok(_) => {
                            println!("{}", format!("✓ Message sent to {}! (unencrypted)", to_username).green());
                            println!();
                            self.wait_for_enter();
                            return Ok(true);
                        }
                        Err(e) => {
                            println!("{}", format!("✗ Error: {}", e).red());
                            println!();
                            self.wait_for_enter();
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // Encrypt the message
        let encrypted_content = match self.api.get_keys(&token, &to_username) {
            Ok(response) => {
                match self.ensure_encryption_mut()?.encrypt_message(&to_username, &password, &content, &response.key_bundle.identity_key) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        println!("{}", format!("✗ Encryption failed: {}", e).red());
                        println!();
                        self.wait_for_enter();
                        return Ok(true);
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("✗ Failed to get recipient's keys: {}", e).red());
                println!();
                self.wait_for_enter();
                return Ok(true);
            }
        };

        println!("{}", "📤 Sending encrypted message...".yellow());

        match self.api.send_message(&token, to_username.clone(), encrypted_content) {
            Ok(_) => {
                println!("{}", format!("✓ Encrypted message sent to {}! 🔒", to_username).green().bold());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
            Err(e) => {
                println!("{}", format!("✗ Error: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }

    fn change_username(&mut self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Change Username ═══".cyan().bold());
        println!();
        println!("{}", format!("Current username: {}", self.config.get_current_username().unwrap()).bright_black());
        println!();

        // Show menu with Change and Cancel options
        let options = vec!["Change Username", "← Cancel"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact()?;

        if selection == 1 {
            // Cancel selected
            return Ok(true);
        }

        println!();
        let new_username: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("New username (leave empty to cancel)")
            .allow_empty(true)
            .interact_text()?;

        if new_username.is_empty() {
            println!("{}", "✗ Cancelled".yellow());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        println!("\n{}", "Updating username...".yellow());

        let token = self.config.get_current_token().unwrap().clone();

        match self.api.update_username(&token, new_username.clone()) {
            Ok(response) => {
                // Update config with new username
                let old_username = self.config.get_current_username().unwrap().clone();
                if let Some(account) = self.config.accounts.remove(&old_username) {
                    let updated_account = Account {
                        username: response.username.clone(),
                        token: account.token,
                    };
                    self.config.accounts.insert(response.username.clone(), updated_account);
                    self.config.current_account = Some(response.username.clone());
                    self.config.save()?;
                }

                println!("{}", format!("✓ Username updated to {}!", response.username).green());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
            Err(e) => {
                println!("{}", format!("✗ Error: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }

    fn view_conversations(&mut self) -> Result<bool> {
        let token = self.config.get_current_token().unwrap().clone();

        println!("\n{}", "Loading conversations...".yellow());

        match self.api.get_conversations(&token) {
            Ok(conversations) => {
                if conversations.is_empty() {
                    self.clear_screen();
                    println!("{}", "═══ Conversations ═══".cyan().bold());
                    println!();
                    println!("{}", "No conversations yet.".yellow());
                    println!();
                    self.wait_for_enter();
                    Ok(true)
                } else {
                    self.clear_screen();
                    println!("{}", "═══ Conversations ═══".cyan().bold());
                    println!();

                    // Create list of conversation labels with unread indicators
                    let mut options: Vec<String> = conversations
                        .iter()
                        .map(|conv| {
                            if conv.unread_count > 0 {
                                format!("{} ({} unread)", conv.username, conv.unread_count)
                            } else {
                                conv.username.clone()
                            }
                        })
                        .collect();
                    options.push("← Back".to_string());

                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Select a conversation")
                        .items(&options)
                        .default(0)
                        .interact()?;

                    if selection < conversations.len() {
                        // User selected a conversation
                        let username = conversations[selection].username.clone();
                        self.view_conversation_messages(&username)?;
                    }

                    Ok(true)
                }
            }
            Err(e) => {
                println!("{}", format!("✗ Error: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }

    fn view_conversation_messages(&mut self, username: &str) -> Result<bool> {
        let token = self.config.get_current_token().unwrap().clone();
        let current_user = self.config.get_current_username().unwrap().clone();

        println!("\n{}", "Loading messages...".yellow());

        // Mark messages as read when opening the conversation
        let _ = self.api.mark_messages_read(&token, username);

        match self.api.get_filtered_messages(&token, username) {
            Ok(all_messages) => {
                // Note: API returns messages in DESC order (newest first), so we reverse to get chronological order
                let mut messages: Vec<_> = all_messages
                    .iter()
                    .filter(|msg| {
                        (&msg.from_username == username && &msg.to_username == &current_user)
                            || (&msg.from_username == &current_user && &msg.to_username == username)
                    })
                    .collect();
                messages.reverse(); // Now oldest to newest (chronological)

                loop {
                    self.clear_screen();
                    println!("{}", format!("═══ Conversation with {} ═══", username).cyan().bold());
                    println!();

                    if messages.is_empty() {
                        println!("{}", "No messages yet.".yellow());
                    } else {
                        // Display messages in chronological order (oldest first, latest at bottom)
                        for msg in messages.iter().cloned() {
                            self.print_message(&msg);
                        }
                    }

                    println!();

                    let options = vec!["Reply", "← Back"];

                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Actions")
                        .items(&options)
                        .default(0)
                        .interact()?;

                    match selection {
                        0 => {
                            // Reply
                            self.send_message(Some(username.to_string()))?;
                            // Refresh messages after sending
                            return self.view_conversation_messages(username);
                        }
                        1 => {
                            // Back
                            break;
                        }
                        _ => break,
                    }
                }

                Ok(true)
            }
            Err(e) => {
                println!("{}", format!("✗ Error: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }

    fn logout(&mut self) -> Result<()> {
        self.stop_polling();
        self.config.logout_current();
        self.config.save()?;
        println!("\n{}", "✓ Logged out successfully!".green());
        println!();
        self.wait_for_enter();
        Ok(())
    }

    fn set_server_url(&mut self) -> Result<bool> {
        println!();
        let url: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Server URL")
            .default(self.config.server_url.clone())
            .interact_text()?;

        self.config.server_url = url;
        self.config.save()?;
        self.api = ApiClient::new(self.config.server_url.clone());

        println!("{}", "✓ Server URL updated!".green());
        println!();
        self.wait_for_enter();
        Ok(true)
    }

    fn print_message(&mut self, msg: &MessageResponse) {
        let time = msg.created_at.with_timezone(&Local);
        let time_str = time.format("%Y-%m-%d %H:%M:%S").to_string();
        let current_user = self.config.get_current_username().unwrap().clone();

        if msg.from_username == current_user {
            // Sent message
            println!("{} {} → {}",
                time_str.bright_black(),
                "You".green().bold(),
                msg.to_username.cyan()
            );
        } else {
            // Received message
            println!("{} {} → {} 🔒",
                time_str.bright_black(),
                msg.from_username.cyan().bold(),
                "You".green()
            );
        }

        // Try to decrypt the message
        let decrypted_content = if let Ok(password) = self.ensure_password() {
            let sender = if msg.from_username == current_user {
                &msg.to_username
            } else {
                &msg.from_username
            };

            // Try to decrypt - if encryption manager exists
            if let Ok(enc) = self.ensure_encryption_mut() {
                match enc.decrypt_message(sender, &password, &msg.content) {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        // Decryption failed - might be plaintext (backwards compatibility)
                        // Try to decode base64 to check if it's encrypted
                        if msg.content.len() > 100 && msg.content.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
                            // Looks like encrypted content that failed to decrypt
                            format!("[Encrypted message - decryption failed: {}]", e)
                        } else {
                            // Probably plaintext
                            msg.content.clone()
                        }
                    }
                }
            } else {
                // No encryption manager - show plaintext
                msg.content.clone()
            }
        } else {
            msg.content.clone()
        };

        println!("  {}", decrypted_content);
        println!();
    }

    fn security_menu(&mut self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Security & Encryption ═══".cyan().bold());
        println!();

        let options = vec![
            "View My Fingerprint",
            "Verify Contact",
            "Export Key Backup",
            "Import Key Backup",
            "← Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Security Options")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => self.view_fingerprint(),
            1 => self.verify_contact(),
            2 => self.export_backup(),
            3 => self.import_backup(),
            4 => Ok(true),
            _ => Ok(true),
        }
    }

    fn view_fingerprint(&self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Your Encryption Fingerprint ═══".cyan().bold());
        println!();

        match self.ensure_encryption()?.get_fingerprint() {
            Ok(fingerprint) => {
                println!("{}", fingerprint.bright_white().bold());
                println!();
                println!("{}", "Share this fingerprint with your contacts so they can verify it's really you.".yellow());
            }
            Err(e) => {
                println!("{}", format!("✗ Failed to get fingerprint: {}", e).red());
                println!();
                println!("{}", "⚠ Your encryption keys haven't been generated yet.".yellow());
                println!("{}", "Please log out and log back in to generate your encryption keys.".yellow());
            }
        }

        println!();
        self.wait_for_enter();
        Ok(true)
    }

    fn verify_contact(&mut self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Verify Contact ═══".cyan().bold());
        println!();

        let username: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Contact username")
            .allow_empty(true)
            .interact_text()?;

        if username.is_empty() {
            return Ok(true);
        }

        let token = self.config.get_current_token().unwrap().clone();

        println!("\n{}", "Fetching contact's public key...".yellow());

        match self.api.get_keys(&token, &username) {
            Ok(response) => {
                let fingerprint = self.ensure_encryption()?.get_fingerprint_for_key(&response.key_bundle.identity_key)?;

                println!();
                println!("{}", format!("{}'s fingerprint:", username).cyan().bold());
                println!("{}", fingerprint.bright_white().bold());
                println!();

                let matches = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Does this fingerprint match what they told you?")
                    .default(false)
                    .interact()?;

                if matches {
                    self.ensure_encryption()?.verify_contact_key(&username, &response.key_bundle.identity_key, &fingerprint)?;
                    println!();
                    println!("{}", format!("✓ {} has been marked as verified! ✓", username).green().bold());
                } else {
                    println!();
                    println!("{}", "⚠ Fingerprints do not match! Do not send sensitive messages.".red().bold());
                }
            }
            Err(e) => {
                println!("{}", format!("✗ Failed to get contact's keys: {}", e).red());
            }
        }

        println!();
        self.wait_for_enter();
        Ok(true)
    }

    fn export_backup(&self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Export Key Backup ═══".cyan().bold());
        println!();
        println!("{}", "This will export your encryption keys so you can import them on another device.".yellow());
        println!("{}", "⚠ Keep this backup safe! Anyone with it can read your messages.".red().bold());
        println!();

        let password = match &self.current_password {
            Some(p) => p.clone(),
            None => {
                println!("{}", "✗ Password required".red());
                println!();
                self.wait_for_enter();
                return Ok(true);
            }
        };

        let backup_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Backup password (to encrypt the backup)")
            .interact()?;

        let confirm_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm backup password")
            .interact()?;

        if backup_password != confirm_password {
            println!("{}", "✗ Passwords do not match!".red());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        match self.ensure_encryption()?.export_backup(&password, &backup_password) {
            Ok(backup) => {
                println!();
                println!("{}", "✓ Backup created!".green());
                println!();
                println!("{}", "Your encrypted backup (save this):".cyan().bold());
                println!("{}", backup.bright_white());
                println!();
                println!("{}", "⚠ Store this backup in a safe place!".yellow());
            }
            Err(e) => {
                println!("{}", format!("✗ Failed to create backup: {}", e).red());
            }
        }

        println!();
        self.wait_for_enter();
        Ok(true)
    }

    fn import_backup(&mut self) -> Result<bool> {
        self.clear_screen();
        println!("{}", "═══ Import Key Backup ═══".cyan().bold());
        println!();

        let backup: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Paste your encrypted backup")
            .allow_empty(true)
            .interact_text()?;

        if backup.is_empty() {
            return Ok(true);
        }

        let backup_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Backup password")
            .interact()?;

        let new_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("New password (for this device)")
            .interact()?;

        let confirm_password: String = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm new password")
            .interact()?;

        if new_password != confirm_password {
            println!("{}", "✗ Passwords do not match!".red());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        match self.ensure_encryption()?.import_backup(&backup, &backup_password, &new_password) {
            Ok(_) => {
                self.current_password = Some(new_password);
                println!();
                println!("{}", "✓ Backup imported successfully!".green());
                println!("{}", "You can now decrypt messages from this device.".green());
            }
            Err(e) => {
                println!();
                println!("{}", format!("✗ Failed to import backup: {}", e).red());
            }
        }

        println!();
        self.wait_for_enter();
        Ok(true)
    }

    fn print_banner(&self) {
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        println!("{}", "╔═══════════════════════════════════╗".cyan());
        println!("{}", "║                                   ║".cyan());
        println!("{}", format!("║      MigChat CLI v{:<13}  ║", VERSION).cyan().bold());
        println!("{}", "║     Interactive Chat Client       ║".cyan());
        println!("{}", "║                                   ║".cyan());
        println!("{}", "╚═══════════════════════════════════╝".cyan());
        println!();
    }

    fn clear_screen(&self) {
        print!("\x1B[2J\x1B[1;1H");
    }

    fn wait_for_enter(&self) {
        Input::<String>::new()
            .with_prompt("Press Enter to continue")
            .allow_empty(true)
            .interact_text()
            .ok();
    }

    fn perform_update(&mut self) -> Result<bool> {
        println!();
        println!(
            "{}",
            format!(
                "Updating from v{} to v{}...",
                update::get_current_version(),
                self.update_available.as_ref().unwrap()
            )
            .yellow()
        );
        println!();

        match update::perform_update() {
            Ok(_) => {
                println!("{}", "✓ Update successful! Please restart the application.".green());
                println!();
                self.wait_for_enter();
                // Exit after successful update
                Ok(false)
            }
            Err(e) => {
                println!("{}", format!("✗ Update failed: {}", e).red());
                println!();
                self.wait_for_enter();
                Ok(true)
            }
        }
    }
}
