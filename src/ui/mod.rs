use crate::api::{ApiClient, MessageResponse};
use crate::config::{Account, Config};
use crate::polling::MessagePoller;
use crate::update;
use anyhow::Result;
use chrono::Local;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};

pub struct UI {
    api: ApiClient,
    config: Config,
    update_available: Option<String>,
    poller: Option<MessagePoller>,
}

impl UI {
    pub fn new(config: Config) -> Self {
        let api = ApiClient::new(config.server_url.clone());
        Self {
            api,
            config,
            update_available: None,
            poller: None,
        }
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
                self.config.switch_account(&username);
                self.config.save()?;
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
            2 => self.change_username(),
            3 if update_offset == 1 => self.perform_update(),
            _ => {
                let adjusted = selection - update_offset;
                match adjusted {
                    3 => {
                        self.logout()?;
                        Ok(true)
                    }
                    4 => {
                        self.logout()?;
                        Ok(true)
                    }
                    5 => Ok(false),
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

        println!("\n{}", "Creating account...".yellow());

        match self.api.create_account(username.clone(), password) {
            Ok(response) => {
                self.config.add_account(response.username, response.token);
                self.config.save()?;

                println!("{}", "✓ Account created successfully!".green());
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
        println!();
        let to_username: String = match to_username {
            Some(username) => {
                println!("{}", format!("Replying to: {}", username).cyan().bold());
                username
            }
            None => Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Send to (username)")
                .interact_text()?,
        };

        let content: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Message")
            .interact_text()?;

        println!("\n{}", "Sending message...".yellow());

        let token = self.config.get_current_token().unwrap();

        match self.api.send_message(token, to_username.clone(), content) {
            Ok(_) => {
                println!("{}", format!("✓ Message sent to {}!", to_username).green());
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
        println!();
        let new_username: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("New username")
            .interact_text()?;

        if new_username.is_empty() {
            println!("{}", "✗ Username cannot be empty".red());
            println!();
            self.wait_for_enter();
            return Ok(true);
        }

        println!("\n{}", "Updating username...".yellow());

        let token = self.config.get_current_token().unwrap();

        match self.api.update_username(token, new_username.clone()) {
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
        let token = self.config.get_current_token().unwrap();

        println!("\n{}", "Loading conversations...".yellow());

        match self.api.get_conversations(token) {
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
        let token = self.config.get_current_token().unwrap();
        let current_user = self.config.get_current_username().unwrap().clone();

        println!("\n{}", "Loading messages...".yellow());

        match self.api.get_messages(token) {
            Ok(all_messages) => {
                // Filter messages for this conversation
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
                        for msg in messages.iter() {
                            self.print_message(msg);
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

    fn print_message(&self, msg: &MessageResponse) {
        let time = msg.created_at.with_timezone(&Local);
        let time_str = time.format("%Y-%m-%d %H:%M:%S").to_string();
        let current_user = self.config.get_current_username().unwrap();

        if &msg.from_username == current_user {
            // Sent message
            println!("{} {} → {}",
                time_str.bright_black(),
                "You".green().bold(),
                msg.to_username.cyan()
            );
        } else {
            // Received message
            println!("{} {} → {}",
                time_str.bright_black(),
                msg.from_username.cyan().bold(),
                "You".green()
            );
        }
        println!("  {}", msg.content);
        println!();
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
