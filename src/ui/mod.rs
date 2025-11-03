use crate::api::{ApiClient, MessageResponse};
use crate::config::Config;
use anyhow::Result;
use chrono::Local;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};

pub struct UI {
    api: ApiClient,
    config: Config,
}

impl UI {
    pub fn new(config: Config) -> Self {
        let api = ApiClient::new(config.server_url.clone());
        Self { api, config }
    }

    pub fn run(&mut self) -> Result<()> {
        self.clear_screen();
        self.print_banner();

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
            } else {
                if !self.show_main_menu()? {
                    break;
                }
            }
        }

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

        let options = vec![
            "View Conversations",
            "View All Messages",
            "Send Message",
            "Switch Account",
            "Logout",
            "Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Main Menu")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => self.view_conversations(),
            1 => self.view_messages(),
            2 => self.send_message(),
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

    fn send_message(&mut self) -> Result<bool> {
        println!();
        let to_username: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Send to (username)")
            .interact_text()?;

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

    fn view_messages(&mut self) -> Result<bool> {
        let token = self.config.get_current_token().unwrap();

        println!("\n{}", "Loading messages...".yellow());

        match self.api.get_messages(token) {
            Ok(messages) => {
                self.clear_screen();
                println!("{}", "═══ All Messages ═══".cyan().bold());
                println!();

                if messages.is_empty() {
                    println!("{}", "No messages yet.".yellow());
                } else {
                    for msg in messages.iter() {
                        self.print_message(msg);
                    }
                }

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
                self.clear_screen();
                println!("{}", "═══ Conversations ═══".cyan().bold());
                println!();

                if conversations.is_empty() {
                    println!("{}", "No conversations yet.".yellow());
                } else {
                    for conv in conversations.iter() {
                        let time = conv.last_message_time.with_timezone(&Local);
                        let time_str = time.format("%Y-%m-%d %H:%M:%S").to_string();

                        println!("{}", format!("┌─ {} {}", conv.username, if conv.unread_count > 0 { format!("({})", conv.unread_count).red().to_string() } else { "".to_string() }).bold());
                        println!("│  {}", conv.last_message.bright_black());
                        println!("└─ {}", time_str.bright_black());
                        println!();
                    }
                }

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

    fn logout(&mut self) -> Result<()> {
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
        println!("{}", "╔═══════════════════════════════════╗".cyan());
        println!("{}", "║                                   ║".cyan());
        println!("{}", "║          MigChat CLI              ║".cyan().bold());
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
}
