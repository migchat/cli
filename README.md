# MigChat CLI

An interactive command-line client for MigChat server, built with Rust.

## Features

- 🎨 **Beautiful Interactive UI** - Colorful, menu-driven interface using dialoguer
- 🔐 **Account Management** - Create accounts and automatic session management
- 💬 **Real-time Messaging** - Send and receive messages to/from other users
- 📋 **Conversation Tracking** - View all your conversations with metadata
- 💾 **Persistent Sessions** - Automatic token storage in `~/.migchat/config.json`
- 🌐 **Configurable Server** - Connect to any MigChat server instance

## Installation

### Quick Install (Recommended)

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/migchat/cli/main/install.sh | bash
```

This will:
- Detect your platform automatically
- Download the latest release binary
- Install to `~/.local/bin/migchat`
- Make it executable

After installation, you may need to add `~/.local/bin` to your PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Manual Installation

1. Download the binary for your platform from the [latest release](https://github.com/migchat/cli/releases/latest)
2. Rename it to `migchat` (remove platform suffix)
3. Make it executable: `chmod +x migchat`
4. Move it to a directory in your PATH: `mv migchat ~/.local/bin/`

### From Source

1. **Install Rust** (if not already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Clone and build**:
```bash
git clone https://github.com/migchat/cli.git
cd cli
cargo build --release
```

3. **Install globally** (optional):
```bash
cargo install --path .
```

Or run directly:
```bash
cargo run
```

## Usage

### Starting the CLI

```bash
# If installed via script or manually
migchat

# If installed via cargo
migchat-cli

# Or run from source
cargo run
```

### First Time Setup

1. The CLI will connect to the default server: `https://server-1ce-la.fly.dev`
2. On first launch, you'll be prompted to create an account
3. Enter your desired username and password
4. Your account and session will be saved automatically

### Account Management

The CLI supports multiple accounts:

- **First Login**: When no accounts exist, you'll be prompted to create one
- **Returning Users**: When accounts exist, you'll see a list of saved accounts to select from
- **Switch Accounts**: Switch between accounts without re-entering credentials
- **Persistent Sessions**: All account tokens are stored securely in `~/.migchat/config.json`

### Main Features

#### 1. Multiple Account Support
- Store multiple accounts on the same server
- Quickly switch between accounts
- Each account maintains its own authentication token

#### 2. Create Account
- Create a new account with a unique username
- Password is securely hashed on the server
- Authentication token is stored locally

#### 3. View Conversations
- See all your active conversations
- Shows last message and timestamp
- Displays unread message count

#### 4. View All Messages
- See complete message history
- Shows sent and received messages
- Color-coded for easy reading (you vs others)

#### 5. Send Message
- Send a message to any username
- Server validates recipient exists
- Instant confirmation

#### 6. Switch Account / Logout
- Switch between your saved accounts
- Logout to return to account selection
- Accounts remain saved for easy re-login

#### 7. Set Server URL
- Connect to a different MigChat server
- Useful for development or self-hosted instances

## Configuration

Configuration is stored in `~/.migchat/config.json`:

```json
{
  "server_url": "https://server-1ce-la.fly.dev",
  "accounts": {
    "alice": {
      "username": "alice",
      "token": "alice_auth_token"
    },
    "bob": {
      "username": "bob",
      "token": "bob_auth_token"
    }
  },
  "current_account": "alice"
}
```

### Changing Server

You can change the server in two ways:

1. **Through the CLI**: Select "Set Server URL" from the auth menu
2. **Edit config manually**: Edit `~/.migchat/config.json` before launching

## UI Preview

```
╔═══════════════════════════════════╗
║                                   ║
║          MigChat CLI              ║
║     Interactive Chat Client       ║
║                                   ║
╚═══════════════════════════════════╝

✓ Connected to server: https://server-1ce-la.fly.dev

Logged in as: your_username

Main Menu:
  View Conversations
> View All Messages
  Send Message
  Logout
  Exit
```

## Development

### Project Structure

```
src/
├── main.rs           # Application entry point
├── api/              # API client implementation
│   ├── mod.rs
│   ├── client.rs     # HTTP client for MigChat API
│   └── models.rs     # Request/response models
├── config.rs         # Configuration management
└── ui/               # Interactive UI
    └── mod.rs        # Menu system and display logic
```

### Dependencies

- **reqwest** - HTTP client for API calls
- **dialoguer** - Interactive CLI prompts and menus
- **colored** - Terminal color output
- **serde/serde_json** - JSON serialization
- **chrono** - Date/time handling
- **anyhow** - Error handling
- **dirs** - Cross-platform config directory

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run with logging
RUST_LOG=debug cargo run
```

### Testing with Local Server

If you're running the server locally:

```bash
# Start the server on port 3000
cd ../server
cargo run

# In another terminal, run the CLI
cd ../cli
cargo run
```

Then set the server URL to `http://localhost:3000` from the CLI menu.

## Features in Detail

### Color Coding

- 🟢 **Green**: Success messages and your username
- 🔵 **Cyan**: Other usernames and headers
- 🟡 **Yellow**: Loading/processing messages
- 🔴 **Red**: Errors and unread counts
- ⚫ **Gray**: Timestamps and metadata

### Message Display

Messages show:
- Timestamp in your local timezone
- Direction (from/to)
- Content
- Visual separation between messages

### Error Handling

- Network errors are caught and displayed
- Invalid credentials show clear messages
- Server unavailability is detected on startup

## Troubleshooting

### "Cannot connect to server"

Check:
1. Server URL is correct in config
2. Server is running and accessible
3. No firewall blocking the connection

### "Failed to create account: Username already exists"

The username is taken. Try a different one.

### Config file errors

Delete the config file and restart:
```bash
rm ~/.migchat/config.json
```

### Build errors

Make sure you have the latest Rust:
```bash
rustup update
```

## Contributing

Pull requests are welcome! For major changes, please open an issue first.

## License

MIT

## Related

- [MigChat Server](https://github.com/migchat/server) - The backend server
