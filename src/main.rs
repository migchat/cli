mod api;
mod config;
mod ui;
mod update;
mod polling;
mod crypto;

use anyhow::{anyhow, Result};
use config::Config;
use std::env;
use ui::UI;

struct LaunchOptions {
    server_url: Option<String>,
}

fn parse_launch_options() -> Result<LaunchOptions> {
    let mut args = env::args().skip(1);
    let mut server_url = env::var("MIGCHAT_SERVER_URL").ok();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server-url" => {
                let value = args.next().ok_or_else(|| anyhow!("Missing value for --server-url"))?;
                server_url = Some(value);
            }
            "--help" | "-h" => {
                println!("MigChat CLI");
                println!("Usage: migchat [--server-url <URL>]");
                println!();
                println!("Options:");
                println!("  --server-url <URL>  Override and persist the MigChat server URL");
                println!("  -h, --help          Show this help message");
                std::process::exit(0);
            }
            _ => return Err(anyhow!("Unknown argument: {}", arg)),
        }
    }

    Ok(LaunchOptions { server_url })
}

fn main() -> Result<()> {
    let options = parse_launch_options()?;
    let mut config = Config::load()?;

    if let Some(server_url) = options.server_url {
        config.server_url = server_url;
        config.save()?;
    }

    let mut ui = UI::new(config);
    ui.run()?;
    Ok(())
}
