mod api;
mod config;
mod ui;
mod update;
mod polling;

use anyhow::Result;
use config::Config;
use ui::UI;

fn main() -> Result<()> {
    let config = Config::load()?;
    let mut ui = UI::new(config);
    ui.run()?;
    Ok(())
}
