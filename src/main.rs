use anyhow::Result;
use clap::Parser;
use local_config::LocalConfig;

mod app;
mod cli;
mod crypto;
mod local_config;
mod text_table;
mod util;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    let local_config = LocalConfig::new()?;
    local_config.write_config_file()?;

    let mut app = app::App::new(local_config);

    match args.command {
        cli::Commands::Identity(identity) => match identity {
            cli::Identity::Ls => {
                app.handle_list_identities()?;
            }
            cli::Identity::Gen { name } => {
                app.handle_generate_identity(name)?;
            }
            cli::Identity::Pubkey { name } => {
                app.handle_derive_public_key(name)?;
            }
        },
    }

    Ok(())
}
