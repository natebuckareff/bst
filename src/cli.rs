use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Local identities
    #[clap(subcommand)]
    Identity(Identity),
}

#[derive(Subcommand, Debug)]
pub enum Identity {
    /// List local identities
    Ls,

    /// Generate new identity
    Gen {
        /// Identity name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Derive public key for identity
    Pubkey { name: String },
}
