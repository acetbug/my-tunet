use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "my-tunet")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Set {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
    },
    Show,
}
