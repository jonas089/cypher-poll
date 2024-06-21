use client::{run, Cli};
use clap::Parser;
fn main() {
    let cli = Cli::parse();
    run(cli);
}