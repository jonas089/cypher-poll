use clap::Parser;
use client::{run, Cli};
fn main() {
    let cli = Cli::parse();
    run(cli);
}
