use clap::Parser;
use std::process::ExitCode;

mod app;
mod cli;
mod commands;
mod json;
mod sign;
mod util;

fn main() -> ExitCode {
  // Setup tracing subscriber for CLI
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
    )
    .with_writer(std::io::stderr)
    .init();

  let cli = cli::Cli::parse();
  match app::run(cli) {
    Ok(()) => ExitCode::SUCCESS,
    Err(_) => ExitCode::FAILURE,
  }
}
