//! Proxy discovery and benchmarking tool.

mod cli;
mod db;
mod probe;
mod score;
mod api;
mod feed;
mod scan;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};
use anyhow::Result;

/// Run the proxy_o_matic application.
pub fn run() -> Result<()> {
    let args = cli::Cli::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    fmt().with_env_filter(filter).init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move { crate::api::serve(args).await })
}
