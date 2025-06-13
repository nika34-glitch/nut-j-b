use clap::{Parser, ArgAction};
use std::net::SocketAddr;

/// Command line options
#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
pub struct Cli {
    /// Feed files or URLs
    #[arg(long = "feed", action = ArgAction::Append)]
    pub feeds: Vec<String>,

    /// CIDRs to scan
    #[arg(long = "scan-cidr", action = ArgAction::Append)]
    pub cidrs: Vec<String>,

    /// Refresh period seconds
    #[arg(long = "update-every", default_value_t = 1800)]
    pub update_every: u64,

    /// Concurrency level
    #[arg(long = "concurrency", default_value_t = 5000)]
    pub concurrency: usize,

    /// Listen address
    #[arg(long = "listen", default_value = "0.0.0.0:8081")]
    pub listen: SocketAddr,

    /// Database path
    #[arg(long = "db-path", default_value = "proxy.db")]
    pub db_path: String,

    /// Log level
    #[arg(long = "log-level", default_value = "info")]
    pub log_level: String,

    /// Exit after minutes (for CI)
    #[arg(long = "exit-after")]
    pub exit_after: Option<u64>,
}
