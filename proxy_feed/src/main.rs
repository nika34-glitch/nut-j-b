use clap::{Parser, Subcommand};
use proxy_feed::{harvester, Config};
use rand::rng;
use rand::seq::SliceRandom;
use tracing_subscriber::fmt;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch proxy lists from configured sources
    Fetch {
        /// Path to configuration TOML
        #[arg(long)]
        config: String,
        /// Output file path
        #[arg(long)]
        output: String,
        /// Shuffle output
        #[arg(long, default_value_t = false)]
        shuffle: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Fetch {
            config,
            output,
            shuffle,
        } => {
            let cfg = Config::from_file(&config)?;
            let mut set = harvester::fetch_all(&cfg).await?;
            // merge existing
            if let Ok(contents) = tokio::fs::read_to_string(&output).await {
                for line in contents.lines() {
                    if !line.trim().is_empty() {
                        set.insert(line.trim().to_lowercase());
                    }
                }
            }
            let mut proxies: Vec<_> = set.into_iter().collect();
            if shuffle {
                let mut rng = rng();
                proxies.shuffle(&mut rng);
            } else {
                proxies.sort();
            }
            tokio::fs::write(&output, proxies.join("\n")).await?;
        }
    }

    Ok(())
}
