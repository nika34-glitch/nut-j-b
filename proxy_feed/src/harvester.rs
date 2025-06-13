use regex::Regex;
use reqwest::Client;
use std::{collections::HashSet, process::Stdio};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{error, info};

use crate::Config;

/// Errors that can occur when harvesting proxy feeds.
#[derive(Debug, thiserror::Error)]
pub enum HarvestError {
    #[error("HTTP error fetching {0}: {1}")]
    Http(String, #[source] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("command failed: {0}")]
    Command(String),
    #[error("no sources succeeded")]
    NoSources,
}

/// Fetch proxies from all configured sources, returning a deduplicated set.
pub async fn fetch_all(config: &Config) -> Result<HashSet<String>, HarvestError> {
    let client = Client::new();
    let mut set = HashSet::new();
    let mut success = false;

    if let Some(url) = &config.sources.free_proxy_list {
        if fetch_from_url(&client, url, &mut set).await.is_ok() {
            success = true;
        }
    }
    if let Some(url) = &config.sources.ssl_proxies {
        if fetch_from_url(&client, url, &mut set).await.is_ok() {
            success = true;
        }
    }
    if let Some(list) = &config.sources.proxy_scrape {
        for url in list {
            if fetch_from_url(&client, url, &mut set).await.is_ok() {
                success = true;
            }
        }
    }
    if let Some(list) = &config.sources.github_lists {
        for url in list {
            if fetch_from_url(&client, url, &mut set).await.is_ok() {
                success = true;
            }
        }
    }
    if let Some(cmd) = &config.sources.proxybroker_cmd {
        if fetch_from_command(cmd, &mut set).await.is_ok() {
            success = true;
        }
    }

    if !success {
        return Err(HarvestError::NoSources);
    }

    Ok(set)
}

async fn fetch_from_url(
    client: &Client,
    url: &str,
    set: &mut HashSet<String>,
) -> Result<(), HarvestError> {
    info!("fetching {}", url);
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let count = extract_into_set(&text, set);
                info!("fetched {} entries from {}", count, url);
                Ok(())
            }
            Err(e) => {
                error!("error reading {}: {}", url, e);
                Err(HarvestError::Http(url.to_string(), e))
            }
        },
        Err(e) => {
            error!("http error {}: {}", url, e);
            Err(HarvestError::Http(url.to_string(), e))
        }
    }
}

async fn fetch_from_command(cmd: &str, set: &mut HashSet<String>) -> Result<(), HarvestError> {
    info!("running command: {}", cmd);
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HarvestError::Command(cmd.into()))?;
    let mut reader = BufReader::new(stdout).lines();
    let mut count = 0usize;
    while let Some(line) = reader.next_line().await? {
        if !line.trim().is_empty() {
            if set.insert(line.trim().to_lowercase()) {
                count += 1;
            }
        }
    }
    let status = child.wait().await?;
    if !status.success() {
        error!("command exited with status {}", status);
        return Err(HarvestError::Command(cmd.into()));
    }
    info!("command produced {} entries", count);
    Ok(())
}

fn extract_into_set(text: &str, set: &mut HashSet<String>) -> usize {
    let re = Regex::new(r"(?mi)([A-Za-z0-9.-]+:\d{2,5})").unwrap();
    let mut count = 0;
    for caps in re.captures_iter(text) {
        let proxy = caps.get(1).unwrap().as_str().trim().to_lowercase();
        if set.insert(proxy) {
            count += 1;
        }
    }
    count
}
