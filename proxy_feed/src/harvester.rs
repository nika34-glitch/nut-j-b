use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use regex::Regex;
use reqwest::Client;
use std::io::Cursor;
use std::io::Read;
use std::{collections::HashSet, process::Stdio};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{error, info};
use zip::read::ZipArchive;
use zstd::stream::read::Decoder as ZstdDecoder;

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
        Ok(resp) => {
            let ct_header = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            match resp.bytes().await {
                Ok(bytes) => {
                    let text = decode_bytes(url, &ct_header, &bytes)?;
                    let count = extract_into_set(&text, set);
                    info!("fetched {} entries from {}", count, url);
                    Ok(())
                }
                Err(e) => {
                    error!("error reading {}: {}", url, e);
                    Err(HarvestError::Http(url.to_string(), e))
                }
            }
        }
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
        if !line.trim().is_empty() && set.insert(line.trim().to_lowercase()) {
            count += 1;
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

fn decode_bytes(url: &str, ct: &str, bytes: &[u8]) -> Result<String, HarvestError> {
    let lower_ct = ct.to_ascii_lowercase();

    if lower_ct.contains("gzip") || url.ends_with(".gz") {
        let mut d = String::new();
        GzDecoder::new(bytes)
            .read_to_string(&mut d)
            .map_err(HarvestError::Io)?;
        return Ok(d);
    }
    if lower_ct.contains("bzip2") || url.ends_with(".bz2") {
        let mut d = String::new();
        BzDecoder::new(bytes)
            .read_to_string(&mut d)
            .map_err(HarvestError::Io)?;
        return Ok(d);
    }
    if lower_ct.contains("zstd") || url.ends_with(".zst") || url.ends_with(".zstd") {
        let mut d = String::new();
        ZstdDecoder::new(bytes)
            .map_err(HarvestError::Io)?
            .read_to_string(&mut d)
            .map_err(HarvestError::Io)?;
        return Ok(d);
    }
    if lower_ct.contains("zip") || url.ends_with(".zip") {
        let cursor = Cursor::new(bytes);
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| HarvestError::Io(std::io::Error::other(e)))?;
        let mut combined = String::new();
        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| HarvestError::Io(std::io::Error::other(e)))?;
            let mut s = String::new();
            file.read_to_string(&mut s).map_err(HarvestError::Io)?;
            combined.push_str(&s);
            combined.push('\n');
        }
        return Ok(combined);
    }

    // default: treat as utf-8 text
    Ok(String::from_utf8_lossy(bytes).into_owned())
}
