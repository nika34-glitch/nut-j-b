use base64::{engine::general_purpose, Engine as _};
use bzip2::read::BzDecoder;
use csv::ReaderBuilder;
use flate2::read::GzDecoder;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
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

fn insert_proxy(ip: &str, port: &str, set: &mut HashSet<String>) -> bool {
    let ip_clean = ip.trim_matches(|c| c == '[' || c == ']');
    let proxy = format!("{}:{}", ip_clean, port);
    set.insert(proxy)
}

fn extract_basic(text: &str, set: &mut HashSet<String>) -> usize {
    let re_scheme = Regex::new(
        r"(?xi)(?:\b(socks4|socks5|http|https)://)?\s*(?:\[(?P<ip6>[0-9a-f:]+)\]|(?P<ip4>(?:\d{1,3}\.){3}\d{1,3}))\s*[:\s,]+(?P<port>\d{2,5})",
    )
    .unwrap();
    let mut count = 0;
    for caps in re_scheme.captures_iter(text) {
        let ip = caps
            .name("ip6")
            .or_else(|| caps.name("ip4"))
            .unwrap()
            .as_str();
        let port = caps.name("port").unwrap().as_str();
        if insert_proxy(ip, port, set) {
            count += 1;
        }
    }
    count
}

fn extract_csv(text: &str, delim: u8, set: &mut HashSet<String>) -> usize {
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(delim)
        .from_reader(text.as_bytes());
    let ipv4 = Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap();
    let ipv6 = Regex::new(r"^[0-9a-fA-F:]+$").unwrap();
    let mut count = 0;
    for rec in rdr.records() {
        if let Ok(r) = rec {
            if r.len() >= 2 {
                let ip = r.get(0).unwrap().trim();
                let port = r.get(1).unwrap().trim();
                if (ipv4.is_match(ip) || ipv6.is_match(ip)) && port.chars().all(|c| c.is_digit(10))
                {
                    if insert_proxy(ip, port, set) {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

fn extract_html(text: &str, set: &mut HashSet<String>) -> usize {
    let mut count = 0;
    let html = Html::parse_document(text);
    if let Ok(sel) = Selector::parse("td") {
        for elem in html.select(&sel) {
            let cell = elem.text().collect::<String>();
            count += extract_basic(&cell, set);
        }
    }
    count
}

fn extract_base64(text: &str, set: &mut HashSet<String>) -> usize {
    let b64_re = Regex::new(r"[A-Za-z0-9+/=]{12,}").unwrap();
    let mut count = 0;
    for cap in b64_re.captures_iter(text) {
        if let Ok(decoded) = general_purpose::STANDARD.decode(cap.get(0).unwrap().as_str()) {
            if let Ok(s) = String::from_utf8(decoded) {
                count += extract_basic(&s, set);
            }
        }
    }
    count
}

fn extract_into_set(text: &str, set: &mut HashSet<String>) -> usize {
    let mut total = 0;
    total += extract_basic(text, set);
    if text.contains(',') {
        total += extract_csv(text, b',', set);
    }
    if text.contains('\t') {
        total += extract_csv(text, b'\t', set);
    }
    if text.contains("<table") {
        total += extract_html(text, set);
    }
    total += extract_base64(text, set);
    total
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
