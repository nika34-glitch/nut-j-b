use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use anyhow::Result;

struct ProxyState {
    ewma: f32,
    quarantine: Option<Instant>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut state: HashMap<String, ProxyState> = HashMap::new();
    loop {
        if let Err(e) = run_cycle(&mut state).await {
            eprintln!("cycle error: {e}");
        }
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

async fn run_cycle(state: &mut HashMap<String, ProxyState>) -> Result<()> {
    let lists = vec![
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    ];
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0")
        .build()?;
    let mut candidates = Vec::new();
    for url in lists {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(txt) = resp.text().await {
                candidates.extend(txt.lines().map(|l| l.trim().to_string()));
            }
        }
    }
    candidates.sort();
    candidates.dedup();

    use futures::stream::{FuturesUnordered, StreamExt};
    let mut futs = FuturesUnordered::new();
    for c in candidates {
        let uri = format!("socks4a://{}", c);
        if let Some(ps) = state.get(&uri) {
            if let Some(exp) = ps.quarantine {
                if exp > Instant::now() {
                    continue;
                }
            }
        }
        futs.push(test_proxy(uri));
    }

    let mut good = Vec::new();
    while let Some((proxy, ok, dur)) = futs.next().await {
        let ent = state.entry(proxy.clone()).or_insert(ProxyState {
            ewma: 1.0,
            quarantine: None,
        });
        ent.ewma = if ok { ent.ewma * 0.9 + 0.1 } else { ent.ewma * 0.9 };
        if ent.ewma < 0.2 {
            ent.quarantine = Some(Instant::now() + Duration::from_secs(1800));
            continue;
        }
        if ok && dur < Duration::from_millis(400) {
            good.push(proxy);
        }
    }

    if !good.is_empty() {
        let mut file = tokio::fs::File::create("proxies.txt").await?;
        for g in good {
            file.write_all(g.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
    }
    Ok(())
}

async fn test_proxy(proxy: String) -> (String, bool, Duration) {
    let start = Instant::now();
    let parts: Vec<_> = proxy.trim_start_matches("socks4a://").split(':').collect();
    let mut success = false;
    if parts.len() == 2 {
        let addr = format!("{}:{}", parts[0], parts[1]);
        if let Ok(mut stream) = TcpStream::connect(&addr).await {
            // SOCKS4a handshake
            let mut req = Vec::new();
            req.push(0x04); // version
            req.push(0x01); // CONNECT
            let port: u16 = 110;
            req.push((port >> 8) as u8);
            req.push((port & 0xff) as u8);
            req.extend(&[0, 0, 0, 1]);
            req.push(0); // empty user id
            req.extend(b"popmail.libero.it");
            req.push(0);
            if stream.write_all(&req).await.is_ok() {
                let mut resp = [0u8; 8];
                if stream.read_exact(&mut resp).await.is_ok() && resp[1] == 0x5a {
                    let mut buf = [0u8; 3];
                    if stream.read_exact(&mut buf).await.is_ok() {
                        success = &buf == b"+OK";
                    }
                }
            }
        }
    }
    (proxy, success, start.elapsed())
}
