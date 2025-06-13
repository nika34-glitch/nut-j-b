use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};

const DEFAULT_FEEDS: &[&str] = &[
    // The Big Proxy List
    "https://www.thebigproxylist.com/api/proxylist.txt",
    // TheSpeedX/PROXY-List
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    // TheSpeedX/SOCKS-List for additional SOCKS feeds
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    // JetKai proxy list
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    // Monosans consolidated proxies
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    // ClarkeTM proxy list
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    // UK Proxy specific list
    "https://raw.githubusercontent.com/proxylistuk/ukproxylist/master/uk_proxies.txt",
    // free-proxy-list.net HTML table
    "https://free-proxy-list.net/",
    // CheckerProxy.net chronological lists
    "https://raw.githubusercontent.com/checkerproxy/vps/main/proxy.txt",
    // coderduck.com daily list
    "https://www.coderduck.com/ports/api/proxy?key=free&https=true&format=txt",
    // cool-proxy.net scoreboard
    "https://cool-proxy.net/proxies.json",
    // Elliottophellia ultimate list
    "https://raw.githubusercontent.com/Elliottophellia/proxylist/main/proxies.txt",
    // experte.com continuously tested list
    "https://api.experte.com/proxylist?format=txt",
    // floppydata scraped list
    "https://floppydata.com/proxies.txt",
    // fosy.club free list
    "https://fosy.club/free-proxy-list.txt",
    // free-proxy-list.com service
    "https://free-proxy-list.com/",
    // freeproxylist.cc 3 min refresh
    "https://freeproxylist.cc/feeds/freeproxylist.txt",
    // freeproxylists.com
    "https://www.freeproxylists.com/api/proxylist.txt",
    // freeproxylists.net
    "https://www.freeproxylists.net/?format=txt",
    // freeproxy.world
    "https://raw.githubusercontent.com/roosterkid/freeproxylist/main/proxies.txt",
    // freshnewproxies24 community dumps
    "https://freshnewproxies24.top/latest.txt",
    // proxygather.com gatherproxy
    "http://proxygather.com/api/proxies.txt",
    // geonode free list
    "https://proxylist.geonode.com/api/proxy-list?limit=10000&format=txt",
    // getproxylist free API
    "https://api.getproxylist.com/proxy.txt",
    // gimmeproxy rotating API
    "https://gimmeproxy.com/api/getProxy",
    // gologin free list
    "https://api.gologin.com/proxylist.txt",
    // google passed proxies
    "https://googlepassedproxylist.blogspot.com/feeds/posts/default?alt=txt",
];

struct ProxyState {
    ewma: f32,
    avg_latency: f32,
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
    // Refresh a curated set of public proxy feeds
    let lists = DEFAULT_FEEDS;
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0")
        .build()?;
    let mut candidates = Vec::new();
    let re = regex::Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").unwrap();
    let mut fetches = FuturesUnordered::new();
    for &url in lists {
        let c = client.clone();
        fetches.push(async move {
            if let Ok(resp) = c.get(url).send().await {
                resp.text().await.ok()
            } else {
                None
            }
        });
    }
    while let Some(opt) = fetches.next().await {
        if let Some(txt) = opt {
            for cap in re.captures_iter(&txt) {
                candidates.push(format!("{}:{}", &cap[1], &cap[2]));
            }
        }
    }
    candidates.sort();
    candidates.dedup();

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
            avg_latency: dur.as_secs_f32(),
            quarantine: None,
        });
        ent.ewma = if ok {
            ent.ewma * 0.8 + 0.2
        } else {
            ent.ewma * 0.8
        };
        ent.avg_latency = if ent.avg_latency == 0.0 {
            dur.as_secs_f32()
        } else {
            ent.avg_latency * 0.8 + dur.as_secs_f32() * 0.2
        };
        if ent.ewma < 0.2 {
            ent.quarantine = Some(Instant::now() + Duration::from_secs(1800));
            continue;
        }
        let latency_score = (1.0 - (ent.avg_latency * 1000.0 / 1000.0).min(1.0)).max(0.0);
        let score = ent.ewma * 0.7 + latency_score * 0.3;
        if score > 0.7 {
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
