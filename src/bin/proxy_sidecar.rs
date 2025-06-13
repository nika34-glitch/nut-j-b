use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

use anyhow::Result;
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use proxy_feed::{self, harvester, Config as FeedConfig};

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
    // gologin free list
    "https://api.gologin.com/proxylist.txt",
    // google passed proxies
    "https://googlepassedproxylist.blogspot.com/feeds/posts/default?alt=txt",
    // hidemy.life HTML table
    "https://hidemy.life/en/proxy-list/",
    // hideip.me GitHub feeds
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/https.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks5.txt",
    // IPAddress.com proxy index
    "https://ipaddress.com/proxy-list/",
    // KangProxy auto list
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/http/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/https/https.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/socks4/socks4.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/socks5/socks5.txt",
    // ProxyListPlus fresh list
    "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1",
    // ProxyNova live proxies
    "https://www.proxynova.com/proxy-server-list/",
    // ProxyScrape API
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    // Proxy-List.download service
    "https://www.proxy-list.download/api/v1/get?type=http",
    // socks-proxy.net table
    "https://www.socks-proxy.net/",
    // socks5-proxy-list blog feed
    "https://socks5-proxy-list.blogspot.com/feeds/posts/default",
    // ProxyDB HTTP list
    "https://proxydb.net/?protocol=http",
    // SocksList.us API feeds
    "https://sockslist.us/api",
    // Spys.one HTTP/HTTPS list
    "https://spys.one/en/http-proxy-list/",
    // Spys.one SOCKS list
    "https://spys.one/en/socks-proxy-list/",
    // Spoofs.de RSS feed
    "https://raw.githubusercontent.com/spoofs/proxy/main/list.txt",
    // SSLProxies.org HTTPS list
    "https://www.sslproxies.org/",
    // UK-only proxies
    "https://free-proxy-list.net/uk-proxy.html",
    // US-only proxies
    "https://www.us-proxy.org/",
    // vakhov fresh proxy list
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxy-list.txt",
    // WorkingProxyListTXT daily feed
    "https://workingproxylisttxt.blogspot.com/feeds/posts/default?alt=txt",
    // Zaeem20 free proxy list
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/proxy_list.txt",
    // 89ip.cn hourly free list
    "https://www.89ip.cn/tqdl.html",
    // 66ip.cn daily proxies
    "http://www.66ip.cn/mo.php?tqsl=1000",
    // KuaiDaiLi fast proxies
    "https://www.kuaidaili.com/free/inha/",
    // a2u hourly list
    "https://raw.githubusercontent.com/a2u/free-proxy-list/main/proxy_list.txt",
    // HUYDGD AutoGetProxy
    "https://raw.githubusercontent.com/HUYDGD/AutoGetProxy/master/all_proxies.txt",
    // mmpx12 consolidated list
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt",
    // ForceFledgling ProxyHub
    "https://raw.githubusercontent.com/ForceFledgling/ProxyHub/master/proxy_list.txt",
    // ShiftyTR proxy archives
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    // prxchk elite proxy list
    "https://raw.githubusercontent.com/prxchk/Proxy-List/master/proxy-list.txt",
    // MuRongPIG Proxy-Master
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/proxies.txt",
    // proxifly free proxy list
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies.txt",
    // gitrecon1455 fresh proxies
    "https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/main/proxies.txt",
    // VMHeaven continuously updated lists
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/http.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/https.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks4.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt",
];

struct ProxyState {
    ewma: f32,
    avg_latency: f32,
    quarantine: Option<Instant>,
}

struct ProxyMetrics {
    latency_ms: f32,
    success_rate: f32,
    throughput_kbps: f32,
    error_rate: f32,
    anonymity_level: f32,
    uptime_pct: f32,
    proxy_type: f32,
    location_score: f32,
}

fn score_metrics(m: &ProxyMetrics) -> f32 {
    let latency_norm = 1.0 - (m.latency_ms / 2000.0).min(1.0);
    let throughput_norm = (m.throughput_kbps / 10_000.0).min(1.0);
    100.0
        * (0.20 * latency_norm
            + 0.20 * m.success_rate
            + 0.15 * throughput_norm
            + 0.15 * (1.0 - m.error_rate)
            + 0.10 * (m.anonymity_level / 2.0)
            + 0.10 * m.uptime_pct
            + 0.05 * (m.proxy_type / 2.0)
            + 0.05 * m.location_score)
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Proxy sidecar proxy fetcher")]
struct Cli {
    /// Optional TOML configuration compatible with `proxy_feed`
    #[arg(long = "feed-config")]
    feed_config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = match cli.feed_config.as_deref() {
        Some(path) => match FeedConfig::from_file(path) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("failed to load feed config {}: {}", path, e);
                None
            }
        },
        None => None,
    };

    let mut state: HashMap<String, ProxyState> = HashMap::new();
    loop {
        if let Err(e) = run_cycle(&mut state, cfg.as_ref()).await {
            eprintln!("cycle error: {e}");
        }
        // Refresh every 2 minutes
        tokio::time::sleep(Duration::from_secs(120)).await;
    }
}

async fn run_cycle(
    state: &mut HashMap<String, ProxyState>,
    cfg: Option<&FeedConfig>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0")
        .build()?;

    let candidates = gather_candidates(&client, cfg).await;

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
        let metrics = ProxyMetrics {
            latency_ms: ent.avg_latency * 1000.0,
            success_rate: ent.ewma,
            throughput_kbps: 0.0,
            error_rate: 1.0 - ent.ewma,
            anonymity_level: 1.0,
            uptime_pct: 1.0,
            proxy_type: 1.0,
            location_score: 0.5,
        };
        let score = score_metrics(&metrics) / 100.0;
        if score >= 0.75 {
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
        let stream_res =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await;
        let mut stream = match stream_res {
            Ok(Ok(s)) => s,
            _ => return (proxy, false, start.elapsed()),
        };
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
    (proxy, success, start.elapsed())
}

#[derive(Deserialize)]
struct SocksProxy {
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
struct MtProtoProxy {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct GimmeProxyResp {
    ip: String,
    port: u16,
}

async fn fetch_gimmeproxy(client: &reqwest::Client, count: usize) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..count {
        if let Ok(resp) = client
            .get("https://gimmeproxy.com/api/getProxy")
            .send()
            .await
        {
            if let Ok(body) = resp.text().await {
                if let Ok(item) = serde_json::from_str::<GimmeProxyResp>(&body) {
                    out.push(format!("{}:{}", item.ip, item.port));
                }
            }
        }
    }
    out
}

async fn fetch_mtproxies(client: &reqwest::Client) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(resp) = client.get("https://mtpro.xyz/api/?type=socks").send().await {
        if let Ok(body) = resp.text().await {
            if let Ok(list) = serde_json::from_str::<Vec<SocksProxy>>(&body) {
                for p in list {
                    out.push(format!("{}:{}", p.ip, p.port));
                }
            }
        }
    }
    if let Ok(resp) = client
        .get("https://mtpro.xyz/api/?type=mtproto")
        .send()
        .await
    {
        if let Ok(body) = resp.text().await {
            if let Ok(list) = serde_json::from_str::<Vec<MtProtoProxy>>(&body) {
                for p in list {
                    out.push(format!("{}:{}", p.host, p.port));
                }
            }
        }
    }
    out
}

async fn gather_candidates(client: &reqwest::Client, cfg: Option<&FeedConfig>) -> Vec<String> {
    let mut set = HashSet::new();

    // Additional feeds from proxy_feed configuration
    if let Some(cfg) = cfg {
        if let Ok(extra) = harvester::fetch_all(cfg).await {
            set.extend(extra);
        }
    }

    // run otoproxy helper
    if let Ok(out) = Command::new("python")
        .arg("otoproxy/otoproxy.py")
        .output()
        .await
    {
        if out.status.success() {
            if let Ok(text) = tokio::fs::read_to_string("feeds/all-proxies.txt").await {
                for line in text.lines() {
                    let l = line.trim();
                    if !l.is_empty() {
                        set.insert(l.to_string());
                    }
                }
            }
        }
    }

    // built-in feed list
    let re = regex::Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").unwrap();
    let mut fetches = FuturesUnordered::new();
    for &url in DEFAULT_FEEDS {
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
                set.insert(format!("{}:{}", &cap[1], &cap[2]));
            }
        }
    }

    // gimmeproxy.com API
    for p in fetch_gimmeproxy(client, 20).await {
        set.insert(p);
    }

    // mtpro.xyz API
    for p in fetch_mtproxies(client).await {
        set.insert(p);
    }

    let mut v: Vec<_> = set.into_iter().collect();
    v.sort();
    v
}
