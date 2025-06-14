// Proxy sidecar module integrated into main binary
use serde::Deserialize;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use futures::stream::{FuturesUnordered, StreamExt};
use anyhow::Result;
use proxy_feed::{self, harvester, Config as FeedConfig};

const DEFAULT_FEEDS: &[&str] = &[
    "https://www.thebigproxylist.com/api/proxylist.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/proxylistuk/ukproxylist/master/uk_proxies.txt",
    "https://free-proxy-list.net/",
    "https://raw.githubusercontent.com/checkerproxy/vps/main/proxy.txt",
    "https://www.coderduck.com/ports/api/proxy?key=free&https=true&format=txt",
    "https://cool-proxy.net/proxies.json",
    "https://raw.githubusercontent.com/Elliottophellia/proxylist/main/proxies.txt",
    "https://api.experte.com/proxylist?format=txt",
    "https://floppydata.com/proxies.txt",
    "https://fosy.club/free-proxy-list.txt",
    "https://free-proxy-list.com/",
    "https://freeproxylist.cc/feeds/freeproxylist.txt",
    "https://www.freeproxylists.com/api/proxylist.txt",
    "https://www.freeproxylists.net/?format=txt",
    "https://raw.githubusercontent.com/roosterkid/freeproxylist/main/proxies.txt",
    "https://freshnewproxies24.top/latest.txt",
    "http://proxygather.com/api/proxies.txt",
    "https://proxylist.geonode.com/api/proxy-list?limit=10000&format=txt",
    "https://api.getproxylist.com/proxy.txt",
    "https://api.gologin.com/proxylist.txt",
    "https://googlepassedproxylist.blogspot.com/feeds/posts/default?alt=txt",
    "https://hidemy.life/en/proxy-list/",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/https.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks5.txt",
    "https://ipaddress.com/proxy-list/",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/http/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/https/https.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/socks4/socks4.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/master/socks5/socks5.txt",
    "https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1",
    "https://www.proxynova.com/proxy-server-list/",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.socks-proxy.net/",
    "https://socks5-proxy-list.blogspot.com/feeds/posts/default",
    "https://proxydb.net/?protocol=http",
    "https://sockslist.us/api",
    "https://spys.one/en/http-proxy-list/",
    "https://spys.one/en/socks-proxy-list/",
    "https://raw.githubusercontent.com/spoofs/proxy/main/list.txt",
    "https://www.sslproxies.org/",
    "https://free-proxy-list.net/uk-proxy.html",
    "https://www.us-proxy.org/",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxy-list.txt",
    "https://workingproxylisttxt.blogspot.com/feeds/posts/default?alt=txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/proxy_list.txt",
    "https://www.89ip.cn/tqdl.html",
    "http://www.66ip.cn/mo.php?tqsl=1000",
    "https://www.kuaidaili.com/free/inha/",
    "https://raw.githubusercontent.com/a2u/free-proxy-list/main/proxy_list.txt",
    "https://raw.githubusercontent.com/HUYDGD/AutoGetProxy/master/all_proxies.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt",
    "https://raw.githubusercontent.com/ForceFledgling/ProxyHub/master/proxy_list.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    "https://raw.githubusercontent.com/prxchk/Proxy-List/master/proxy-list.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/proxies.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/http.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/https.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks4.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt",
];

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
        if let Ok(resp) = client.get("https://gimmeproxy.com/api/getProxy").send().await {
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
    if let Ok(resp) = client.get("https://mtpro.xyz/api/?type=mtproto").send().await {
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
    if let Some(cfg) = cfg {
        if let Ok(extra) = harvester::fetch_all(cfg).await {
            set.extend(extra);
        }
    }
    if let Ok(out) = Command::new("python").arg("otoproxy/otoproxy.py").output().await {
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
    let re = regex::Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})").unwrap();
    let mut fetches = FuturesUnordered::new();
    for &url in DEFAULT_FEEDS {
        let c = client.clone();
        fetches.push(async move { if let Ok(resp) = c.get(url).send().await { resp.text().await.ok() } else { None } });
    }
    while let Some(opt) = fetches.next().await {
        if let Some(txt) = opt {
            for cap in re.captures_iter(&txt) {
                set.insert(format!("{}:{}", &cap[1], &cap[2]));
            }
        }
    }
    for p in fetch_gimmeproxy(client, 20).await { set.insert(p); }
    for p in fetch_mtproxies(client).await { set.insert(p); }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort();
    v
}

async fn test_proxy(proxy: String) -> (String, bool, Duration) {
    let start = Instant::now();
    let parts: Vec<_> = proxy.trim_start_matches("socks4a://").split(':').collect();
    let mut success = false;
    if parts.len() == 2 {
        let addr = format!("{}:{}", parts[0], parts[1]);
        let stream_res = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await;
        let mut stream = match stream_res { Ok(Ok(s)) => s, _ => return (proxy, false, start.elapsed()), };
        let mut req = Vec::new();
        req.push(0x04); req.push(0x01);
        let port: u16 = 110;
        req.push((port >> 8) as u8); req.push((port & 0xff) as u8);
        req.extend(&[0,0,0,1]); req.push(0);
        req.extend(b"popmail.libero.it"); req.push(0);
        if stream.write_all(&req).await.is_ok() {
            let mut resp = [0u8;8];
            if stream.read_exact(&mut resp).await.is_ok() && resp[1] == 0x5a {
                let mut buf = [0u8;3];
                if stream.read_exact(&mut buf).await.is_ok() { success = &buf == b"+OK"; }
            }
        }
    }
    (proxy, success, start.elapsed())
}

/// Fetch and verify proxies once, returning the good list.
pub async fn run_once(cfg: Option<&FeedConfig>) -> Result<Vec<String>> {
    let client = reqwest::Client::builder().user_agent("Mozilla/5.0").build()?;
    let candidates = gather_candidates(&client, cfg).await;
    let mut futs = FuturesUnordered::new();
    for c in candidates { futs.push(test_proxy(format!("socks4a://{}", c))); }
    let mut good = Vec::new();
    while let Some((proxy, ok, dur)) = futs.next().await {
        if ok && dur < Duration::from_secs(5) {
            good.push(proxy);
        }
    }
    Ok(good)
}

/// Continuously refresh proxies every 2 minutes and write to `proxies.txt`.
pub async fn sidecar_loop(cfg: Option<&FeedConfig>) -> Result<()> {
    loop {
        let list = run_once(cfg).await?;
        if !list.is_empty() {
            let mut file = tokio::fs::File::create("proxies.txt").await?;
            for g in &list {
                file.write_all(g.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
        }
        tokio::time::sleep(Duration::from_secs(120)).await;
    }
}
