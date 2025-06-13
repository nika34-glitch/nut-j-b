use anyhow::anyhow;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use prometheus::{
    register_gauge_vec, register_int_counter_vec, register_int_gauge_vec, GaugeVec, IntCounterVec,
    IntGaugeVec,
};
use rand::random;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::OnceCell,
    time::{self, Instant},
};
use tokio_rustls::rustls;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

static DOH: OnceCell<Arc<TokioAsyncResolver>> = OnceCell::const_new();

static MOCK_DNS: Lazy<Mutex<HashMap<String, Vec<IpAddr>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CONNECT_DELAY: Lazy<Mutex<HashMap<SocketAddr, Duration>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn mock_dns(host: &str, addrs: Vec<IpAddr>) {
    MOCK_DNS.lock().insert(host.to_string(), addrs);
}

pub fn clear_mock_dns() {
    MOCK_DNS.lock().clear();
}

pub fn mock_connect_delay(addr: SocketAddr, d: Duration) {
    CONNECT_DELAY.lock().insert(addr, d);
}

pub fn clear_connect_delay() {
    CONNECT_DELAY.lock().clear();
}

async fn lookup_ips(host: &str) -> anyhow::Result<Vec<IpAddr>> {
    if let Some(ips) = MOCK_DNS.lock().get(host).cloned() {
        return Ok(ips);
    }
    let resolver = doh_resolver().await;
    let ips = resolver.lookup_ip(host).await?;
    Ok(ips.iter().collect())
}

async fn connect_socket(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    #[cfg(test)]
    {
        let delay_opt = {
            let guard = CONNECT_DELAY.lock();
            guard.get(&addr).copied()
        };
        if let Some(delay) = delay_opt {
            time::sleep(delay).await;
        }
    }
    Ok(stream)
}

async fn doh_resolver() -> Arc<TokioAsyncResolver> {
    DOH.get_or_init(|| async {
        let cfg = ResolverConfig::cloudflare_https();
        let opts = ResolverOpts::default();
        Arc::new(TokioAsyncResolver::tokio(cfg, opts))
    })
    .await
    .clone()
}

/// Scheme used by a free endpoint
#[derive(Clone, Copy)]
pub enum Scheme {
    Http,
    Https,
    Wss,
    Tcp,
}

struct PoolItem {
    stream: TcpStream,
    last_used: Instant,
}

struct StreamPool {
    conns: Mutex<Vec<PoolItem>>,
    idle: Duration,
}

impl StreamPool {
    fn new(idle: Duration) -> Self {
        Self {
            conns: Mutex::new(Vec::new()),
            idle,
        }
    }
}

impl Drop for StreamPool {
    fn drop(&mut self) {
        self.conns.lock().clear();
    }
}

pub struct PooledStream {
    stream: Option<TcpStream>,
    pool: Arc<StreamPool>,
}

impl std::ops::Deref for PooledStream {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        self.stream.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PooledStream {
    fn deref_mut(&mut self) -> &mut TcpStream {
        self.stream.as_mut().unwrap()
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let mut pool = self.pool.conns.lock();
            let now = Instant::now();
            pool.retain(|p| now.duration_since(p.last_used) <= self.pool.idle);
            pool.push(PoolItem {
                stream,
                last_used: now,
            });
        }
    }
}

/// Exposed egress endpoint
#[derive(Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
    pool: Arc<StreamPool>,
    tls_cache: Arc<rustls::client::ClientSessionMemoryCache>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            scheme: Scheme::Tcp,
            pool: Arc::new(StreamPool::new(Duration::from_secs(30))),
            tls_cache: Arc::new(rustls::client::ClientSessionMemoryCache::new(32)),
        }
    }
}

impl Endpoint {
    /// Open a TCP connection using the endpoint's tunnelling scheme.
    pub async fn tcp_connect(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        match self.scheme {
            Scheme::Tcp => {
                let ips = lookup_ips(host).await?;
                let mut v6: Vec<SocketAddr> = Vec::new();
                let mut v4: Vec<SocketAddr> = Vec::new();
                for ip in ips {
                    let addr = SocketAddr::new(ip, port);
                    if ip.is_ipv6() {
                        v6.push(addr);
                    } else {
                        v4.push(addr);
                    }
                }

                let mut ipv6: Option<(Duration, TcpStream)> = None;
                for a in v6 {
                    let start = Instant::now();
                    if let Ok(s) = connect_socket(a).await {
                        ipv6 = Some((start.elapsed(), s));
                        break;
                    }
                }

                let mut ipv4: Option<(Duration, TcpStream)> = None;
                for a in v4 {
                    let start = Instant::now();
                    if let Ok(s) = connect_socket(a).await {
                        ipv4 = Some((start.elapsed(), s));
                        break;
                    }
                }

                match (ipv6, ipv4) {
                    (Some((d6, s6)), Some((d4, s4))) => {
                        if d6.as_secs_f64() <= d4.as_secs_f64() * 1.2 {
                            drop(s4);
                            Ok(s6)
                        } else {
                            drop(s6);
                            Ok(s4)
                        }
                    }
                    (Some((_d6, s6)), None) => Ok(s6),
                    (None, Some((_d4, s4))) => Ok(s4),
                    _ => Err(anyhow!("connect failed")),
                }
            }
            Scheme::Http | Scheme::Https | Scheme::Wss => {
                let addr = format!("{}:{}", self.host, self.port);
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
                stream.write_all(req.as_bytes()).await?;
                // Read at least the HTTP status line to avoid partial reads
                let mut buf = [0u8; 12];
                stream.read_exact(&mut buf).await?;
                let resp = std::str::from_utf8(&buf).unwrap_or("");
                if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
                    Ok(stream)
                } else {
                    Err(anyhow::anyhow!("CONNECT failed"))
                }
            }
        }
    }

    pub async fn checkout(&self, host: &str, port: u16) -> anyhow::Result<PooledStream> {
        let mut conn = {
            let mut pool = self.pool.conns.lock();
            let now = Instant::now();
            pool.retain(|p| now.duration_since(p.last_used) <= self.pool.idle);
            pool.pop().map(|p| p.stream)
        };
        if conn.is_none() {
            conn = Some(self.tcp_connect(host, port).await?);
        }
        Ok(PooledStream {
            stream: conn,
            pool: self.pool.clone(),
        })
    }
}

/// Health report
#[derive(Clone)]
pub struct Health {
    pub rtt: Duration,
    pub ok: bool,
    pub ban_score: f32,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            rtt: Duration::from_millis(1),
            ok: true,
            ban_score: 0.0,
        }
    }
}

/// Backend controller placeholder
pub struct Controller;

pub const MAX_RPS: u16 = 15;

static LATENCY: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("libero_free_latency_seconds", "latency", &["backend"]).unwrap()
});
static ERRORS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "libero_free_errors_total",
        "errors",
        &["backend", "kind"]
    )
    .unwrap()
});
static BAN_SCORE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("libero_free_ban_score", "ban score", &["backend"]).unwrap()
});
static ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("libero_free_active", "active", &["backend"]).unwrap()
});
static SUCCESS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("libero_free_success", "success rate", &["backend"]).unwrap()
});

#[async_trait]
pub trait FreeBackend: Send + Sync + 'static {
    async fn bootstrap(&self, _ctl: &Controller) -> anyhow::Result<Endpoint>;
    async fn connect(&self, ep: &Endpoint, host: &str, port: u16) -> anyhow::Result<PooledStream>;
    async fn ping(&self) -> Health;
    async fn dispose(&self);
    fn name(&self) -> &'static str;
}

macro_rules! simple_backend {
    ($name:ident) => {
        #[derive(Default)]
        pub struct $name;
        #[async_trait]
        impl FreeBackend for $name {
            async fn bootstrap(&self, _ctl: &Controller) -> anyhow::Result<Endpoint> {
                Ok(Endpoint::default())
            }
            async fn connect(
                &self,
                ep: &Endpoint,
                host: &str,
                port: u16,
            ) -> anyhow::Result<PooledStream> {
                ep.checkout(host, port).await
            }
            async fn ping(&self) -> Health {
                Health::default()
            }
            async fn dispose(&self) {}
            fn name(&self) -> &'static str {
                stringify!($name)
            }
        }
    };
}

simple_backend!(DenoDeploy);
simple_backend!(RunKit);
simple_backend!(FastlyCompute);
simple_backend!(NetlifyEdge);
simple_backend!(StackBlitz);
simple_backend!(CodeSandbox);
simple_backend!(VercelEdge);
simple_backend!(BunPlayground);

simple_backend!(BinderPod);
simple_backend!(KatacodaLab);
simple_backend!(KillercodaLab);
simple_backend!(ColabTunnel);
simple_backend!(CodespaceDevurl);
simple_backend!(DroneCIExec);
simple_backend!(TravisBuild);
simple_backend!(OpenShiftPlayground);
simple_backend!(JSFiddleDebug);
simple_backend!(GlitchRemix);
simple_backend!(TioRun);
simple_backend!(PaizaIo);
simple_backend!(WasmEdgeSandbox);
simple_backend!(FastlyFiddle);
simple_backend!(StackStormWebhook);
simple_backend!(IPFSP2P);
simple_backend!(IPinfoEdge);
simple_backend!(ChiselDemo);
simple_backend!(ZeroTierMoon);
simple_backend!(FlyMachines);
simple_backend!(FermyonSpin);
simple_backend!(OpenShiftDevSandbox);
simple_backend!(WandboxCPP);
simple_backend!(BeeceptorMock);
simple_backend!(TryItOnline);
simple_backend!(OpenRestyPlay);
simple_backend!(TryCF);

struct TokenBucket {
    tokens: f32,
    last: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: 0.0,
            last: Instant::now(),
        }
    }

    fn refill(&mut self, max_rps: u16, now: Instant) {
        let elapsed = now.duration_since(self.last).as_secs_f32();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * max_rps as f32).min(max_rps as f32);
            self.last = now;
        }
    }

    fn take(&mut self, max_rps: u16, now: Instant) -> bool {
        self.take_n(max_rps, now, 1)
    }

    fn take_n(&mut self, max_rps: u16, now: Instant, n: u8) -> bool {
        self.refill(max_rps, now);
        if self.tokens >= n as f32 {
            self.tokens -= n as f32;
            true
        } else {
            false
        }
    }
}

struct BackendState {
    backend: Arc<dyn FreeBackend>,
    endpoint: Endpoint,
    bucket: Mutex<TokenBucket>,
    attempts: Mutex<u32>,
    ban_score: Mutex<f32>,
    latency_ms: Mutex<f32>,
    success_ewma: Mutex<f32>,
    failures: Mutex<u32>,
    quarantined: Mutex<Option<Instant>>, // until
    idx: usize,
}

pub struct FreeManager {
    backends: Vec<Arc<BackendState>>,
    max_rps: u16,
    base_quarantine: Duration,
    latency_weight: f32,
    ban_weight: f32,
    current: AtomicUsize,
    batch_left: AtomicU8,
}

impl FreeManager {
    pub async fn detect(
        max_rps: u16,
        quarantine: Duration,
        latency_weight: f32,
        ban_weight: f32,
        backend: Option<&str>,
    ) -> Self {
        let mut list: Vec<Arc<dyn FreeBackend>> = vec![
            Arc::new(DenoDeploy::default()),
            Arc::new(RunKit::default()),
            Arc::new(FastlyCompute::default()),
            Arc::new(NetlifyEdge::default()),
            Arc::new(StackBlitz::default()),
            Arc::new(CodeSandbox::default()),
            Arc::new(VercelEdge::default()),
            Arc::new(BunPlayground::default()),
            Arc::new(BinderPod::default()),
            Arc::new(KatacodaLab::default()),
            Arc::new(KillercodaLab::default()),
            Arc::new(ColabTunnel::default()),
            Arc::new(CodespaceDevurl::default()),
            Arc::new(DroneCIExec::default()),
            Arc::new(TravisBuild::default()),
            Arc::new(OpenShiftPlayground::default()),
            Arc::new(JSFiddleDebug::default()),
            Arc::new(GlitchRemix::default()),
            Arc::new(TioRun::default()),
            Arc::new(PaizaIo::default()),
            Arc::new(WasmEdgeSandbox::default()),
            Arc::new(FastlyFiddle::default()),
            Arc::new(StackStormWebhook::default()),
            Arc::new(IPFSP2P::default()),
            Arc::new(IPinfoEdge::default()),
            Arc::new(ChiselDemo::default()),
            Arc::new(ZeroTierMoon::default()),
            Arc::new(FlyMachines::default()),
            Arc::new(FermyonSpin::default()),
            Arc::new(OpenShiftDevSandbox::default()),
            Arc::new(WandboxCPP::default()),
            Arc::new(BeeceptorMock::default()),
            Arc::new(TryItOnline::default()),
            Arc::new(OpenRestyPlay::default()),
            Arc::new(TryCF::default()),
        ];
        let backends: Vec<Arc<dyn FreeBackend>> = if let Some(name) = backend {
            list.into_iter().filter(|b| b.name() == name).collect()
        } else {
            list
        };
        let ctl = Controller;
        let mut vec = Vec::new();
        for (idx, b) in backends.into_iter().enumerate() {
            let endpoint = match time::timeout(Duration::from_secs(20), b.bootstrap(&ctl)).await {
                Ok(Ok(ep)) => ep,
                _ => Endpoint::default(),
            };
            vec.push(Arc::new(BackendState {
                backend: b.clone(),
                endpoint,
                bucket: Mutex::new(TokenBucket::new()),
                attempts: Mutex::new(0),
                ban_score: Mutex::new(0.0),
                latency_ms: Mutex::new(0.0),
                success_ewma: Mutex::new(0.0),
                failures: Mutex::new(0),
                quarantined: Mutex::new(None),
                idx,
            }));
        }
        Self {
            backends: vec,
            max_rps,
            base_quarantine: quarantine,
            latency_weight,
            ban_weight,
            current: AtomicUsize::new(0),
            batch_left: AtomicU8::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn attempts(&self) -> Vec<(&'static str, u32)> {
        self.backends
            .iter()
            .map(|b| (b.backend.name(), *b.attempts.lock()))
            .collect()
    }

    /// Refill all backend token buckets.
    pub fn refill_tokens(&self) {
        let now = Instant::now();
        for b in &self.backends {
            b.bucket.lock().refill(self.max_rps, now);
        }
    }

    /// Periodically decay success EWMA for all backends.
    pub fn ewma_decay(&self) {
        for b in &self.backends {
            let mut ewma = b.success_ewma.lock();
            *ewma *= 0.99;
            SUCCESS
                .with_label_values(&[b.backend.name()])
                .set(*ewma as f64);
        }
    }

    async fn select_backend(&self) -> Arc<BackendState> {
        loop {
            let remaining = self.batch_left.load(Ordering::Acquire);
            if remaining > 0 {
                let idx = self.current.load(Ordering::Acquire);
                return self.backends[idx].clone();
            }

            let now = Instant::now();
            let mut best: Option<Arc<BackendState>> = None;
            let mut best_score = f32::MAX;
            for b in &self.backends {
                if let Some(exp) = *b.quarantined.lock() {
                    if exp > now {
                        continue;
                    }
                }
                let mut bucket = b.bucket.lock();
                if !bucket.take(self.max_rps, now) {
                    continue;
                }
                let load = ACTIVE.with_label_values(&[b.backend.name()]).get() as f32
                    / self.max_rps as f32;
                let ban = *b.ban_score.lock() * self.ban_weight;
                let lat = *b.latency_ms.lock() / 500.0 * self.latency_weight;
                let score = load + ban + lat;
                if score < best_score {
                    best_score = score;
                    best = Some(b.clone());
                } else {
                    // return token
                    bucket.tokens += 1.0;
                }
            }
            if let Some(b) = best {
                return b;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn pop3_login(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pwd: &str,
        timeout: Duration,
        _fast_open: bool,
    ) -> bool {
        let b = self.select_backend().await;

        if self.batch_left.load(Ordering::Acquire) == 0 {
            let batch = rand::random::<u8>() % 5 + 4; // 4-8
            let mut now = Instant::now();
            loop {
                {
                    let mut bucket = b.bucket.lock();
                    if bucket.take_n(self.max_rps, now, batch) {
                        break;
                    }
                }
                time::sleep(Duration::from_millis(50)).await;
                now = Instant::now();
            }
            self.batch_left.store(batch, Ordering::Release);
            self.current.store(b.idx, Ordering::Release);
        } else {
            self.batch_left.fetch_sub(1, Ordering::AcqRel);
        }

        *b.attempts.lock() += 1;
        ACTIVE.with_label_values(&[b.backend.name()]).inc();
        let start = Instant::now();
        let res = time::timeout(timeout, async {
            let mut stream = b.backend.connect(&b.endpoint, host, port).await.ok()?;
            let req = format!("USER {}\r\nPASS {}\r\nQUIT\r\n", user, pwd);
            stream.write_all(req.as_bytes()).await.ok()?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.ok()?;
            Some(&buf[..3] == b"+OK")
        })
        .await;
        ACTIVE.with_label_values(&[b.backend.name()]).dec();
        let lat = Instant::now().duration_since(start).as_millis() as f32;
        {
            let mut l = b.latency_ms.lock();
            *l = if *l == 0.0 { lat } else { *l * 0.9 + lat * 0.1 };
            LATENCY
                .with_label_values(&[b.backend.name()])
                .set(*l as f64 / 1000.0);
        }
        match res {
            Ok(Some(true)) => {
                {
                    *b.success_ewma.lock() = 0.9 * *b.success_ewma.lock() + 0.1;
                    SUCCESS
                        .with_label_values(&[b.backend.name()])
                        .set(*b.success_ewma.lock() as f64);
                }
                *b.ban_score.lock() = 0.0;
                *b.failures.lock() = 0;
                *b.quarantined.lock() = None;
                true
            }
            Ok(Some(false)) => false,
            _ => {
                ERRORS.with_label_values(&[b.backend.name(), "net"]).inc();
                {
                    let mut failures = b.failures.lock();
                    *failures += 1;
                    let backoff = self.base_quarantine.mul_f32(2f32.powi(*failures as i32));
                    let ttl = backoff.min(Duration::from_secs(1800));
                    *b.quarantined.lock() = Some(Instant::now() + ttl);
                }
                let mut bs = b.ban_score.lock();
                *bs += 1.0;
                BAN_SCORE
                    .with_label_values(&[b.backend.name()])
                    .set(*bs as f64);
                false
            }
        }
    }
}
