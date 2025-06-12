use std::time::{Duration, Instant};
use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use prometheus::{IntCounterVec, IntGaugeVec, GaugeVec, register_int_counter_vec, register_int_gauge_vec, register_gauge_vec};
use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use tokio::time;
use std::sync::Arc;

/// Scheme used by a proxyless endpoint
#[derive(Clone, Copy)]
pub enum Scheme {
    Http,
    Https,
    Tcp,
}

/// Exposed egress endpoint
#[derive(Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self { host: "127.0.0.1".into(), port: 0, scheme: Scheme::Tcp }
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
        Self { rtt: Duration::from_millis(1), ok: true, ban_score: 0.0 }
    }
}

/// Backend controller placeholder
pub struct Controller;

pub const MAX_RPS: u16 = 15;

static LATENCY: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("libero_proxyless_latency_seconds", "latency", &["backend"]).unwrap()
});
static ERRORS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!("libero_proxyless_errors_total", "errors", &["backend", "kind"]).unwrap()
});
static BAN_SCORE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("libero_proxyless_ban_score", "ban score", &["backend"]).unwrap()
});
static ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("libero_proxyless_active", "active", &["backend"]).unwrap()
});

#[async_trait]
pub trait ProxylessBackend: Send + Sync + 'static {
    async fn bootstrap(&self, _ctl: &Controller) -> anyhow::Result<Endpoint>;
    async fn ping(&self) -> Health;
    async fn dispose(&self);
    fn name(&self) -> &'static str;
}

macro_rules! simple_backend {
    ($name:ident) => {
        #[derive(Default)]
        pub struct $name;
        #[async_trait]
        impl ProxylessBackend for $name {
            async fn bootstrap(&self, _ctl: &Controller) -> anyhow::Result<Endpoint> {
                Ok(Endpoint::default())
            }
            async fn ping(&self) -> Health { Health::default() }
            async fn dispose(&self) {}
            fn name(&self) -> &'static str { stringify!($name) }
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

struct BackendState {
    backend: Arc<dyn ProxylessBackend>,
    endpoint: Endpoint,
    health: Health,
    rate_used: f32,
    quarantined: Option<Instant>,
}

pub struct ProxylessManager {
    backends: DashMap<&'static str, BackendState>,
    quarantine: Duration,
    max_rps: u16,
}

impl ProxylessManager {
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub async fn detect(max_rps: u16, quarantine: Duration) -> Self {
        let backends: Vec<Arc<dyn ProxylessBackend>> = vec![
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
        let map = DashMap::new();
        let ctl = Controller;
        for b in backends {
            let endpoint = match time::timeout(Duration::from_secs(20), b.bootstrap(&ctl)).await {
                Ok(Ok(ep)) => ep,
                _ => Endpoint::default(),
            };
            map.insert(b.name(), BackendState { backend: b.clone(), endpoint, health: Health::default(), rate_used: 0.0, quarantined: None });
        }
        Self { backends: map, quarantine, max_rps }
    }

    pub async fn pop3_login(&self, host: &str, port: u16, user: &str, pwd: &str, timeout: Duration) -> bool {
        let mut selected = None;
        for b in self.backends.iter() {
            if let Some(q) = b.quarantined {
                if q > Instant::now() { continue; }
            }
            selected = Some(b);
            break;
        }
        let b = match selected {
            Some(b) => b,
            None => return false,
        };
        ACTIVE.with_label_values(&[b.backend.name()]).inc();
        let res = time::timeout(timeout, async {
            let mut stream = TcpStream::connect((host, port)).await.ok()?;
            let req = format!("USER {}\r\nPASS {}\r\nQUIT\r\n", user, pwd);
            stream.write_all(req.as_bytes()).await.ok()?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.ok()?;
            Some(&buf[..3] == b"+OK")
        }).await;
        ACTIVE.with_label_values(&[b.backend.name()]).dec();
        match res {
            Ok(Some(true)) => true,
            Ok(Some(false)) => false,
            _ => {
                ERRORS.with_label_values(&[b.backend.name(), "net"]).inc();
                false
            }
        }
    }
}

