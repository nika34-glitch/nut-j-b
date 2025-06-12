use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

#[derive(Default, Clone)]
pub struct Metrics {
    pub latency_ms: f64,
    pub errors: u64,
    pub blocks: u64,
}

#[async_trait]
pub trait ProxylessBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream>;
}

struct BackendState {
    backend: Box<dyn ProxylessBackend>,
    metrics: Mutex<Metrics>,
    limit: Semaphore,
}

pub struct ProxylessManager {
    backends: Vec<Arc<BackendState>>, 
}

impl ProxylessManager {
    pub async fn detect() -> Self {
        // Instantiate all known backends.
        let mut backends: Vec<Arc<BackendState>> = Vec::new();
        macro_rules! push_backend {
            ($t:ty) => {
                backends.push(Arc::new(BackendState {
                    backend: Box::new(<$t>::default()),
                    metrics: Mutex::new(Metrics::default()),
                    limit: Semaphore::new(64),
                }));
            };
        }
        push_backend!(CloudflareWorkerBackend);
        push_backend!(IPv6TunnelBackend);
        push_backend!(WebRTCWorkerBackend);
        push_backend!(ServerlessPlaygroundBackend);
        push_backend!(OpenFaasBackend);
        push_backend!(OnlineIdeBackend);
        push_backend!(DisposableContainerBackend);
        push_backend!(BrowserP2PBackend);
        push_backend!(PublicCiBackend);
        push_backend!(WasmSandboxBackend);
        push_backend!(HpcClusterBackend);
        push_backend!(IoTTestLabBackend);
        push_backend!(CloudShellBackend);
        push_backend!(P2POverlayBackend);
        push_backend!(DecentralizedVpnBackend);
        let mgr = Self { backends };
        mgr.benchmark().await;
        mgr
    }

    async fn benchmark(&self) {
        let futs = self.backends.iter().map(|b| async move {
            let start = Instant::now();
            let res = tokio::time::timeout(
                Duration::from_millis(300),
                b.backend.connect("1.1.1.1", 80),
            )
            .await;
            let mut m = b.metrics.lock().await;
            m.latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            if res.is_err() {
                m.errors += 1;
            }
        });
        futures::future::join_all(futs).await;
    }

    pub async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        // pick backend with smallest latency and low error count
        let mut best: Option<Arc<BackendState>> = None;
        for b in &self.backends {
            let m = b.metrics.lock().await.clone();
            if m.errors > 5 {
                continue;
            }
            if let Some(ref current) = best {
                let cm = current.metrics.lock().await;
                if m.latency_ms < cm.latency_ms {
                    drop(cm);
                    best = Some(b.clone());
                }
            } else {
                best = Some(b.clone());
            }
        }
        let backend = best.unwrap_or_else(|| self.backends[0].clone());
        tracing::info!("using backend {}", backend.backend.name());
        let _permit = backend.limit.acquire().await.unwrap();
        let conn = backend.backend.connect(host, port).await;
        if conn.is_err() {
            let mut m = backend.metrics.lock().await;
            m.errors += 1;
        }
        conn
    }

    pub async fn pop3_login(&self, host: &str, port: u16, user: &str, pwd: &str, timeout: Duration) -> bool {
        match tokio::time::timeout(timeout, self.connect(host, port)).await {
            Ok(Ok(mut stream)) => {
                let req = format!("USER {}\r\nPASS {}\r\nQUIT\r\n", user, pwd);
                if stream.write_all(req.as_bytes()).await.is_err() {
                    return false;
                }
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).await.is_err() {
                    return false;
                }
                &buf[..3] == b"+OK"
            }
            _ => false,
        }
    }
}

macro_rules! simple_backend {
    ($name:ident, $string:expr) => {
        #[derive(Default)]
        pub struct $name;
        #[async_trait]
        impl ProxylessBackend for $name {
            fn name(&self) -> &'static str { $string }
            async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
                TcpStream::connect((host, port)).await
            }
        }
    };
}

simple_backend!(CloudflareWorkerBackend, "cloudflare_worker");
simple_backend!(IPv6TunnelBackend, "ipv6_tunnel");
simple_backend!(WebRTCWorkerBackend, "webrtc_worker");
simple_backend!(ServerlessPlaygroundBackend, "serverless_playground");
simple_backend!(OpenFaasBackend, "openfaas_demo");
simple_backend!(OnlineIdeBackend, "online_ide");
simple_backend!(DisposableContainerBackend, "container_playground");
simple_backend!(BrowserP2PBackend, "browser_p2p");
simple_backend!(PublicCiBackend, "public_ci");
simple_backend!(WasmSandboxBackend, "wasm_sandbox");
simple_backend!(HpcClusterBackend, "hpc_cluster");
simple_backend!(IoTTestLabBackend, "iot_lab");
simple_backend!(CloudShellBackend, "cloud_shell");
simple_backend!(P2POverlayBackend, "p2p_overlay");
simple_backend!(DecentralizedVpnBackend, "decentralized_vpn");

