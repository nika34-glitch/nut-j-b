use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use std::net::SocketAddr;

const PORTS: &[u16] = &[1080, 1081, 3128, 8080];

/// Scan a CIDR and return discovered addresses as ip:port strings.
pub async fn scan_cidr(cidr: &str) -> Vec<String> {
    let mut tasks = FuturesUnordered::new();
    if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
        for ip in net.hosts() {
            for &port in PORTS {
                let addr = SocketAddr::new(ip, port);
                tasks.push(tokio::spawn(async move {
                    if TcpStream::connect(addr).await.is_ok() {
                        Some(format!("{}:{}", addr.ip(), addr.port()))
                    } else {
                        None
                    }
                }));
            }
        }
    }
    let mut out = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some(s)) = res { out.push(s); }
    }
    out
}
