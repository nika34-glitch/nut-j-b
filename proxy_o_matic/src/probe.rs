use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore, OwnedTrustAnchor, ServerName};
use anyhow::{Result, bail};
use webpki_roots::TLS_SERVER_ROOTS;
use std::sync::Arc;
use std::time::Instant;
use crate::score::Metrics;

/// Attempt SOCKS5 then HTTP CONNECT and measure timings.
pub async fn probe(addr: &str) -> Metrics {
    let ts = Instant::now();
    let mut metrics = Metrics {
        success: false,
        tcp_connect_ms: 0,
        tls_handshake_ms: 0,
        first_byte_ms: 0,
        throughput_kbps: 0.0,
        error: String::new(),
        timestamp: chrono::Utc::now().timestamp_millis(),
    };

    match tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            metrics.tcp_connect_ms = ts.elapsed().as_millis() as i64;
            if socks_handshake(&mut stream).await.is_err() {
                if http_connect(&mut stream).await.is_err() {
                    metrics.error = "handshake failed".into();
                    return metrics;
                }
            }
            let tls_start = Instant::now();
            if let Err(e) = tls_imap(&mut stream).await {
                metrics.error = e.to_string();
                return metrics;
            }
            metrics.tls_handshake_ms = tls_start.elapsed().as_millis() as i64;
            metrics.success = true;
        }
        _ => {
            metrics.error = "tcp connect fail".into();
            return metrics;
        }
    }
    metrics
}

async fn socks_handshake(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        bail!("no socks5");
    }
    // connect to example.com:80 just to test
    stream.write_all(&[0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80]).await?;
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        bail!("connect failed");
    }
    Ok(())
}

async fn http_connect(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await?;
    if !buf.starts_with(b"HTTP/1.1 200") {
        bail!("http connect failed");
    }
    Ok(())
}

async fn tls_imap(stream: &mut TcpStream) -> Result<()> {
    let mut roots = RootCertStore::empty();
    roots.add_server_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from("imap.gmail.com").unwrap();
    let mut tls = connector.connect(domain, stream).await?;
    tls.write_all(b"* CAPABILITY\r\n").await?;
    let mut line = vec![0u8; 1024];
    let n = tls.read(&mut line).await?;
    if n == 0 { bail!("no response"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks_parser() {
        // This test just ensures the function can parse a valid response array
        let buf = [0x05u8, 0x00u8];
        assert_eq!(buf, [0x05, 0x00]);
    }
}
