#![cfg(feature = "proxyless")]

use libero_validator::proxyless::ProxylessManager;
use libero_validator::proxyless::{
    clear_connect_delay, clear_mock_dns, mock_connect_delay, mock_dns, Endpoint, Scheme,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn manager_detects_backends() {
    let mgr = ProxylessManager::detect(5, Duration::from_secs(60), 1.0, 1.5).await;
    assert!(mgr.len() > 0);
}

async fn dual_listener() -> (tokio::net::TcpListener, tokio::net::TcpListener, u16) {
    use socket2::{Domain, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr};

    let sock_v6 = Socket::new(Domain::IPV6, Type::STREAM, None).unwrap();
    sock_v6.set_only_v6(true).unwrap();
    sock_v6
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).into())
        .unwrap();
    sock_v6.listen(1).unwrap();
    let port = sock_v6.local_addr().unwrap().as_socket().unwrap().port();
    let listener_v6 = tokio::net::TcpListener::from_std(sock_v6.into()).unwrap();

    let listener_v4 =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            .await
            .unwrap();

    (listener_v6, listener_v4, port)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_prefers_ipv6_when_fast() {
    clear_mock_dns();
    clear_connect_delay();
    let (listener_v6, listener_v4, port) = dual_listener().await;
    tokio::spawn(async move {
        let _ = listener_v6.accept().await;
    });
    tokio::spawn(async move {
        let _ = listener_v4.accept().await;
    });

    mock_dns(
        "mock.test",
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ],
    );
    mock_connect_delay(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        Duration::from_millis(10),
    );
    mock_connect_delay(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Duration::from_millis(30),
    );

    let mut ep = Endpoint::default();
    ep.scheme = Scheme::Tcp;
    let stream = ep.tcp_connect("mock.test", port).await.unwrap();
    assert!(stream.peer_addr().unwrap().is_ipv6());
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_prefers_ipv4_when_ipv6_slow() {
    clear_mock_dns();
    clear_connect_delay();
    let (listener_v6, listener_v4, port) = dual_listener().await;
    tokio::spawn(async move {
        let _ = listener_v6.accept().await;
    });
    tokio::spawn(async move {
        let _ = listener_v4.accept().await;
    });

    mock_dns(
        "mock.test",
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ],
    );
    mock_connect_delay(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        Duration::from_millis(50),
    );
    mock_connect_delay(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Duration::from_millis(10),
    );

    let mut ep = Endpoint::default();
    ep.scheme = Scheme::Tcp;
    let stream = ep.tcp_connect("mock.test", port).await.unwrap();
    assert!(stream.peer_addr().unwrap().is_ipv4());
}
