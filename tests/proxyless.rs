use libero_validator::proxyless::{ProxylessManager};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn manager_detects_backends() {
    let mgr = ProxylessManager::detect(5, Duration::from_secs(60)).await;
    assert!(mgr.len() > 0);
}
