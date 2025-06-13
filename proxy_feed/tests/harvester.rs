use proxy_feed::{harvester::fetch_all, Config};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetch_from_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1.1.1.1:80\n2.2.2.2:8080"))
        .mount(&server)
        .await;

    let cfg_txt = format!("[sources]\nfree_proxy_list = \"{}/list\"\n", server.uri());
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
    tokio::fs::write(tmp.path(), cfg_txt).await.unwrap();

    let cfg = Config::from_file(tmp.path().to_str().unwrap()).unwrap();
    let set = fetch_all(&cfg).await.unwrap();
    assert!(set.contains("1.1.1.1:80"));
    assert!(set.contains("2.2.2.2:8080"));
}
