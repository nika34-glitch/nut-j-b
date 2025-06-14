use crate::{cli::Cli, db::{Database, ProxyStats}};
use hyper::{Body, Request, Response, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;
use anyhow::Result;

#[derive(Clone)]
struct AppState {
    db: Database,
    checkout: Arc<DashMap<String, std::time::Instant>>,
}

pub async fn serve(args: Cli) -> Result<()> {
    let db = Database::open(&args.db_path).await?;
    let state = AppState { db, checkout: Arc::new(DashMap::new()) };
    let addr = args.listen;

    let make_svc = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let state = state.clone();
                async move { handle(req, state).await }
            }))
        }
    });

    let server = hyper::Server::bind(&addr).serve(make_svc);
    info!("Listening on {}", addr);
    if let Some(mins) = args.exit_after {
        tokio::select! {
            _ = server => {},
            _ = tokio::time::sleep(std::time::Duration::from_secs(mins*60)) => {},
        }
    } else {
        server.await?;
    }
    Ok(())
}

async fn handle(req: Request<Body>, state: AppState) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/best") => {
            let top = match state.db.top(1).await {
                Ok(t) => t,
                Err(_) => return Ok(resp(StatusCode::INTERNAL_SERVER_ERROR, "{}")),
            };
            if let Some(p) = top.into_iter().next() {
                state.checkout.insert(format!("{}:{}", p.ip, p.port), std::time::Instant::now());
                Ok(json(&p))
            } else {
                Ok(resp(StatusCode::NOT_FOUND, "{}"))
            }
        }
        (&Method::GET, "/stats") => {
            let rows = match state.db.top(100).await {
                Ok(r) => r,
                Err(_) => return Ok(resp(StatusCode::INTERNAL_SERVER_ERROR, "{}")),
            };
            Ok(json(&rows))
        }
        (&Method::POST, "/feedback") => {
            let whole = hyper::body::to_bytes(req.into_body()).await?;
            if let Ok(fb) = serde_json::from_slice::<Feedback>(&whole) {
                // simplified update
                let row = ProxyStats {
                    ip: fb.ip,
                    port: fb.port as i64,
                    last_success: None,
                    last_failure: None,
                    tries: 1,
                    success_count: if fb.ok {1} else {0},
                    avg_rtt: 0.0,
                    avg_throughput: 0.0,
                    score: 0.0,
                };
                let _ = state.db.upsert(&row).await;
                return Ok(resp(StatusCode::OK, "{}"));
            }
            Ok(resp(StatusCode::BAD_REQUEST, "{}"))
        }
        _ => Ok(resp(StatusCode::NOT_FOUND, "Not Found")),
    }
}

fn json<T: Serialize>(data: &T) -> Response<Body> {
    let body = serde_json::to_string(data).unwrap();
    Response::new(Body::from(body))
}

fn resp(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder().status(status).body(Body::from(body.to_string())).unwrap()
}

#[derive(Deserialize)]
struct Feedback {
    ip: String,
    port: u16,
    ok: bool,
}
