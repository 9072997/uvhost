use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::lookup_host;
use tokio::time;
use tower::service_fn;

const LOG_SIZE: usize = 64;

#[derive(Clone, Debug)]
struct AppState {
    log: Arc<Mutex<StatusLog>>,
}

#[derive(Clone, Debug, Copy)]
struct StatusChange {
    up: bool,
    time: u64, // UNIX timestamp
}

#[derive(Clone, Debug)]
struct StatusLog {
    buf: [Option<StatusChange>; LOG_SIZE],
    head: usize,
    count: usize,
}

impl StatusLog {
    fn new() -> Self {
        Self {
            buf: [None; LOG_SIZE],
            head: 0,
            count: 0,
        }
    }
    fn push(&mut self, entry: StatusChange) {
        self.buf[self.head] = Some(entry);
        self.head = (self.head + 1) % LOG_SIZE;
        if self.count < LOG_SIZE {
            self.count += 1;
        }
    }
    fn iter(&self) -> impl Iterator<Item = &StatusChange> {
        (0..self.count).map(move |i| {
            let idx = (self.head + LOG_SIZE - self.count + i) % LOG_SIZE;
            self.buf[idx].as_ref().unwrap()
        })
    }
}

async fn fetch_ipv6_addr() -> Result<String, Box<dyn std::error::Error>> {
    let connector = HttpConnector::new();
    let client = HyperClient::builder(TokioExecutor::new()).build(connector);
    let req = Request::builder()
        .method(Method::GET)
        .uri("http://v6.ipv6-test.com/api/myip.php")
        .body(Full::new(Bytes::new()))?;
    let resp = client.request(req).await?;
    let bytes = resp.collect().await?.to_bytes();
    Ok(String::from_utf8_lossy(&bytes).trim().to_string())
}

fn expand_ipv6(ip: &str) -> String {
    use std::net::Ipv6Addr;
    let addr: Ipv6Addr = ip.parse().unwrap();
    let segments = addr.segments();
    segments
        .iter()
        .map(|seg| format!("{:04x}", seg))
        .collect::<Vec<_>>()
        .join("-")
}

fn withfallback_domain(ip: &str) -> String {
    format!("{}.withfallback.com", expand_ipv6(ip))
}

async fn trickle_handler(_req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut body = Vec::new();
    for _ in 0..30 {
        body.push(b'x');
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(Response::new(Full::new(Bytes::from(body))))
}

async fn log_handler(state: AppState) -> String {
    let log = state.log.lock().unwrap();
    log.iter()
        .map(|entry| format!("{}: {}", entry.time, if entry.up { "UP" } else { "DOWN" }))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn resolve_ipv4(domain: &str) -> Option<String> {
    // Resolve the domain to an IPv4 address
    let mut addrs = lookup_host((domain, 8080)).await.ok()?;
    addrs.find_map(|addr| {
        if let std::net::SocketAddr::V4(v4) = addr {
            Some(v4.ip().to_string())
        } else {
            None
        }
    })
}

// Helper for a single check
async fn check_once(client: &HyperClient<HttpConnector, Full<Bytes>>, domain: &str) -> bool {
    let ipv4_addr = resolve_ipv4(domain).await;
    if let Some(ip) = ipv4_addr {
        let url = format!("http://{}:8080/trickle", ip);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .header("Host", domain)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(45), client.request(req)).await;
        if let Ok(Ok(mut r)) = resp {
            let mut count = 0;
            while let Some(frame_result) = r.body_mut().frame().await {
                match frame_result {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            count += data.len();
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            return count == 30;
        }
    }
    false
}

async fn monitor_task(domain: String, state: AppState) {
    let connector = HttpConnector::new();
    let client = HyperClient::builder(TokioExecutor::new()).build(connector);
    let mut last_up = None;
    let mut in_flight = FuturesUnordered::new();
    let mut interval = time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    // Prime with 2 requests
    for _ in 0..2 {
        interval.tick().await; // space them 15s apart
        let client = client.clone();
        let domain = domain.clone();
        in_flight.push(tokio::spawn(
            async move { check_once(&client, &domain).await },
        ));
    }

    loop {
        // Wait for the next request to finish
        if let Some(Ok(up)) = in_flight.next().await {
            // Log only if the status changed
            if last_up != Some(up) {
                let mut log = state.log.lock().unwrap();
                log.push(StatusChange {
                    up,
                    time: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                });
                last_up = Some(up);
            }
        }
        // Fire a new request every 15s
        interval.tick().await;
        let client = client.clone();
        let domain = domain.clone();
        in_flight.push(tokio::spawn(
            async move { check_once(&client, &domain).await },
        ));
    }
}

async fn request_adapter(
    req: Request<Incoming>,
    state: AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let req2 = Request::from_parts(parts, Full::new(bytes));
    mux_handler(req2, state).await
}

async fn mux_handler(
    req: Request<Full<Bytes>>,
    state: AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/trickle") => trickle_handler(req).await,
        (&Method::GET, "/log") => {
            let body = log_handler(state).await;
            Ok(Response::new(Full::new(Bytes::from(body))))
        }
        _ => {
            let mut not_found = Response::new(Full::new(Bytes::from_static(b"Not Found")));
            *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ipv6 = fetch_ipv6_addr().await?;
    let domain = withfallback_domain(&ipv6);
    println!("IPv6: {} => {}", ipv6, domain);
    let state = AppState {
        log: Arc::new(Mutex::new(StatusLog::new())),
    };
    let state2 = state.clone();
    tokio::spawn(async move {
        monitor_task(domain, state2).await;
    });
    let state = Arc::new(state);
    let make_svc = || {
        let state = state.clone();
        service_fn(move |req| {
            let state = state.clone();
            request_adapter(req, (*state).clone())
        })
    };
    let addr: SocketAddr = "[::]:8080".parse()?;
    let std_listener = std::net::TcpListener::bind(addr)?;
    std_listener.set_nonblocking(true)?;
    println!("Listening on http://[::]:8080");
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let svc = make_svc();
        let io = TokioIo::new(stream);
        let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
        tokio::spawn(async move {
            if let Err(err) = ServerBuilder::new(TokioExecutor::new())
                .serve_connection(io, hyper_svc)
                .await
            {
                eprintln!("server connection error: {err}");
            }
        });
    }
}
