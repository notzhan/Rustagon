//! Small embedded server for Falco-compatible health, version, and metrics endpoints.

use crate::metrics::{MetricsSnapshot, CONTENT_TYPE_PROMETHEUS};
use rustagon_config::WebserverConfig;
use serde_json::Value;
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::{timeout, Duration},
};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

pub type MetricsProvider = Arc<dyn Fn() -> MetricsSnapshot + Send + Sync>;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum WebserverError {
    #[error("invalid webserver listen address `{address}:{port}`: {source}")]
    InvalidAddress {
        address: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("cannot load webserver SSL certificate `{path}`: {reason}")]
    SslCertificate { path: String, reason: String },
    #[error("cannot serialize webserver versions response: {0}")]
    Versions(#[from] serde_json::Error),
}

pub struct Webserver {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for Webserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Webserver")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Webserver {
    pub async fn start(
        config: &WebserverConfig,
        versions: Value,
        metrics: Option<MetricsProvider>,
    ) -> Result<Option<Self>, WebserverError> {
        if !config.enabled {
            return Ok(None);
        }

        let listener = TcpListener::bind((config.listen_address.as_str(), config.listen_port))
            .await
            .map_err(|source| WebserverError::InvalidAddress {
                address: config.listen_address.clone(),
                port: config.listen_port,
                source,
            })?;
        let local_addr =
            listener
                .local_addr()
                .map_err(|source| WebserverError::InvalidAddress {
                    address: config.listen_address.clone(),
                    port: config.listen_port,
                    source,
                })?;
        let tls = config
            .ssl_enabled
            .then(|| tls_acceptor(&config.ssl_certificate))
            .transpose()?;
        let routes = Arc::new(Routes {
            health_path: config.k8s_healthz_endpoint.clone(),
            versions: serde_json::to_vec(&versions)?,
            metrics: config
                .prometheus_metrics_enabled
                .then_some(metrics)
                .flatten(),
        });
        let max_connections = match config.threadiness {
            0 => std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            configured => configured as usize,
        };
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        connections.abort_all();
                        while connections.join_next().await.is_some() {}
                        break;
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept(), if connections.len() < max_connections => {
                        let Ok((stream, _)) = accepted else { break };
                        let routes = Arc::clone(&routes);
                        let tls = tls.clone();
                        connections.spawn(async move {
                            let request = async {
                                if let Some(acceptor) = tls {
                                    if let Ok(stream) = acceptor.accept(stream).await {
                                        let _ = serve_connection(stream, routes).await;
                                    }
                                } else {
                                    let _ = serve_connection(stream, routes).await;
                                }
                            };
                            let _ = timeout(CONNECTION_TIMEOUT, request).await;
                        });
                    }
                }
            }
        });

        Ok(Some(Self {
            local_addr,
            shutdown: Some(shutdown),
            task,
        }))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for Webserver {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

struct Routes {
    health_path: String,
    versions: Vec<u8>,
    metrics: Option<MetricsProvider>,
}

async fn serve_connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    routes: Arc<Routes>,
) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(1024);
    loop {
        if request.len() >= 8192 {
            return write_response(
                &mut stream,
                "431 Request Header Fields Too Large",
                "text/plain",
                b"",
            )
            .await;
        }
        let read = stream.read_buf(&mut request).await?;
        if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let first_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let (status, content_type, body): (&str, &str, Vec<u8>) = if method != "GET" {
        ("405 Method Not Allowed", "text/plain", Vec::new())
    } else if path == routes.health_path {
        (
            "200 OK",
            "application/json",
            br#"{"status": "ok"}"#.to_vec(),
        )
    } else if path == "/versions" {
        ("200 OK", "application/json", routes.versions.clone())
    } else if path == "/metrics" {
        match &routes.metrics {
            Some(provider) => (
                "200 OK",
                CONTENT_TYPE_PROMETHEUS,
                provider().to_prometheus().into_bytes(),
            ),
            None => ("404 Not Found", "text/plain", Vec::new()),
        }
    } else {
        ("404 Not Found", "text/plain", Vec::new())
    };
    write_response(&mut stream, status, content_type, &body).await
}

async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

fn tls_acceptor(path: &str) -> Result<TlsAcceptor, WebserverError> {
    let error = |reason: String| WebserverError::SslCertificate {
        path: path.to_string(),
        reason,
    };
    let file = File::open(path).map_err(|source| error(source.to_string()))?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| error(source.to_string()))?;
    let file = File::open(path).map_err(|source| error(source.to_string()))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|source| error(source.to_string()))?
        .ok_or_else(|| error("combined PEM contains no private key".to_string()))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|source| error(source.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
