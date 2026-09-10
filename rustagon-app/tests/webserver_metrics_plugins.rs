use rustagon_app::{
    load_config::load_config,
    metrics::{MetricsSnapshot, CONTENT_TYPE_PROMETHEUS},
    webserver::Webserver,
};
use rustagon_config::WebserverConfig;
use serde_json::json;
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

fn webserver_config() -> WebserverConfig {
    WebserverConfig {
        enabled: true,
        listen_address: "127.0.0.1".to_string(),
        listen_port: 0,
        k8s_healthz_endpoint: "/ready".to_string(),
        prometheus_metrics_enabled: true,
        ..WebserverConfig::default()
    }
}

#[tokio::test]
async fn webserver_serves_health_versions_and_prometheus_metrics() {
    let metrics = Arc::new(|| MetricsSnapshot {
        falco_version: "0.41.0".to_string(),
        outputs_queue_num_drops: 2,
        reload_timestamp_nanoseconds: 123,
    });
    let server = Webserver::start(
        &webserver_config(),
        json!({"falco":{"version":"0.41.0"}}),
        Some(metrics),
    )
    .await
    .unwrap()
    .expect("enabled webserver should bind");
    let base = format!("http://{}", server.local_addr());

    let health = reqwest::get(format!("{base}/ready")).await.unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(health.headers()["content-type"], "application/json");
    assert_eq!(health.text().await.unwrap(), r#"{"status": "ok"}"#);

    let versions = reqwest::get(format!("{base}/versions")).await.unwrap();
    assert_eq!(versions.status(), 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&versions.text().await.unwrap()).unwrap(),
        json!({"falco":{"version":"0.41.0"}})
    );

    let metrics = reqwest::get(format!("{base}/metrics")).await.unwrap();
    assert_eq!(metrics.status(), 200);
    assert_eq!(metrics.headers()["content-type"], CONTENT_TYPE_PROMETHEUS);
    assert!(metrics
        .text()
        .await
        .unwrap()
        .contains("falcosecurity_falco_outputs_queue_num_drops_total 2"));
}

#[tokio::test]
async fn disabled_webserver_does_not_bind() {
    let config = WebserverConfig::default();
    assert!(Webserver::start(&config, json!({}), None)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn ssl_requires_a_combined_certificate_file() {
    let mut config = webserver_config();
    config.ssl_enabled = true;
    config.ssl_certificate = "/definitely/missing/falco.pem".to_string();
    let error = Webserver::start(&config, json!({}), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("SSL certificate"));
}

#[tokio::test]
async fn stopping_webserver_terminates_incomplete_connections() {
    let mut config = webserver_config();
    config.threadiness = 1;
    let server = Webserver::start(&config, json!({}), None)
        .await
        .unwrap()
        .unwrap();
    let mut client = TcpStream::connect(server.local_addr()).await.unwrap();
    client
        .write_all(b"GET /versions HTTP/1.1\r\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    server.stop().await;

    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("connection should close promptly")
            .unwrap(),
        0
    );
}

#[test]
fn prometheus_snapshot_uses_falco_tip_field_names() {
    let text = MetricsSnapshot {
        falco_version: r#"0.41.0"dev"#.to_string(),
        outputs_queue_num_drops: 7,
        reload_timestamp_nanoseconds: 1_748_338_536_592_811_359,
    }
    .to_prometheus();

    assert!(text.contains(r#"falcosecurity_falco_version_info{version="0.41.0\"dev"} 1"#));
    assert!(text.contains("falcosecurity_falco_outputs_queue_num_drops_total 7"));
    assert!(text.contains("falcosecurity_falco_reload_timestamp_nanoseconds 1748338536592811359"));
}

#[test]
fn config_load_rejects_enabled_plugins_with_explicit_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(
        &path,
        "load_plugins: [json]\nplugins:\n  - name: json\n    library_path: libjson.so\n",
    )
    .unwrap();

    let error = load_config(&path, &[]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Falco plugins are enabled (json), but pure-Rust plugin support is not implemented"
    );
}

#[test]
fn config_load_rejects_boolean_plugin_enablement_with_explicit_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(
        &path,
        "load_plugins: true\nplugins:\n  - name: json\n    library_path: libjson.so\n",
    )
    .unwrap();

    let error = load_config(&path, &[]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Falco plugins are enabled (json), but pure-Rust plugin support is not implemented"
    );
}

#[test]
fn config_load_rejects_plugins_when_load_plugins_is_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(
        &path,
        "plugins:\n  - name: json\n    library_path: libjson.so\n",
    )
    .unwrap();

    let error = load_config(&path, &[]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Falco plugins are enabled (json), but pure-Rust plugin support is not implemented"
    );
}

#[test]
fn config_load_allows_declared_but_disabled_plugins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(
        &path,
        "load_plugins: []\nplugins:\n  - name: json\n    library_path: libjson.so\n",
    )
    .unwrap();

    assert!(load_config(&path, &[]).is_ok());
}
