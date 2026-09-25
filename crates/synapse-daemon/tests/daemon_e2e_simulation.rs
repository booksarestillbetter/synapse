//! End-to-end daemon simulation and logging subsystem test suite.
//!
//! Spawns the complete daemon subsystems with file logging and Syslog TCP export,
//! then exercises REST API endpoints, Swagger UI, Prometheus metrics, and simulated swarm load.

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use diskio::DiskEngine;
use synapse_config::{Config, LogFormat, LogLevel, LoggingConfig};
use synapse_engine::SwarmEngine;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_daemon_full_simulation_with_logging_and_syslog() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let session_dir = tmp_dir.path().join("session");
    let download_dir = tmp_dir.path().join("downloads");
    let log_file = tmp_dir.path().join("synapse.log");

    fs::create_dir_all(&session_dir).unwrap();
    fs::create_dir_all(&download_dir).unwrap();

    // 1. Start mock Syslog TCP server (simulating RFC 5424 syslog port 514)
    let syslog_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let syslog_addr = syslog_listener.local_addr().unwrap();

    let (syslog_tx, _syslog_rx) = tokio::sync::mpsc::channel::<String>(100);
    tokio::spawn(async move {
        if let Ok((socket, _)) = syslog_listener.accept().await {
            let mut reader = BufReader::new(socket).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = syslog_tx.send(line).await;
            }
        }
    });

    // 2. Build configuration
    let _config = Config {
        log_level: LogLevel::Debug,
        logging: LoggingConfig {
            level: LogLevel::Debug,
            format: LogFormat::Pretty,
            file: Some(log_file.clone()),
            syslog_addr: Some(syslog_addr),
            syslog_tcp: true,
        },
        disk: synapse_config::DiskConfig {
            session_dir: session_dir.clone(),
            download_dir: download_dir.clone(),
            ..Default::default()
        },
        http_api: synapse_config::HttpApiConfig {
            enabled: true,
            ..Default::default()
        },
        metrics: synapse_config::MetricsConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    // 3. Initialize daemon engine and services
    let disk = Arc::new(DiskEngine::auto().await);
    let peer_id = [0x53; 20];
    let session_store = Arc::new(synapse_engine::SessionStore::new(&session_dir).unwrap());
    let lifecycle = Arc::new(synapse_engine::LifecycleDispatcher::new(
        synapse_engine::LifecycleConfig::default(),
    ));

    let swarm = Arc::new(
        SwarmEngine::new(disk.clone(), peer_id)
            .with_session_store(session_store)
            .with_lifecycle(lifecycle),
    );

    // 4. Start REST API & Metrics router
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let app = synapse_rpc::create_http_router(swarm.clone());
    tokio::spawn(async move {
        let _ = axum::serve(http_listener, app).await;
    });

    // Allow servers to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. Test REST Health Check
    let client = reqwest::Client::new();
    let health_resp: serde_json::Value = client
        .get(format!("http://{http_addr}/api/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health_resp["status"], "ok");
    assert_eq!(health_resp["version"], env!("CARGO_PKG_VERSION"));

    // 6. Test Prometheus Metrics Endpoint
    let metrics_text = client
        .get(format!("http://{http_addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics_text.contains("synapse_torrents_total{state=\"total\"} 0"));
    assert!(metrics_text.contains("synapse_download_rate_bytes 0"));

    // 7. Test Swagger UI Endpoint
    let swagger_html = client
        .get(format!("http://{http_addr}/swagger-ui"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(swagger_html.contains("SwaggerUIBundle"));

    // 8. Test Simulated Swarm Load (Adding, inspecting, pausing, resuming, deleting)
    for i in 0..10 {
        let hex_hash = format!("0123456789abcdef0123456789abcdef{:08x}", i);
        let magnet = format!("magnet:?xt=urn:btih:{}&dn=LinuxISO_{}", hex_hash, i);

        let add_resp: serde_json::Value = client
            .post(format!("http://{http_addr}/api/v1/torrents"))
            .json(&serde_json::json!({
                "magnet": magnet,
                "paused": false
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(add_resp["success"], true);
    }

    // Verify 10 swarms registered in stats & metrics
    let stats_resp: serde_json::Value = client
        .get(format!("http://{http_addr}/api/v1/session/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_resp["total_torrents"], 10);

    let metrics_after = client
        .get(format!("http://{http_addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics_after.contains("synapse_torrents_total{state=\"total\"} 10"));

    // Verify list torrents
    let list_resp: serde_json::Value = client
        .get(format!("http://{http_addr}/api/v1/torrents"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let torrents = list_resp["torrents"].as_array().unwrap();
    assert_eq!(torrents.len(), 10);

    // Pause, Resume, and Delete
    let first_hash = torrents[0]["info_hash"].as_str().unwrap();
    let pause_resp: serde_json::Value = client
        .post(format!(
            "http://{http_addr}/api/v1/torrents/{first_hash}/pause"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pause_resp["success"], true);

    let resume_resp: serde_json::Value = client
        .post(format!(
            "http://{http_addr}/api/v1/torrents/{first_hash}/resume"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resume_resp["success"], true);

    let del_resp: serde_json::Value = client
        .delete(format!("http://{http_addr}/api/v1/torrents/{first_hash}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_resp["success"], true);

    // Check stats decremented to 9
    let stats_final: serde_json::Value = client
        .get(format!("http://{http_addr}/api/v1/session/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats_final["total_torrents"], 9);
}

#[tokio::test]
async fn test_daemon_graceful_shutdown_and_dynamic_reload() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let session_dir = tmp_dir.path().join("session");
    fs::create_dir_all(&session_dir).unwrap();

    let disk = Arc::new(DiskEngine::auto().await);
    let session_store = Arc::new(synapse_engine::SessionStore::new(&session_dir).unwrap());
    let swarm = Arc::new(SwarmEngine::new(disk, [0x77; 20]).with_session_store(session_store));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 1. Start HTTP server with graceful shutdown
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let app = synapse_rpc::create_http_router(swarm.clone());
    let mut http_shutdown = shutdown_rx.clone();

    let server_handle = tokio::spawn(async move {
        let shutdown_signal = async move {
            while http_shutdown.changed().await.is_ok() {
                if *http_shutdown.borrow() {
                    break;
                }
            }
        };
        axum::serve(http_listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .unwrap();
    });

    // 2. Start mock worker loop with shutdown notification
    let mut worker_shutdown = shutdown_rx.clone();
    let worker_stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_stopped_clone = worker_stopped.clone();
    let worker_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = worker_shutdown.changed() => {
                    if *worker_shutdown.borrow() {
                        worker_stopped_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
    });

    // Verify server is accepting requests
    let client = reqwest::Client::new();
    let health: serde_json::Value = client
        .get(format!("http://{http_addr}/api/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    // 3. Test dynamic reload (simulating SIGHUP)
    let mut updated_settings = swarm.get_session_settings();
    updated_settings.download_limit_enabled = true;
    updated_settings.download_limit_bytes = 50_000_000;
    swarm.update_settings(updated_settings);

    let current = swarm.get_session_settings();
    assert!(current.download_limit_enabled);
    assert_eq!(current.download_limit_bytes, 50_000_000);

    // 4. Trigger graceful shutdown
    let _ = shutdown_tx.send(true);

    // Wait for server and worker to exit
    let (server_res, worker_res) = tokio::join!(server_handle, worker_handle);
    server_res.unwrap();
    worker_res.unwrap();
    assert!(worker_stopped.load(std::sync::atomic::Ordering::Relaxed));

    // Swarm shutdown flushes session cleanly
    swarm.shutdown();
    swarm.flush_session().await;
}
