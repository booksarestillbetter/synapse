use std::fs;
use synapse_engine::{LifecycleConfig, LifecycleDispatcher};
use synapse_meta::File;
use tempfile::tempdir;

#[tokio::test]
async fn test_lifecycle_hardlink_and_offline_wal() {
    let tmp = tempdir().unwrap();
    let download_dir = tmp.path().join("downloads");
    let staging_dir = tmp.path().join("staging");
    let wal_path = tmp.path().join("wal/completed_wal.jsonl");

    fs::create_dir_all(&download_dir).unwrap();

    let file_name = "test_movie.mkv";
    let file_path = download_dir.join(file_name);
    fs::write(&file_path, b"dummy video bytes").unwrap();

    let config = LifecycleConfig {
        staging_dir: Some(staging_dir.clone()),
        auto_hardlink: true,
        wal_path: Some(wal_path.clone()),
        post_script: None,
        copy_script: None,
        script_timeout: None,
        instructions: None,
    };

    let dispatcher = LifecycleDispatcher::new(config);
    let info_hash = [0x55; 20];
    let files = vec![File {
        path: file_name.into(),
        length: 17,
        is_padding: false,
    }];

    // 1. Trigger completion
    let event = dispatcher
        .on_torrent_completed(info_hash, file_name, 17, &download_dir, &files, &[])
        .await
        .unwrap();

    assert_eq!(event.name, file_name);
    assert_eq!(event.info_hash_hex, hex::encode(info_hash));

    // Verify hardlink exists in staging
    let staged_file = staging_dir.join(file_name);
    assert!(staged_file.exists());
    assert_eq!(fs::read(&staged_file).unwrap(), b"dummy video bytes");

    // 2. Drain offline WAL
    let wal_events = dispatcher.drain_wal().unwrap();
    assert_eq!(wal_events.len(), 1);
    assert_eq!(wal_events[0].info_hash_hex, hex::encode(info_hash));

    // Verify WAL is cleared after drain
    let drained_again = dispatcher.drain_wal().unwrap();
    assert!(drained_again.is_empty());
}

#[tokio::test]
async fn test_lifecycle_with_custom_plugin_and_post_script() {
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use synapse_engine::{LifecycleError, LifecyclePlugin, TorrentCompletedEvent};

    let tmp = tempdir().unwrap();
    let download_dir = tmp.path().join("downloads");
    let script_path = tmp.path().join("post_process.sh");
    let out_marker = tmp.path().join("processed.txt");

    fs::create_dir_all(&download_dir).unwrap();

    // Create simple shell script
    let script_content = format!(
        "#!/bin/sh\necho \"Processed $1 $SYNAPSE_TORRENT_NAME\" > {}\n",
        out_marker.display()
    );
    fs::write(&script_path, script_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
    }

    struct TestPlugin {
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl LifecyclePlugin for TestPlugin {
        fn name(&self) -> &str {
            "test_plugin"
        }
        async fn on_torrent_completed(
            &self,
            _event: &TorrentCompletedEvent,
        ) -> Result<(), LifecycleError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let plugin_called = Arc::new(AtomicBool::new(false));
    let custom_plugin = Arc::new(TestPlugin {
        called: plugin_called.clone(),
    });

    let config = LifecycleConfig {
        staging_dir: None,
        auto_hardlink: false,
        wal_path: None,
        post_script: Some(script_path),
        copy_script: None,
        script_timeout: None,
        instructions: None,
    };

    let dispatcher = LifecycleDispatcher::new(config).with_plugin(custom_plugin);
    let info_hash = [0xAA; 20];
    let file_name = "sample.dat";
    let files = vec![File {
        path: file_name.into(),
        length: 100,
        is_padding: false,
    }];

    dispatcher
        .on_torrent_completed(info_hash, file_name, 100, &download_dir, &files, &[])
        .await
        .unwrap();

    // Verify custom plugin was invoked
    assert!(plugin_called.load(Ordering::SeqCst));

    // Verify post script was executed
    assert!(out_marker.exists());
    let marker_text = fs::read_to_string(&out_marker).unwrap();
    assert!(marker_text.contains(&hex::encode(info_hash)));
    assert!(marker_text.contains(file_name));
}

/// The post-script hook is meant to be fully self-sufficient (no callback into synapse or any
/// other service needed) — every field of the completion event must actually reach the script,
/// both as individual env vars for the common ones and as full JSON for everything else.
#[tokio::test]
async fn post_script_receives_every_field_of_the_completion_event() {
    let tmp = tempdir().unwrap();
    let download_dir = tmp.path().join("downloads");
    let script_path = tmp.path().join("dump_env.sh");
    // One file per variable rather than one combined dump — several of these values (the file
    // list, the trackers) legitimately contain embedded newlines, which would make a
    // line-oriented `KEY=value` dump file ambiguous to parse back.
    let out_dir = tmp.path().join("env_dump");

    fs::create_dir_all(&download_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let d = out_dir.display();
    let script_content = format!(
        "#!/bin/sh\n\
         printf '%s' \"$SYNAPSE_INFO_HASH\" > {d}/HASH\n\
         printf '%s' \"$SYNAPSE_TORRENT_NAME\" > {d}/NAME\n\
         printf '%s' \"$SYNAPSE_DOWNLOAD_DIR\" > {d}/DOWNLOAD_DIR\n\
         printf '%s' \"$SYNAPSE_SOURCE_PATH\" > {d}/SOURCE_PATH\n\
         printf '%s' \"$SYNAPSE_TOTAL_BYTES\" > {d}/TOTAL_BYTES\n\
         printf '%s' \"$SYNAPSE_FILE_COUNT\" > {d}/FILE_COUNT\n\
         printf '%s' \"$SYNAPSE_FILES\" > {d}/FILES\n\
         printf '%s' \"$SYNAPSE_TRACKERS\" > {d}/TRACKERS\n\
         printf '%s' \"$SYNAPSE_EVENT_JSON\" > {d}/EVENT_JSON\n"
    );
    fs::write(&script_path, script_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
    }

    let config = LifecycleConfig {
        staging_dir: None,
        auto_hardlink: false,
        wal_path: None,
        post_script: Some(script_path),
        copy_script: None,
        script_timeout: None,
        instructions: None,
    };

    let dispatcher = LifecycleDispatcher::new(config);
    let info_hash = [0x77; 20];
    let files = vec![
        File {
            path: "Show.S01E01.mkv".into(),
            length: 111,
            is_padding: false,
        },
        File {
            path: "Show.S01E02.mkv".into(),
            length: 222,
            is_padding: false,
        },
    ];
    let trackers = vec![
        "udp://tracker.example.com:6969/announce".to_string(),
        "http://backup.example.org/announce".to_string(),
    ];

    dispatcher
        .on_torrent_completed(info_hash, "Show.S01", 333, &download_dir, &files, &trackers)
        .await
        .unwrap();

    let get = |key: &str| -> String {
        fs::read_to_string(out_dir.join(key)).unwrap_or_else(|e| panic!("missing {key}: {e}"))
    };

    assert_eq!(get("HASH"), hex::encode(info_hash));
    assert_eq!(get("NAME"), "Show.S01");
    assert_eq!(get("DOWNLOAD_DIR"), download_dir.to_string_lossy());
    assert_eq!(
        get("SOURCE_PATH"),
        download_dir.join("Show.S01").to_string_lossy()
    );
    assert_eq!(get("TOTAL_BYTES"), "333");
    assert_eq!(get("FILE_COUNT"), "2");
    assert_eq!(get("FILES"), "Show.S01E01.mkv\nShow.S01E02.mkv");
    assert_eq!(
        get("TRACKERS"),
        "udp://tracker.example.com:6969/announce\nhttp://backup.example.org/announce"
    );

    // The JSON blob independently carries the same data, for a script that would rather parse
    // structured data than scrape individual env vars.
    let parsed: synapse_engine::TorrentCompletedEvent =
        serde_json::from_str(&get("EVENT_JSON")).unwrap();
    assert_eq!(parsed.name, "Show.S01");
    assert_eq!(parsed.total_bytes, 333);
    assert_eq!(parsed.files.len(), 2);
    assert_eq!(parsed.trackers, trackers);
}

#[cfg(unix)]
#[tokio::test]
async fn post_script_enforces_timeout_and_kills_hanging_child() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    let tmp = tempdir().unwrap();
    let download_dir = tmp.path().join("downloads");
    fs::create_dir_all(&download_dir).unwrap();
    let script_path = tmp.path().join("hang.sh");
    fs::write(&script_path, "#!/bin/sh\nexec sleep 30\n").unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    let dispatcher = LifecycleDispatcher::new(LifecycleConfig {
        staging_dir: None,
        auto_hardlink: false,
        wal_path: None,
        post_script: Some(script_path),
        copy_script: None,
        script_timeout: Some(Duration::from_millis(150)),
        instructions: None,
    });

    let started = Instant::now();
    let err = dispatcher
        .on_torrent_completed([0x33; 20], "hang_test", 10, &download_dir, &[], &[])
        .await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "timeout should abort quickly, took {elapsed:?}"
    );
    assert!(
        err.is_ok(),
        "dispatcher swallows individual plugin error and returns event"
    );

    // Directly test PostScriptPlugin::on_torrent_completed for explicit timeout error.
    let plugin = synapse_engine::PostScriptPlugin::new("post_script", tmp.path().join("hang.sh"))
        .with_timeout(Duration::from_millis(150));
    use synapse_engine::{LifecyclePlugin, TorrentCompletedEvent};
    let ev = TorrentCompletedEvent {
        info_hash_hex: hex::encode([0x33; 20]),
        name: "hang_test".into(),
        total_bytes: 10,
        download_dir: download_dir.to_string_lossy().to_string(),
        source_path: download_dir.join("hang_test").to_string_lossy().to_string(),
        staged_path: None,
        files: vec![],
        trackers: vec![],
        timestamp_ms: 0,
    };
    let res = plugin.on_torrent_completed(&ev).await;
    assert!(
        matches!(res, Err(synapse_engine::LifecycleError::Plugin { ref message, .. }) if message.contains("timed out")),
        "expected timeout error, got {res:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn post_script_delivers_stdin_and_json_file_and_caps_huge_file_list_without_e2big() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempdir().unwrap();
    let download_dir = tmp.path().join("downloads");
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&download_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let script_path = tmp.path().join("check_big.sh");
    let d = out_dir.display();
    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\n\
             set -eu\n\
             cat > {d}/stdin.json\n\
             cp \"$SYNAPSE_EVENT_JSON_FILE\" {d}/file.json\n\
             printf '%s' \"$SYNAPSE_EVENT_JSON_FILE\" > {d}/json_path.txt\n\
             printf '%s' \"${{SYNAPSE_FILES_TRUNCATED:-}}\" > {d}/files_trunc.txt\n\
             printf '%s' \"${{SYNAPSE_EVENT_JSON_TRUNCATED:-}}\" > {d}/json_trunc.txt\n\
             printf '%s' \"${{#SYNAPSE_FILES}}\" > {d}/files_len.txt\n"
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();

    let files: Vec<File> = (0..5000)
        .map(|i| File {
            path: format!("season_01/episode_{i:04}_very_long_release_name_here.mkv").into(),
            length: 1024,
            is_padding: false,
        })
        .collect();

    let plugin = synapse_engine::PostScriptPlugin::new("post_script", script_path);
    use synapse_engine::{LifecyclePlugin, TorrentCompletedEvent};
    let ev = TorrentCompletedEvent {
        info_hash_hex: hex::encode([0x44; 20]),
        name: "huge_pack".into(),
        total_bytes: 5000 * 1024,
        download_dir: download_dir.to_string_lossy().to_string(),
        source_path: download_dir.join("huge_pack").to_string_lossy().to_string(),
        staged_path: None,
        files: files
            .iter()
            .map(|f| synapse_engine::CompletedFileInfo {
                path: f.path.to_string_lossy().to_string(),
                length: f.length,
            })
            .collect(),
        trackers: vec![],
        timestamp_ms: 12345,
    };

    plugin.on_torrent_completed(&ev).await.unwrap();

    assert_eq!(
        fs::read_to_string(out_dir.join("files_trunc.txt")).unwrap(),
        "1"
    );
    assert_eq!(
        fs::read_to_string(out_dir.join("json_trunc.txt")).unwrap(),
        "1"
    );
    let env_files_len: usize = fs::read_to_string(out_dir.join("files_len.txt"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(env_files_len <= 32 * 1024);

    let stdin_json = fs::read_to_string(out_dir.join("stdin.json")).unwrap();
    let file_json = fs::read_to_string(out_dir.join("file.json")).unwrap();
    assert_eq!(stdin_json, file_json);
    let parsed: TorrentCompletedEvent = serde_json::from_str(&file_json).unwrap();
    assert_eq!(parsed.files.len(), 5000);

    let temp_json_path = fs::read_to_string(out_dir.join("json_path.txt")).unwrap();
    assert!(
        !std::path::Path::new(&temp_json_path).exists(),
        "temporary JSON file should be removed cleanly on drop"
    );
}
