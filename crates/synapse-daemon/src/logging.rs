//! Synapse 2.0 Logging Subsystem.
//!
//! Provides multi-target structured logging:
//! 1. Console / Terminal formatting (Pretty, Compact, or JSON).
//! 2. Optional File Appender (writing log streams to disk).
//! 3. Optional Network Syslog (RFC 5424) over TCP/UDP to port 514.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use synapse_config::{Config, LogFormat};
use tracing::field::Visit;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// The `tracing` target every startup/listener/shutdown log line in `main.rs` uses. Paranoid
/// mode's allowlist (below) names this target precisely rather than trying to enumerate every
/// individual call site, so anything added later that doesn't explicitly opt in stays silenced.
pub const LIFECYCLE_TARGET: &str = "lifecycle";

struct ReopenableLogFileInner {
    path: PathBuf,
    file: File,
}

/// Thread-safe, SIGHUP-reopenable file writer for tracing output.
#[derive(Clone)]
pub struct ReopenableLogFile {
    inner: Arc<Mutex<ReopenableLogFileInner>>,
}

impl ReopenableLogFile {
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ReopenableLogFileInner { path, file })),
        })
    }

    pub fn reopen(&self) -> std::io::Result<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.file.flush();
        if let Some(parent) = guard.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&guard.path)?;
        guard.file = new_file;
        Ok(())
    }
}

impl Write for ReopenableLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.file.flush()
    }
}

impl<'a> fmt::MakeWriter<'a> for ReopenableLogFile {
    type Writer = ReopenableLogFile;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static ACTIVE_LOG_FILE: OnceLock<ReopenableLogFile> = OnceLock::new();

/// Reopens the configured daemon log file (if active), enabling external logrotate via `SIGHUP`.
pub fn reopen_log_file() -> std::io::Result<bool> {
    if let Some(handle) = ACTIVE_LOG_FILE.get() {
        handle.reopen()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn effective_log_level(config: &Config) -> synapse_config::LogLevel {
    if config.logging.level != synapse_config::LogLevel::Info {
        config.logging.level
    } else {
        config.log_level
    }
}

/// The `EnvFilter` directive `init_logging` builds, factored out as a pure function so its
/// logic is unit-testable — `EnvFilter`/`tracing`'s global subscriber can only be installed
/// once per process, which rules out testing `init_logging` itself directly.
fn filter_directive(config: &Config) -> String {
    if config.privacy.paranoid_mode {
        // Default-deny: nothing is enabled except the lifecycle target at info. This
        // deliberately ignores RUST_LOG and [logging].level entirely — paranoid mode must not
        // be silently reopened by an environment variable left over from a debugging session,
        // and a log line elsewhere that isn't careful about what it prints still can't leak
        // through an allowlist it was never added to.
        format!("off,{LIFECYCLE_TARGET}=info")
    } else {
        std::env::var("RUST_LOG")
            .unwrap_or_else(|_| effective_log_level(config).as_filter().to_string())
    }
}

/// Initializes the global tracing subscriber according to daemon configuration.
pub fn init_logging(config: &Config) {
    let fallback = effective_log_level(config).as_filter();
    let filter =
        EnvFilter::try_new(filter_directive(config)).unwrap_or_else(|_| EnvFilter::new(fallback));

    // 1. Console Layer
    let console_layer = match config.logging.format {
        LogFormat::Pretty => fmt::layer().pretty().boxed(),
        LogFormat::Compact => fmt::layer().compact().boxed(),
        LogFormat::Json => fmt::layer().json().boxed(),
    };

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer);

    // 2. Optional File Layer (SIGHUP-reopenable handle)
    let file_layer =
        config
            .logging
            .file
            .as_ref()
            .and_then(|path| match ReopenableLogFile::open(path.clone()) {
                Ok(handle) => {
                    let _ = ACTIVE_LOG_FILE.set(handle.clone());
                    Some(fmt::layer().with_writer(handle).with_ansi(false).compact())
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: failed to open log file {}: {}. Proceeding without file logging.",
                        path.display(),
                        e
                    );
                    None
                }
            });

    // 3. Optional Syslog Layer (TCP/UDP to port 514)
    let syslog_layer = config.logging.syslog_addr.map(|addr| {
        let is_tcp = config.logging.syslog_tcp;
        SyslogLayer::new(addr, is_tcp)
    });

    match (file_layer, syslog_layer) {
        (Some(f), Some(s)) => {
            registry.with(f).with(s).init();
        }
        (Some(f), None) => {
            registry.with(f).init();
        }
        (None, Some(s)) => {
            registry.with(s).init();
        }
        (None, None) => {
            registry.init();
        }
    }

    if config.privacy.paranoid_mode {
        // Emitted after `.init()` (a tracing event dispatched before the global subscriber is
        // installed goes nowhere) so this confirmation is itself the proof paranoid mode took
        // effect — if this line doesn't show up, nothing configured after it will either.
        tracing::info!(
            target: LIFECYCLE_TARGET,
            "🕶️  Paranoid mode active: only startup, listener and shutdown events are logged \
             — no torrent, peer, tracker or transfer detail. RUST_LOG and [logging].level are \
             ignored while this is on."
        );
    }
}

/// Custom tracing Layer that forwards events to a Syslog TCP/UDP daemon (port 514).
pub struct SyslogLayer {
    sender: SyncSender<String>,
}

impl SyslogLayer {
    pub fn new(addr: SocketAddr, is_tcp: bool) -> Self {
        let (tx, rx) = sync_channel::<String>(10_000);

        // Spawn background worker thread for network syslog delivery
        thread::Builder::new()
            .name("synapse-syslog-worker".into())
            .spawn(move || {
                if is_tcp {
                    run_tcp_syslog_worker(addr, rx);
                } else {
                    run_udp_syslog_worker(addr, rx);
                }
            })
            .expect("failed to spawn syslog worker thread");

        Self { sender: tx }
    }
}

fn syslog_pri(level: Level) -> u8 {
    let sev = match level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    };
    16 * 8 + sev
}

fn format_syslog_line(
    level: Level,
    target: &str,
    visitor: &MessageVisitor,
    pid: u32,
    now: &str,
) -> String {
    let pri = syslog_pri(level);
    let msg = visitor.format_syslog_body();
    let safe_target = sanitize_syslog_field(target);
    format!("<{pri}>1 {now} localhost synapsed {pid} {safe_target} - {msg}\n")
}

impl<S> Layer<S> for SyslogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let now = chrono_timestamp();
        let syslog_msg = format_syslog_line(
            *event.metadata().level(),
            event.metadata().target(),
            &visitor,
            std::process::id(),
            &now,
        );

        let _ = self.sender.try_send(syslog_msg);
    }
}

/// Sanitizes CR, LF, and NUL characters from syslog fields so attacker-controlled strings
/// (torrent names, peer client names, tracker errors) cannot forge multi-line syslog entries.
pub fn sanitize_syslog_field(s: &str) -> String {
    s.replace(['\r', '\n', '\0'], " ")
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl MessageVisitor {
    fn format_syslog_body(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref msg) = self.message {
            if !msg.is_empty() {
                parts.push(msg.as_str());
            }
        }
        for f in &self.fields {
            parts.push(f.as_str());
        }
        sanitize_syslog_field(&parts.join(" "))
    }
}

impl Visit for MessageVisitor {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}").trim_matches('"').to_string());
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }
}

fn run_tcp_syslog_worker(addr: SocketAddr, rx: std::sync::mpsc::Receiver<String>) {
    let mut stream: Option<std::net::TcpStream> = None;

    while let Ok(msg) = rx.recv() {
        let mut sent = false;
        for _ in 0..2 {
            if stream.is_none() {
                if let Ok(s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                    stream = Some(s);
                }
            }

            if let Some(ref mut s) = stream {
                if s.write_all(msg.as_bytes()).is_ok() {
                    let _ = s.flush();
                    sent = true;
                    break;
                } else {
                    stream = None; // Connection broken, retry once
                }
            }
        }

        if !sent {
            // Drop message if syslog destination is unreachable
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn run_udp_syslog_worker(addr: SocketAddr, rx: std::sync::mpsc::Receiver<String>) {
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    if let Ok(socket) = std::net::UdpSocket::bind(bind_addr) {
        while let Ok(msg) = rx.recv() {
            let _ = socket.send_to(msg.as_bytes(), addr);
        }
    }
}

fn format_rfc5424_utc(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc5424_utc(dur.as_secs(), dur.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // filter_directive reads RUST_LOG, a process-global env var; serialize against
    // `cargo test`'s default parallelism the same way synapse-config's own env-var tests do.
    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_chrono_timestamp_format() {
        let ts = chrono_timestamp();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('.'));
    }

    #[test]
    fn paranoid_mode_ignores_rust_log_and_the_configured_level() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RUST_LOG", "trace");

        let mut config = Config::default();
        config.privacy.paranoid_mode = true;
        config.logging.level = synapse_config::LogLevel::Trace;

        assert_eq!(
            filter_directive(&config),
            format!("off,{LIFECYCLE_TARGET}=info")
        );

        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn without_paranoid_mode_rust_log_wins_over_the_configured_level_when_set() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("RUST_LOG");

        let mut config = Config::default();
        config.logging.level = synapse_config::LogLevel::Warn;
        assert_eq!(filter_directive(&config), "warn");

        std::env::set_var("RUST_LOG", "debug");
        assert_eq!(filter_directive(&config), "debug");

        std::env::remove_var("RUST_LOG");
    }

    #[test]
    fn syslog_field_sanitization_strips_crlf_and_nul() {
        let malicious = "EvilTorrent\r\n<11>1 2026-01-01T00:00:00Z localhost synapsed 1 lifecycle - Forged\0Line";
        let sanitized = sanitize_syslog_field(malicious);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\0'));
        assert!(sanitized.contains("EvilTorrent  <11>1"));
    }

    #[test]
    fn top_level_log_level_acts_as_fallback_when_logging_section_is_default() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("RUST_LOG");

        let mut cfg = Config {
            log_level: synapse_config::LogLevel::Debug,
            ..Default::default()
        };
        assert_eq!(filter_directive(&cfg), "debug");

        cfg.logging.level = synapse_config::LogLevel::Error;
        assert_eq!(filter_directive(&cfg), "error");
    }

    #[test]
    fn syslog_pri_timestamps_and_structured_fields_follow_rfc5424() {
        assert_eq!(syslog_pri(Level::ERROR), 131);
        assert_eq!(syslog_pri(Level::WARN), 132);
        assert_eq!(syslog_pri(Level::INFO), 134);
        assert_eq!(syslog_pri(Level::DEBUG), 135);
        assert_eq!(syslog_pri(Level::TRACE), 135);

        assert_eq!(format_rfc5424_utc(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_rfc5424_utc(1_700_000_000, 42),
            "2023-11-14T22:13:20.042Z"
        );
        let ts = chrono_timestamp();
        assert_eq!(ts.len(), 24);
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[10], b'T');

        let visitor = MessageVisitor {
            message: Some("started".to_string()),
            fields: vec!["port=54345".to_string(), "ok=true".to_string()],
        };
        let line = format_syslog_line(
            Level::INFO,
            "lifecycle",
            &visitor,
            42,
            "1970-01-01T00:00:00.000Z",
        );
        assert_eq!(
            line,
            "<134>1 1970-01-01T00:00:00.000Z localhost synapsed 42 lifecycle - started port=54345 ok=true\n"
        );
    }

    #[test]
    fn reopenable_log_file_writes_to_new_inode_after_rename() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("daemon.log");
        let rotated = dir.path().join("daemon.log.1");

        let mut writer = ReopenableLogFile::open(active.clone()).unwrap();
        writer.write_all(b"before\n").unwrap();
        writer.flush().unwrap();

        std::fs::rename(&active, &rotated).unwrap();
        writer.reopen().unwrap();

        writer.write_all(b"after\n").unwrap();
        writer.flush().unwrap();

        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(&active).unwrap(), "after\n");
    }
}
