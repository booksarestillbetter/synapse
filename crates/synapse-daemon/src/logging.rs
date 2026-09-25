//! Synapse 2.0 Logging Subsystem.
//!
//! Provides multi-target structured logging:
//! 1. Console / Terminal formatting (Pretty, Compact, or JSON).
//! 2. Optional File Appender (writing log streams to disk).
//! 3. Optional Network Syslog (RFC 5424) over TCP/UDP to port 514.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, SyncSender};
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
        std::env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.as_filter().to_string())
    }
}

/// Initializes the global tracing subscriber according to daemon configuration.
pub fn init_logging(config: &Config) {
    let filter = EnvFilter::try_new(filter_directive(config))
        .unwrap_or_else(|_| EnvFilter::new(config.logging.level.as_filter()));

    // 1. Console Layer
    let console_layer = match config.logging.format {
        LogFormat::Pretty => fmt::layer().pretty().boxed(),
        LogFormat::Compact => fmt::layer().compact().boxed(),
        LogFormat::Json => fmt::layer().json().boxed(),
    };

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer);

    // 2. Optional File Layer
    let file_layer = config.logging.file.as_ref().and_then(|path| {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Some(
                fmt::layer()
                    .with_writer(std::sync::Mutex::new(file))
                    .with_ansi(false)
                    .compact(),
            ),
            Err(e) => {
                eprintln!(
                    "WARNING: failed to open log file {}: {}. Proceeding without file logging.",
                    path.display(),
                    e
                );
                None
            }
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

impl<S> Layer<S> for SyslogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let pri = match *event.metadata().level() {
            Level::ERROR => 11,                // Local0.Error (16 * 8 + 3)
            Level::WARN => 12,                 // Local0.Warn  (16 * 8 + 4)
            Level::INFO => 14,                 // Local0.Info  (16 * 8 + 6)
            Level::DEBUG | Level::TRACE => 15, // Local0.Debug (16 * 8 + 7)
        };

        let msg = visitor.message.unwrap_or_default();
        let target = event.metadata().target();

        // Format RFC 5424 syslog line: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        let now = chrono_timestamp();
        let syslog_msg = format!(
            "<{pri}>1 {now} localhost synapsed {} {target} - {msg}\n",
            std::process::id()
        );

        let _ = self.sender.try_send(syslog_msg);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
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
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        while let Ok(msg) = rx.recv() {
            let _ = socket.send_to(msg.as_bytes(), addr);
        }
    }
}

fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", dur.as_secs(), dur.subsec_millis())
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
}
