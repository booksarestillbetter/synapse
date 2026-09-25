# Paranoid Mode

An optional, disabled-by-default logging lockdown: `[privacy].paranoid_mode = true` suppresses
every log line except the daemon starting up, each listener coming up (or failing to come up),
and shutdown. No torrent names, info hashes, peer addresses, tracker announces, file paths,
transfer stats, or errors that mention any of those — nothing that says what synapse is fetching
or who it's talking to.

This is a deliberate, restart-required opt-in for a specific threat model (logs themselves being
a liability — shared hosting, a compromised log aggregator, a subpoena, a nosy sysadmin), not a
general log-noise reducer. If you just want less chatter, use `[logging].level = "warn"` instead
and leave `paranoid_mode` off.

## Enabling it

```toml
[privacy]
paranoid_mode = true
```

or the equivalent environment variable, `SYNAPSE_PARANOID_MODE=true`.

While it's on, `[logging].level` and `RUST_LOG` are both ignored entirely — paranoid mode is
authoritative over what gets logged, not one more filter layered on top of them, and it can't be
silently reopened by an environment variable left over from a debugging session.

## What still gets logged

Exactly three kinds of event, all handled the same way a systemd/Docker health check would
read them — none of them say anything about what's being downloaded, seeded, or connected to:

- **Startup**: the daemon starting, subsystems (storage, BEP 35 trust store, RSS poller, search
  engines) initializing, and any startup-time configuration problem.
- **Listening**: each listener (BitTorrent peer port, LSD, Zeroconf, DHT, gRPC control plane,
  REST API/web UI) coming up with the address it bound, or failing to bind with the reason —
  including a hard failure to bind the peer port at all, which stops the daemon. Also RLIMIT
  tuning and a SIGHUP config reload's own outcome (reloaded, or failed to reload).
- **Shutdown**: which shutdown signal was received, the graceful-shutdown sequence, and whether
  it completed or timed out.

## What's suppressed

Everything else — which, concretely, is essentially the entire engine: every torrent add,
piece completion, hash failure, peer connect/disconnect, choke/unchoke decision, tracker
announce and scrape, DHT lookup, circuit breaker trip, rate limit adjustment, alert, and the
watch-directory's own per-file ingest log (which otherwise prints the incoming torrent's name).
File logging and network syslog (`[logging].file`/`[logging].syslog_addr`, if configured) are
suppressed exactly the same way — paranoid mode governs everything the daemon emits, not just
the console.

## How it's enforced

This isn't a list of log statements individually checked against a denylist — that approach
only holds until someone adds a new log line somewhere in the several hundred thousand lines of
engine code and forgets to be careful about what it prints. Instead, the handful of startup/
listener/shutdown lines above are the only ones tagged with a specific `tracing` target
(`lifecycle`); paranoid mode's filter is `off,lifecycle=info` — a default-deny allowlist that
turns everything off except that one target. A log line elsewhere that isn't careful about what
it prints still can't leak through an allowlist it was never added to, and nothing added to the
codebase in the future is logged in paranoid mode unless it explicitly opts in by using that
target.

## Confirming it's active

The daemon logs one line, on the `lifecycle` target (so it survives the filter, and doubles as
proof the filter is actually installed), right after startup:

```
🕶️  Paranoid mode active: only startup, listener and shutdown events are logged — no torrent,
peer, tracker or transfer detail. RUST_LOG and [logging].level are ignored while this is on.
```

If you don't see that line, paranoid mode isn't active — check `[privacy].paranoid_mode` in the
config actually being loaded (`--config <path>`, or the platform default location) and that
you've restarted the daemon after changing it (it's read once at startup, not hot-reloaded).
