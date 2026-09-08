# Completion Instructions Webhook

An optional, disabled-by-default hook that fires once per torrent completion: synapse asks a
configured URL *where this torrent's files should go*, then places them there itself. It's an
in-process equivalent of the older pattern where a management app (conduit, in
particular) generates a shell script for Transmission's `script-torrent-done-filename` to run,
and that script calls back into the app's API to decide the destination. Same two HTTP calls,
same JSON shapes — synapse just makes them directly instead of exec'ing a script.

This document specifies the wire contract precisely enough to implement your own instructions
server, independent of conduit. Conduit's own implementation (`src/api/sync_routes.rs`,
`classify_file`/`notify_download`) is one correct implementation of this contract, not the
definition of it.

## Enabling it

```toml
[lifecycle]
auto_hardlink = false   # mutually exclusive with instructions in practice — pick one

[lifecycle.instructions]
enabled = true
url = "http://127.0.0.1:4242"      # base URL; /api/sync/classify and /api/sync/notify-download are appended
token = "your-bearer-token"         # optional — sent as `Authorization: Bearer <token>` if set
node_name = "synapse-01"            # identifies this daemon instance to the server, like a Transmission node name
timeout_secs = 10
fallback_dir = "/data/downloads"    # optional — see Failure handling below
```

See `example_config.toml` for the full annotated reference.

## When it fires

Once per torrent, the moment its last piece is verified and written to disk (the same event
that also drives the `auto_hardlink`/staging path and `post_script`/`copy_script`, if any of
those are also configured — every configured completion plugin runs independently, so you can
run more than one). It does not fire on partial progress, on pause/resume, or on manual
recheck.

## Request 1 — classify

```
POST {url}/api/sync/classify
Content-Type: application/json
Authorization: Bearer <token>        (omitted entirely if no token configured)
```

Body:

```jsonc
{
  "name": "The.Movie.2024.1080p.BluRay-GROUP",  // torrent's display name — required
  "hash": "a1b2c3...",                           // 40-char hex info-hash — always present
  "node": "synapse-01",                          // this daemon's configured node_name
  "dir": "/data/downloads",                      // the configured download directory (not joined with name)
  "tracker": "udp://tracker.example.com:6969/announce",  // first/primary announce URL, if any
  "trackers": ["udp://tracker.example.com:6969/announce", "http://backup.example.org/announce"],
  "total_bytes": 4294967296
}
```

`tracker`/`trackers` are omitted (not sent as `null`) when the torrent has no announce URL at
all (DHT/PEX-only, e.g. from a bare magnet with no `tr=` params). Match against every entry in
`trackers`, not just `tracker` — order is announce-tier order, most-preferred first, not a
ranking of which one actually seeded the download (synapse doesn't track that per-tracker).

### Expected response

```jsonc
{
  "target_dir": "/media/queue/movieQueue/",   // required — empty/missing means "do nothing, leave the file where it is"
  "post_cmd": "cp -al",                        // optional — see Placement semantics below
  "queue": "movie"                             // optional — echoed back in the notify call, your own bookkeeping label
}
```

Only `target_dir` is load-bearing. Everything else in the response body is ignored by synapse
(conduit's real response includes additional fields like `media_type`/`match_source`/
`decision_trace` for its own UI/logging — synapse doesn't read them, no need to omit them if
you're pointing at conduit unmodified).

An HTTP error status, a connection failure, or a timeout (`timeout_secs`) are all treated as
"couldn't get instructions" and go to fallback handling, below — a 200 response with an empty
`target_dir` is different: that's an explicit "no instructions, leave it" answer, not a failure.

## Placement semantics (`post_cmd`)

synapse does **not** shell out to `post_cmd` — the value's *intent* is interpreted, not
executed, so there's no shell-injection surface from a string that came back over the network,
and behavior doesn't depend on what happens to be installed in the container. The mapping:

| `post_cmd` contains | Operation |
|---|---|
| starts with `mv` | Move (rename; falls back to copy+delete-original across filesystems) |
| contains `-l`, `--link`, or `hardlink` | Hardlink (falls back to copy across filesystems — same as `cp -al`'s real-world behavior) |
| anything else, or omitted | Plain copy |

If you're pointing this at conduit unmodified, its default `post_cmd` is `cp -alv` (hardlink),
so files aren't duplicated on disk as long as `target_dir` is on the same filesystem as the
download directory.

For a multi-file torrent, every file is placed individually at
`{target_dir}/{file's path relative to the download directory}` — which already includes the
torrent's own name as its first path component (BitTorrent's normal multi-file layout), so you
don't get a doubled-up `target_dir/name/name/...`. A single-file torrent is placed at
`{target_dir}/{name}`.

## Request 2 — notify (best-effort, after placement)

Sent only after `target_dir` was non-empty and file placement succeeded. Its result is never
checked beyond logging a warning — by the time this fires, synapse has already done the real
work; this is purely "let the server know," for its own bookkeeping/notifications.

```
POST {url}/api/sync/notify-download
Content-Type: application/json
Authorization: Bearer <token>        (same as above)
```

```jsonc
{
  "hash": "a1b2c3...",
  "name": "The.Movie.2024.1080p.BluRay-GROUP",
  "node": "synapse-01",
  "path": "/media/queue/movieQueue/The.Movie.2024.1080p.BluRay-GROUP",  // where it ended up
  "queue": "movie",                                                     // echoed from the classify response
  "target_dir": "/media/queue/movieQueue/"                              // echoed from the classify response
}
```

## Failure handling

If the classify request fails outright (unreachable, times out, non-2xx status):

- **`fallback_dir` configured**: files are hardlinked there instead (same hardlink-with-
  copy-fallback semantics as the table above — a fixed, unconditional choice, since there's no
  server response to derive a smarter one from).
- **`fallback_dir` unset (the default)**: files are left exactly where they were downloaded.
  Nothing is moved, nothing is retried. This is the safe default — a torrent that finished
  downloading successfully doesn't lose that success just because a webhook was unreachable.

There is currently no retry queue — a completion instructions call that fails is not
attempted again for that torrent. If you need guaranteed delivery, poll `GET
/api/v1/torrents/{hash}` (via synapse's own REST API) and drive placement from the poller
instead of relying on this push-based hook.

## Building your own server

Any HTTP server that implements the two routes above satisfies this contract — nothing here is
conduit-specific. A minimal implementation only needs to:

1. Accept `POST /api/sync/classify`, read `name`/`hash`/`trackers`/`dir` from the body, decide a
   directory, and return `{"target_dir": "..."}`.
2. Accept `POST /api/sync/notify-download` and return any 2xx status (the body is never parsed).

Everything else — tracker-domain matching, filename regex, a UI to configure routing rules — is
policy that belongs in your server, not in synapse.
