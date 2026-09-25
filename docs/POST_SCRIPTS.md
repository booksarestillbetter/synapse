# Post-Completion Scripts

An optional, disabled-by-default hook that runs an external program once a torrent finishes
downloading. This is the "just run my own script, no server involved" option — see
`docs/COMPLETION_INSTRUCTIONS.md` if you want synapse to place files itself by asking a server
where they go, and `example_config.toml`'s `[lifecycle]` section for how these fit together (at
most one of the three completion options is normally active at a time).

Nothing about this depends on Conduit or any other management app. The script gets everything
it needs about the completed torrent — arguments, individual environment variables, and a full
JSON dump — and does whatever it wants with it: move files, kick a media server library scan,
send a notification, write to a database, or call some other service's API. `docs/HACKING.md`'s
crate table and `docs/COMPLETION_INSTRUCTIONS.md`'s webhook contract are the other two options
if you'd rather synapse do the placement itself.

## Enabling it

```toml
[lifecycle]
post_script = "/etc/synapse/on-complete.sh"
# copy_script = "/etc/synapse/on-copy.sh"   # optional second, independent script slot — see below
```

The script (or binary — it just needs to be executable) must exist and be executable when the
torrent completes; if it doesn't, synapse logs a warning and moves on rather than failing the
torrent. It runs asynchronously and its own failure (non-zero exit, or failing to spawn at all)
is logged but never affects the torrent itself — a completed download stays completed either way.

`post_script` and `copy_script` are two entirely independent slots for the *same* kind of hook,
not a "download script" vs. "copy script" distinction — run one script that does everything, or
split concerns across both (e.g. one script that hardlinks files into a media library and a
separate one that only sends a notification). Both receive the exact same arguments and
environment variables, described below.

## When it fires

Once per torrent, the moment its last piece is verified and written to disk — the same event
that also drives the `auto_hardlink`/staging path and the `[lifecycle.instructions]` webhook, if
either of those is also configured (every configured completion option runs independently, so
more than one can be active if you actually want that — see the caveat in `example_config.toml`
about them not being mutually exclusive in the config, only usually in intent). It does not fire
on partial progress, on pause/resume, or on manual recheck.

## What the script receives

### Positional arguments

```
$1  info hash (40-char hex)
$2  torrent name
$3  source path (the completed torrent's own directory/file under the configured download dir)
$4  staged path (empty string if auto_hardlink/staging_dir isn't also configured)
$5  total size in bytes
```

These five are stable and will not change shape — a script written against them keeps working
across synapse versions. Everything else below is additive: new environment variables may be
added over time, but existing ones won't be removed or repurposed.

### Environment variables

| Variable | Contents |
|---|---|
| `SYNAPSE_INFO_HASH` | Same as `$1` |
| `SYNAPSE_TORRENT_NAME` | Same as `$2` |
| `SYNAPSE_DOWNLOAD_DIR` | The configured download directory the torrent was written under (not joined with the torrent's name — this is the raw `[disk].download_dir`-style path) |
| `SYNAPSE_SOURCE_PATH` | Same as `$3` |
| `SYNAPSE_STAGED_PATH` | Same as `$4` |
| `SYNAPSE_TOTAL_BYTES` | Same as `$5` |
| `SYNAPSE_TIMESTAMP_MS` | Unix epoch milliseconds when the torrent completed |
| `SYNAPSE_FILE_COUNT` | Number of files in the torrent (1 for a single-file torrent) |
| `SYNAPSE_FILES` | Every file's path, relative to `SYNAPSE_DOWNLOAD_DIR`, one per line (`\n`-joined — a file path can't contain a literal newline, so this splits back apart unambiguously; see the shell example below) |
| `SYNAPSE_TRACKERS` | Every announce URL the torrent has, tier order, one per line (empty string for a DHT/PEX-only torrent with no trackers at all) |
| `SYNAPSE_EVENT_JSON` | The complete completion event as a single-line JSON object (all of the above, plus nothing else — this is the same shape as `TorrentCompletedEvent` in `crates/synapse-engine/src/lifecycle.rs`) — reach for this instead of the individual variables if your script already has a JSON tool (`jq`, Python, etc.) on hand, rather than parsing shell strings |

### Reading a multi-line variable safely

```sh
#!/bin/sh
# One file per line — this loop is safe even if a file path contains spaces.
printf '%s\n' "$SYNAPSE_FILES" | while IFS= read -r file; do
    echo "completed file: $SYNAPSE_DOWNLOAD_DIR/$file"
done

# Or, with jq, from the JSON blob instead:
echo "$SYNAPSE_EVENT_JSON" | jq -r '.files[].path'
```

## Example: notify a media server and log to a file

```sh
#!/bin/sh
set -eu

echo "$(date -Iseconds) completed: $SYNAPSE_TORRENT_NAME ($SYNAPSE_TOTAL_BYTES bytes, $SYNAPSE_FILE_COUNT file(s))" \
    >> /var/log/synapse-completions.log

# Trigger a Jellyfin library scan — one example of "do whatever you want", no management app involved.
curl -fsS -X POST "http://localhost:8096/Library/Refresh" \
    -H "X-Emby-Token: ${JELLYFIN_API_KEY:?set JELLYFIN_API_KEY in the environment synapse runs under}"
```

## Relationship to the other two completion options

| | Runs in synapse's own process | Placement decided by | Needs a server |
|---|---|---|---|
| `auto_hardlink` + `staging_dir` | Yes | Fixed, configured directory | No |
| `[lifecycle.instructions]` | Yes | A URL you point it at | Yes (see `docs/COMPLETION_INSTRUCTIONS.md`) |
| `post_script` / `copy_script` | No — a separate process | Whatever the script does | No, unless the script itself calls one |

All three are entirely optional and independent of one another and of any particular
management app. Conduit is one thing that can drive `[lifecycle.instructions]`'s webhook
contract or consume a `post_script`'s output, but it implements an open, documented contract —
nothing here requires it, and nothing here fails or degrades in its absence.
