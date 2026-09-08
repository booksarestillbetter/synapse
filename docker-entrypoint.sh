#!/bin/sh
set -e

# Support user customization via PUID and PGID (or USER_ID / GROUP_ID)
PUID="${PUID:-${USER_ID:-1001}}"
PGID="${PGID:-${GROUP_ID:-1001}}"

# If /etc/synapse is mounted from host and missing synapse.toml, seed with default
if [ ! -f /etc/synapse/synapse.toml ] && [ -f /etc/synapse/synapse.toml.default ]; then
    echo "Creating default /etc/synapse/synapse.toml from template..."
    cp /etc/synapse/synapse.toml.default /etc/synapse/synapse.toml 2>/dev/null || true
fi

# Determine active configuration path
CONFIG_PATH=""
if [ -n "$SYNAPSE_CONFIG" ] && [ -f "$SYNAPSE_CONFIG" ]; then
    CONFIG_PATH="$SYNAPSE_CONFIG"
elif [ -f /etc/synapse/synapse.toml ]; then
    CONFIG_PATH="/etc/synapse/synapse.toml"
else
    CONFIG_PATH="/etc/synapse/synapse.toml.default"
fi

# Ensure storage directories exist
mkdir -p /var/lib/synapse/session /data/downloads /media/queue 2>/dev/null || true

# If running as root (container default), handle UID/GID mapping and drop privileges
if [ "$(id -u)" = "0" ]; then
    if [ "$PUID" = "0" ] || [ "$PUID" = "root" ]; then
        echo "Running Synapse as root with config: $CONFIG_PATH"
        exec /usr/local/bin/synapsed -c "$CONFIG_PATH" "$@"
    fi

    # Adjust synapse group GID if necessary
    CURRENT_GID=$(id -g synapse 2>/dev/null || true)
    if [ -n "$CURRENT_GID" ] && [ "$CURRENT_GID" != "$PGID" ]; then
        groupmod -o -g "$PGID" synapse 2>/dev/null || true
    fi

    # Adjust synapse user UID if necessary
    CURRENT_UID=$(id -u synapse 2>/dev/null || true)
    if [ -n "$CURRENT_UID" ] && [ "$CURRENT_UID" != "$PUID" ]; then
        usermod -o -u "$PUID" synapse 2>/dev/null || true
    fi

    # Ensure ownership of session dir and local config
    chown -R "$PUID:$PGID" /var/lib/synapse 2>/dev/null || true
    if [ -f /etc/synapse/synapse.toml ]; then
        chown "$PUID:$PGID" /etc/synapse/synapse.toml 2>/dev/null || true
    fi

    # Ensure queue staging directory is accessible by PUID:PGID
    if [ -d /media/queue ]; then
        chown "$PUID:$PGID" /media/queue 2>/dev/null || true
        chmod 775 /media/queue 2>/dev/null || true
    fi

    echo "Running Synapse as UID $PUID (GID $PGID) with config: $CONFIG_PATH"
    exec gosu "$PUID:$PGID" /usr/local/bin/synapsed -c "$CONFIG_PATH" "$@"
else
    # Container was started with an explicit non-root user (e.g., docker run --user ...)
    echo "Running Synapse as user $(id -u):$(id -g) with config: $CONFIG_PATH"
    exec /usr/local/bin/synapsed -c "$CONFIG_PATH" "$@"
fi
