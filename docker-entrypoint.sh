#!/bin/sh
set -e

# Support user customization via PUID and PGID (or USER_ID / GROUP_ID)
PUID="${PUID:-${USER_ID:-1001}}"
PGID="${PGID:-${GROUP_ID:-1001}}"

# Locate template file (stored outside /etc/synapse so volume mounts cannot mask it)
TEMPLATE=""
if [ -f /usr/share/synapse/synapse.toml.default ]; then
    TEMPLATE="/usr/share/synapse/synapse.toml.default"
elif [ -f /etc/synapse.default.toml ]; then
    TEMPLATE="/etc/synapse.default.toml"
elif [ -f /etc/synapse/synapse.toml.default ]; then
    TEMPLATE="/etc/synapse/synapse.toml.default"
fi

# Locate existing configuration file
CONFIG_PATH=""
if [ -n "$SYNAPSE_CONFIG" ] && [ -f "$SYNAPSE_CONFIG" ]; then
    CONFIG_PATH="$SYNAPSE_CONFIG"
elif [ -f /etc/synapse/synapse.toml ]; then
    CONFIG_PATH="/etc/synapse/synapse.toml"
elif [ -f /etc/synapse/config/synapse.toml ]; then
    CONFIG_PATH="/etc/synapse/config/synapse.toml"
elif [ -f /etc/synapse ]; then
    # In case /etc/synapse was directly mounted as a file (-v ...:/etc/synapse)
    CONFIG_PATH="/etc/synapse"
elif [ -f /var/lib/synapse/synapse.toml ]; then
    CONFIG_PATH="/var/lib/synapse/synapse.toml"
elif [ -f /etc/synapse/config.toml ]; then
    CONFIG_PATH="/etc/synapse/config.toml"
fi

# If no config file found, attempt to seed /etc/synapse/synapse.toml from template
if [ -z "$CONFIG_PATH" ] && [ -n "$TEMPLATE" ]; then
    if [ -d /etc/synapse ] && touch /etc/synapse/.probe 2>/dev/null; then
        rm -f /etc/synapse/.probe
        echo "Creating default /etc/synapse/synapse.toml from template ($TEMPLATE)..."
        cp "$TEMPLATE" /etc/synapse/synapse.toml 2>/dev/null || true
        if [ -f /etc/synapse/synapse.toml ]; then
            CONFIG_PATH="/etc/synapse/synapse.toml"
        fi
    fi
fi

# If still no config file found but template exists, use the template directly
if [ -z "$CONFIG_PATH" ] && [ -n "$TEMPLATE" ]; then
    CONFIG_PATH="$TEMPLATE"
fi

# Ensure storage directories exist
mkdir -p /var/lib/synapse/session /data/downloads /media/queue 2>/dev/null || true

# Prepare command invocation: only pass -c if CONFIG_PATH is a verified existing file
CMD_EXEC="/usr/local/bin/synapsed"
if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
    SET_CONFIG="-c $CONFIG_PATH"
else
    SET_CONFIG=""
fi

# If running as root (container default), handle UID/GID mapping and drop privileges
if [ "$(id -u)" = "0" ]; then
    if [ "$PUID" = "0" ] || [ "$PUID" = "root" ]; then
        echo "Running Synapse as root with config: ${CONFIG_PATH:-built-in defaults}"
        exec $CMD_EXEC $SET_CONFIG "$@"
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
    if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
        chown "$PUID:$PGID" "$CONFIG_PATH" 2>/dev/null || true
    fi
    if [ -d /etc/synapse ]; then
        chown -R "$PUID:$PGID" /etc/synapse 2>/dev/null || true
    fi

    # Ensure queue staging directory is accessible by PUID:PGID
    if [ -d /media/queue ]; then
        chown "$PUID:$PGID" /media/queue 2>/dev/null || true
        chmod 775 /media/queue 2>/dev/null || true
    fi

    echo "Running Synapse as UID $PUID (GID $PGID) with config: ${CONFIG_PATH:-built-in defaults}"
    exec gosu "$PUID:$PGID" $CMD_EXEC $SET_CONFIG "$@"
else
    # Container was started with an explicit non-root user (e.g., docker run --user ...)
    echo "Running Synapse as user $(id -u):$(id -g) with config: ${CONFIG_PATH:-built-in defaults}"
    exec $CMD_EXEC $SET_CONFIG "$@"
fi
