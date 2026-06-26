#!/system/bin/sh

TAG="AntiDevPmZygisk"
TARGET_PKG="com.eltavine.duckdetector"
MIUI_INVENTORY_OP="10022"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
STATE_FILE="$STATE_DIR/miuiop10022.prev"
PID_FILE="$STATE_DIR/inventory.pid"

logi() {
    log -t "$TAG" "$*"
}

old_pid="$(cat "$PID_FILE" 2>/dev/null)"
if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    kill "$old_pid" >/dev/null 2>&1
    logi "inventory appop worker stopped: pid=$old_pid"
fi

if [ ! -f "$STATE_FILE" ]; then
    logi "inventory appop restore skip: no previous state"
    rm -rf "$STATE_DIR"
    exit 0
fi

previous="$(cat "$STATE_FILE" 2>/dev/null)"
restore_mode="default"
case "$previous" in
    *": allow"*) restore_mode="allow" ;;
    *": ignore"*) restore_mode="ignore" ;;
    *": deny"*) restore_mode="deny" ;;
    *": foreground"*) restore_mode="foreground" ;;
    *": default"*) restore_mode="default" ;;
esac

if pm path "$TARGET_PKG" >/dev/null 2>&1; then
    if cmd appops set "$TARGET_PKG" "$MIUI_INVENTORY_OP" "$restore_mode" >/dev/null 2>&1; then
        logi "inventory appop restored: op=$MIUI_INVENTORY_OP mode=$restore_mode"
    else
        logi "inventory appop restore failed: op=$MIUI_INVENTORY_OP mode=$restore_mode"
    fi
fi

rm -rf "$STATE_DIR"
