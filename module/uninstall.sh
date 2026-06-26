#!/system/bin/sh

TAG="AntiDevPmZygisk"
TARGET_PKG="com.eltavine.duckdetector"
MIUI_INVENTORY_OP="10022"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
STATE_FILE="$STATE_DIR/miuiop10022.prev"
PID_FILE="$STATE_DIR/inventory.pid"
PM_BIN="/system/bin/pm"
CMD_BIN="/system/bin/cmd"
LOG_BIN="/system/bin/log"

logi() {
    "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

old_pid="$(cat "$PID_FILE" 2>/dev/null)"
if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    kill "$old_pid" >/dev/null 2>&1
    logi "inventory appop worker stopped: pid=$old_pid"
fi

rm -f /data/adb/service.d/anti_dev_pm_inventory.sh

if [ ! -f "$STATE_FILE" ]; then
    logi "inventory appop restore skip: no legacy DuckDetector state"
else
    previous="$(cat "$STATE_FILE" 2>/dev/null)"
    restore_mode="default"
    case "$previous" in
        *": allow"*) restore_mode="allow" ;;
        *": ignore"*) restore_mode="ignore" ;;
        *": deny"*) restore_mode="deny" ;;
        *": foreground"*) restore_mode="foreground" ;;
        *": default"*) restore_mode="default" ;;
    esac

    if "$PM_BIN" path --user 0 "$TARGET_PKG" >/dev/null 2>&1 ||
        "$PM_BIN" path "$TARGET_PKG" >/dev/null 2>&1; then
        if "$CMD_BIN" appops set "$TARGET_PKG" "$MIUI_INVENTORY_OP" "$restore_mode" >/dev/null 2>&1; then
            logi "inventory appop restored: pkg=$TARGET_PKG op=$MIUI_INVENTORY_OP mode=$restore_mode"
        else
            logi "inventory appop restore failed: pkg=$TARGET_PKG op=$MIUI_INVENTORY_OP mode=$restore_mode"
        fi
    fi
fi

for prev_file in "$STATE_DIR"/*.prev; do
    [ -f "$prev_file" ] || continue
    [ "$prev_file" = "$STATE_FILE" ] && continue

    pkg="${prev_file##*/}"
    pkg="${pkg%.prev}"
    previous="$(cat "$prev_file" 2>/dev/null)"
    restore_mode="default"
    case "$previous" in
        *": allow"*) restore_mode="allow" ;;
        *": ignore"*) restore_mode="ignore" ;;
        *": deny"*) restore_mode="deny" ;;
        *": foreground"*) restore_mode="foreground" ;;
        *": default"*) restore_mode="default" ;;
    esac

    if "$PM_BIN" path --user 0 "$pkg" >/dev/null 2>&1 ||
        "$PM_BIN" path "$pkg" >/dev/null 2>&1; then
        if "$CMD_BIN" appops set "$pkg" "$MIUI_INVENTORY_OP" "$restore_mode" >/dev/null 2>&1; then
            logi "inventory appop restored: pkg=$pkg op=$MIUI_INVENTORY_OP mode=$restore_mode"
        else
            logi "inventory appop restore failed: pkg=$pkg op=$MIUI_INVENTORY_OP mode=$restore_mode"
        fi
    fi
done

rm -rf "$STATE_DIR"
