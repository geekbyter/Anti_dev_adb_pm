#!/system/bin/sh

MODDIR="${0%/*}"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
PID_FILE="$STATE_DIR/inventory.pid"
WORKER_SRC="$MODDIR/inventory_worker.sh"
WORKER="$STATE_DIR/inventory_worker.sh"
TAG="AntiDevPmZygisk"
SH_BIN="/system/bin/sh"
LOG_BIN="/system/bin/log"
CP_BIN="/system/bin/cp"
CHMOD_BIN="/system/bin/chmod"

logi() {
    "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

mkdir -p "$STATE_DIR" >/dev/null 2>&1

stage_worker() {
    if [ -r "$WORKER_SRC" ]; then
        "$CP_BIN" -f "$WORKER_SRC" "$WORKER" >/dev/null 2>&1
        "$CHMOD_BIN" 0755 "$WORKER" >/dev/null 2>&1
    fi

    if [ ! -r "$WORKER" ]; then
        logi "inventory worker missing from post-fs-data: worker=$WORKER src=$WORKER_SRC"
        return 1
    fi
    return 0
}

stage_worker || exit 0

old_pid="$(cat "$PID_FILE" 2>/dev/null)"
if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    old_cmd="$(tr '\0' ' ' < "/proc/$old_pid/cmdline" 2>/dev/null)"
    case "$old_cmd" in
        *"$WORKER"*) exit 0 ;;
        *)
            kill "$old_pid" >/dev/null 2>&1
            sleep 1
            ;;
    esac
fi

if command -v nohup >/dev/null 2>&1; then
    nohup "$SH_BIN" "$WORKER" >/dev/null 2>&1 &
else
    "$SH_BIN" "$WORKER" >/dev/null 2>&1 &
fi

worker_pid="$!"
printf '%s\n' "$worker_pid" > "$PID_FILE"
logi "inventory worker launched from post-fs-data: pid=$worker_pid"
