#!/system/bin/sh

TAG="AntiDevPmZygisk"
TARGET_PKG="com.eltavine.duckdetector"
MIUI_INVENTORY_OP="10022"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
STATE_FILE="$STATE_DIR/miuiop10022.prev"
PID_FILE="$STATE_DIR/inventory.pid"
POLL_SECONDS=30

logi() {
    log -t "$TAG" "$*"
}

is_miui_like() {
    miui_name="$(getprop ro.miui.ui.version.name 2>/dev/null)"
    mi_os_name="$(getprop ro.mi.os.version.name 2>/dev/null)"
    manufacturer="$(getprop ro.product.manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    brand="$(getprop ro.product.brand 2>/dev/null | tr '[:upper:]' '[:lower:]')"

    [ -n "$miui_name" ] && return 0
    [ -n "$mi_os_name" ] && return 0
    [ "$manufacturer" = "xiaomi" ] && return 0
    [ "$brand" = "xiaomi" ] && return 0
    [ "$brand" = "redmi" ] && return 0
    [ "$brand" = "poco" ] && return 0
    return 1
}

wait_for_boot() {
    i=0
    while [ "$i" -lt 60 ]; do
        [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && return 0
        sleep 2
        i=$((i + 1))
    done
    return 0
}

op_is_unsupported() {
    case "$1" in
        *"Unknown operation"*|*"unknown operation"*|*"Invalid operation"*|*"invalid operation"*|*"Invalid op"*|*"invalid op"*|*"Bad operation"*|*"bad operation"*|*"Error:"*|*"error:"*)
            return 0
            ;;
    esac
    return 1
}

ensure_inventory_appop() {
    if ! pm path "$TARGET_PKG" >/dev/null 2>&1; then
        return 2
    fi

    before="$(cmd appops get "$TARGET_PKG" "$MIUI_INVENTORY_OP" 2>&1)"
    if op_is_unsupported "$before"; then
        logi "inventory appop skip: op $MIUI_INVENTORY_OP unsupported: $before"
        return 3
    fi

    if [ ! -f "$STATE_FILE" ]; then
        printf '%s\n' "$before" > "$STATE_FILE"
    fi

    case "$before" in
        *": allow"*)
            return 0
            ;;
    esac

    if ! cmd appops set "$TARGET_PKG" "$MIUI_INVENTORY_OP" allow >/dev/null 2>&1; then
        logi "inventory appop set failed: op=$MIUI_INVENTORY_OP before=$before"
        return 1
    fi

    after="$(cmd appops get "$TARGET_PKG" "$MIUI_INVENTORY_OP" 2>&1)"
    case "$after" in
        *": allow"*)
            logi "inventory appop set to allow: $after"
            return 0
            ;;
        *)
            logi "inventory appop verify failed: $after"
            return 1
            ;;
    esac
}

inventory_worker() {
    wait_for_boot

    if ! is_miui_like; then
        logi "inventory appop skip: non-MIUI/HyperOS ROM"
        rm -f "$PID_FILE"
        exit 0
    fi

    last_state=""
    while true; do
        ensure_inventory_appop
        rc="$?"
        case "$rc" in
            0)
                if [ "$last_state" != "allow" ]; then
                    current="$(cmd appops get "$TARGET_PKG" "$MIUI_INVENTORY_OP" 2>&1)"
                    logi "inventory appop confirmed allow: $current"
                    last_state="allow"
                fi
                ;;
            2)
                if [ "$last_state" != "missing" ]; then
                    logi "inventory appop waiting: $TARGET_PKG is not installed"
                    last_state="missing"
                fi
                ;;
            3)
                rm -f "$PID_FILE"
                exit 0
                ;;
            *)
                last_state="retry"
                ;;
        esac
        sleep "$POLL_SECONDS"
    done
}

mkdir -p "$STATE_DIR" >/dev/null 2>&1
old_pid="$(cat "$PID_FILE" 2>/dev/null)"
if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    logi "inventory appop worker already running: pid=$old_pid"
    exit 0
fi

inventory_worker >/dev/null 2>&1 &
worker_pid="$!"
printf '%s\n' "$worker_pid" > "$PID_FILE"
logi "inventory appop worker started: pid=$worker_pid"
