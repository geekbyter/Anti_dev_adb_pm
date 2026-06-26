#!/system/bin/sh

TAG="AntiDevPmZygisk"
MIUI_INVENTORY_OP="10022"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
PID_FILE="$STATE_DIR/inventory.pid"
CONFIG_FILE="$STATE_DIR/inventory.conf"
TARGETS_FILE="$STATE_DIR/target.txt"
LEGACY_TARGETS_FILE="$STATE_DIR/inventory_targets.list"
TMP_TARGETS="$STATE_DIR/current_targets.tmp"
PM_BIN="/system/bin/pm"
CMD_BIN="/system/bin/cmd"
GETPROP_BIN="/system/bin/getprop"
LOG_BIN="/system/bin/log"
SORT_BIN="/system/bin/sort"
MV_BIN="/system/bin/mv"

POLL_SECONDS=5
BURST_PASSES=60
BURST_SLEEP_SECONDS=1
FORCE_NON_MIUI=0

logi() {
    "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

is_miui_like() {
    miui_name="$("$GETPROP_BIN" ro.miui.ui.version.name 2>/dev/null)"
    mi_os_name="$("$GETPROP_BIN" ro.mi.os.version.name 2>/dev/null)"
    manufacturer="$("$GETPROP_BIN" ro.product.manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    brand="$("$GETPROP_BIN" ro.product.brand 2>/dev/null | tr '[:upper:]' '[:lower:]')"

    [ -n "$miui_name" ] && return 0
    [ -n "$mi_os_name" ] && return 0
    [ "$manufacturer" = "xiaomi" ] && return 0
    [ "$brand" = "xiaomi" ] && return 0
    [ "$brand" = "redmi" ] && return 0
    [ "$brand" = "poco" ] && return 0
    return 1
}

load_config() {
    [ -f "$CONFIG_FILE" ] || return 0

    while IFS='=' read -r key value; do
        case "$key" in
            ""|\#*) continue ;;
            poll_seconds) [ "$value" -ge 2 ] 2>/dev/null && POLL_SECONDS="$value" ;;
            force_non_miui) [ "$value" = "1" ] && FORCE_NON_MIUI=1 || FORCE_NON_MIUI=0 ;;
        esac
    done < "$CONFIG_FILE"
}

wait_for_boot() {
    i=0
    while [ "$i" -lt 90 ]; do
        [ "$("$GETPROP_BIN" sys.boot_completed 2>/dev/null)" = "1" ] && return 0
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

package_exists() {
    "$PM_BIN" path --user 0 "$1" </dev/null >/dev/null 2>&1 ||
        "$PM_BIN" path "$1" </dev/null >/dev/null 2>&1
}

state_file_for_pkg() {
    printf '%s/%s.prev\n' "$STATE_DIR" "$1"
}

ensure_inventory_appop_for_pkg() {
    pkg="$1"
    if ! package_exists "$pkg"; then
        logi "inventory appop package missing: pkg=$pkg"
        return 2
    fi

    before="$("$CMD_BIN" appops get "$pkg" "$MIUI_INVENTORY_OP" </dev/null 2>&1)"
    if op_is_unsupported "$before"; then
        logi "inventory appop unsupported: pkg=$pkg output=$before"
        return 3
    fi

    prev_file="$(state_file_for_pkg "$pkg")"
    if [ ! -f "$prev_file" ]; then
        printf '%s\n' "$before" > "$prev_file"
    fi

    case "$before" in
        *": allow"*) return 0 ;;
    esac

    # MIUI/HyperOS can rewrite MIUIOP(10022) during boot and after permission UI
    # changes, so verify the mode instead of trusting the set command exit code.
    # 不要让 cmd 继承 current_targets.tmp 作为 stdin，否则 system_server
    # 会尝试读取 adb_data_file 并触发 SELinux deny，导致 appops 静默失败。
    set_out="$("$CMD_BIN" appops set "$pkg" "$MIUI_INVENTORY_OP" allow </dev/null 2>&1)"
    set_rc="$?"
    if [ "$set_rc" = "0" ]; then
        after="$("$CMD_BIN" appops get "$pkg" "$MIUI_INVENTORY_OP" </dev/null 2>&1)"
        case "$after" in
            *": allow"*)
                logi "inventory appop allow: pkg=$pkg previous=$before"
                return 0
                ;;
        esac
        logi "inventory appop verify failed: pkg=$pkg after=$after"
        return 1
    fi

    logi "inventory appop set failed: pkg=$pkg rc=$set_rc output=$set_out previous=$before"
    return 1
}

append_target() {
    pkg="$1"
    [ -n "$pkg" ] || return 0
    printf '%s\n' "$pkg" >> "$TMP_TARGETS"
}

append_targets_from_file() {
    file="$1"
    [ -f "$file" ] || return 0

    while read -r pkg; do
        case "$pkg" in
            ""|\#*) continue ;;
            *) append_target "$pkg" ;;
        esac
    done < "$file"
}

build_targets() {
    rm -f "$TMP_TARGETS"
    touch "$TMP_TARGETS"

    append_target "com.eltavine.duckdetector"
    append_targets_from_file "$TARGETS_FILE"
    append_targets_from_file "$LEGACY_TARGETS_FILE"

    "$SORT_BIN" -u "$TMP_TARGETS" 2>/dev/null > "$TMP_TARGETS.sorted" &&
        "$MV_BIN" "$TMP_TARGETS.sorted" "$TMP_TARGETS"
}

run_pass() {
    load_config

    if ! is_miui_like && [ "$FORCE_NON_MIUI" != "1" ]; then
        logi "inventory worker skip: non-MIUI/HyperOS ROM"
        return 3
    fi

    build_targets

    unsupported_seen=0
    handled=0
    failed=0
    missing=0
    while IFS= read -r pkg <&3 || [ -n "$pkg" ]; do
        [ -n "$pkg" ] || continue
        ensure_inventory_appop_for_pkg "$pkg"
        rc="$?"
        [ "$rc" = "0" ] && handled=$((handled + 1))
        [ "$rc" = "3" ] && unsupported_seen=1
        [ "$rc" = "2" ] && missing=$((missing + 1))
        [ "$rc" = "1" ] && failed=$((failed + 1))
    done 3< "$TMP_TARGETS"

    if [ "$handled" = "0" ] && [ "$unsupported_seen" = "1" ] &&
        [ "$failed" = "0" ] && [ "$missing" = "0" ]; then
        logi "inventory worker skip: appop $MIUI_INVENTORY_OP unsupported"
        return 3
    fi

    logi "inventory worker pass: targets=$handled failed=$failed missing=$missing unsupported=$unsupported_seen"
    return 0
}

mkdir -p "$STATE_DIR" >/dev/null 2>&1

if [ ! -f "$TARGETS_FILE" ]; then
    cat > "$TARGETS_FILE" <<'EOF'
# Add extra packages here, one package name per line.
# DuckDetector is always handled even if this file is empty.
EOF
fi

if [ "$1" = "--once" ]; then
    run_pass
    exit 0
fi

printf '%s\n' "$$" > "$PID_FILE"
wait_for_boot

pass=0
while true; do
    run_pass
    rc="$?"
    [ "$rc" = "3" ] && break

    if [ "$pass" -lt "$BURST_PASSES" ]; then
        sleep "$BURST_SLEEP_SECONDS"
    else
        sleep "$POLL_SECONDS"
    fi

    pass=$((pass + 1))
done

rm -f "$PID_FILE"
