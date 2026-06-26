#!/system/bin/sh

SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=true
LATESTARTSERVICE=true

ui_print "- anti_dev_pm_zygisk"
ui_print "- Author: geekbyte"
ui_print "- Standalone Zygisk module"
ui_print "- Scope: DuckDetector visibility checks only"
ui_print "- Grants DuckDetector MIUI/HyperOS installed-app inventory appop when present"
ui_print "- No pm hide, no ADB/developer toggle changes"
ui_print "- Hooks only DuckDetector process observations"

set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/inventory_worker.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644

STATE_DIR="/data/adb/anti_dev_pm_zygisk"
mkdir -p "$STATE_DIR" >/dev/null 2>&1
/system/bin/cp -f "$MODPATH/inventory_worker.sh" "$STATE_DIR/inventory_worker.sh" >/dev/null 2>&1
/system/bin/chmod 0755 "$STATE_DIR/inventory_worker.sh" >/dev/null 2>&1

mkdir -p /data/adb/service.d >/dev/null 2>&1
cat > /data/adb/service.d/anti_dev_pm_inventory.sh <<'EOF'
#!/system/bin/sh

STATE_DIR="/data/adb/anti_dev_pm_zygisk"
WORKER="$STATE_DIR/inventory_worker.sh"
PID_FILE="$STATE_DIR/inventory.pid"
TAG="AntiDevPmZygisk"
SH_BIN="/system/bin/sh"
LOG_BIN="/system/bin/log"

logi() {
  "$LOG_BIN" -t "$TAG" "$*" 2>/dev/null
}

mkdir -p "$STATE_DIR" >/dev/null 2>&1

old_pid="$(cat "$PID_FILE" 2>/dev/null)"
if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
  old_cmd="$(tr '\0' ' ' < "/proc/$old_pid/cmdline" 2>/dev/null)"
  case "$old_cmd" in
    *"$WORKER"*)
      logi "inventory service.d worker already running: pid=$old_pid"
      exit 0
      ;;
    *)
      kill "$old_pid" >/dev/null 2>&1
      sleep 1
      ;;
  esac
fi

if [ -r "$WORKER" ]; then
  if command -v nohup >/dev/null 2>&1; then
    nohup "$SH_BIN" "$WORKER" >/dev/null 2>&1 &
  else
    "$SH_BIN" "$WORKER" >/dev/null 2>&1 &
  fi
  printf '%s\n' "$!" > "$PID_FILE"
  logi "inventory service.d worker launched: pid=$!"
else
  logi "inventory service.d worker missing: $WORKER"
fi
EOF
chmod 0755 /data/adb/service.d/anti_dev_pm_inventory.sh >/dev/null 2>&1

if /system/bin/sh "$STATE_DIR/inventory_worker.sh" --once >/dev/null 2>&1; then
  ui_print "- MIUI inventory appop pass completed"
else
  ui_print "- MIUI inventory appop pass deferred to boot worker"
fi
