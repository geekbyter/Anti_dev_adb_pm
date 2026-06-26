#!/system/bin/sh

SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=true

ui_print "- anti_dev_pm_zygisk"
ui_print "- Author: geekbyte"
ui_print "- Standalone Zygisk module"
ui_print "- Scope: DuckDetector visibility checks only"
ui_print "- Grants DuckDetector MIUI/HyperOS installed-app inventory appop when present"
ui_print "- No pm hide, no ADB/developer toggle changes"
ui_print "- Hooks only DuckDetector process observations"

set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644

TARGET_PKG="com.eltavine.duckdetector"
MIUI_INVENTORY_OP="10022"
STATE_DIR="/data/adb/anti_dev_pm_zygisk"
STATE_FILE="$STATE_DIR/miuiop10022.prev"

miui_name="$(getprop ro.miui.ui.version.name 2>/dev/null)"
mi_os_name="$(getprop ro.mi.os.version.name 2>/dev/null)"
brand="$(getprop ro.product.brand 2>/dev/null | tr '[:upper:]' '[:lower:]')"

if [ -n "$miui_name" ] || [ -n "$mi_os_name" ] || [ "$brand" = "xiaomi" ] || [ "$brand" = "redmi" ] || [ "$brand" = "poco" ]; then
  if pm path "$TARGET_PKG" >/dev/null 2>&1; then
    before="$(cmd appops get "$TARGET_PKG" "$MIUI_INVENTORY_OP" 2>&1)"
    case "$before" in
      *"Unknown operation"*|*"unknown operation"*|*"Invalid operation"*|*"invalid operation"*|*"Invalid op"*|*"invalid op"*|*"Bad operation"*|*"bad operation"*|*"Error:"*|*"error:"*)
        ui_print "- MIUI inventory appop unsupported on this ROM"
        ;;
      *)
        mkdir -p "$STATE_DIR" >/dev/null 2>&1
        [ -f "$STATE_FILE" ] || printf '%s\n' "$before" > "$STATE_FILE"
        if cmd appops set "$TARGET_PKG" "$MIUI_INVENTORY_OP" allow >/dev/null 2>&1; then
          ui_print "- MIUI inventory appop set: $TARGET_PKG op $MIUI_INVENTORY_OP allow"
        else
          ui_print "- MIUI inventory appop set failed; service worker will retry after reboot"
        fi
        ;;
    esac
  else
    ui_print "- DuckDetector not installed; service worker will wait after reboot"
  fi
fi
