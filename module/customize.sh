#!/system/bin/sh

SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=true

ui_print "- anti_dev_pm_zygisk"
ui_print "- Author: geekbyte"
ui_print "- Standalone Zygisk module"
ui_print "- Scope: DuckDetector visibility checks only"
ui_print "- No pm hide, no appops, no ADB/developer toggle changes"
ui_print "- Hooks only DuckDetector process observations"
