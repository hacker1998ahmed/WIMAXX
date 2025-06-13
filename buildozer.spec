# ==============================================================================
#      Buildozer Specification File for WiFi Security Tester (NO PYJNIUS)
# ==============================================================================
#
# هذا الملف تم تعديله لحذف 'pyjnius' لتجاوز مشاكل 'libffi'.
# هذا قد يعطل بعض الوظائف التي تعتمد على التفاعل العميق مع Android.
#
# ==============================================================================

[app]

# (Required) Title of your application
title = WiFi Security Tester

# (Required) Package name
package.name = wifisecuritytester

# (Required) Package domain
package.domain = org.ahmed.wifitester

# (Required) Source code directory
source.dir = .

# (Required) Main Python file to run
main.py = WiFiSecurityTester_Final.py

# (List) List of file extensions to include
source.include_exts = py,png,jpg,kv,atlas,json,txt,ttf,m4

# (List) List of directories to exclude
source.exclude_dirs = .buildozer, bin, build, venv, __pycache__, .git, .github

# (Str) Application version
version = 8.0

# (List) Kivy requirements (pyjnius and hostpython3 have been removed)
requirements = kivy,kivymd,plyer,https://github.com/kivy-garden/graph/archive/master.zip

# (Str) Custom application icon
icon.filename = wimax/assets/icons/app_icon.png

# (Str) Orientation
orientation = portrait

# (Boolean) Fullscreen
fullscreen = 0


[buildozer]

# Log level (will be updated by GitHub Actions)
log_level = 1

# Warn on root (will be updated by GitHub Actions)
warn_on_root = 1


[android]

# Android permissions (some may no longer be strictly needed without pyjnius, but keeping for safety)
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE

# Android API to use
android.api = 28

# Minimum API required
android.minapi = 21

# Android NDK version to use (less critical now, but good to keep a stable one)
android.ndk = 21e # Or simply remove this line to let Buildozer choose

# The Android arch to build for
android.arch = arm64-v8a, armeabi-v7a

# Android version code (will be updated by GitHub Actions)
android.versioncode = 1

# Files to be copied to the /assets folder
android.add_src = wimax/assets

# Create an Android App Bundle (aab)
android.release.aab = False
