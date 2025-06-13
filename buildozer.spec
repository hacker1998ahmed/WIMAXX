# ==============================================================================
#      Buildozer Specification File for WiFi Security Tester
# ==============================================================================
#
# هذا الملف هو خارطة الطريق لـ Buildozer لبناء تطبيق الأندرويد.
# يجب أن يكون هذا الملف في الجذر الرئيسي لمشروعك.
#
# ==============================================================================

[app]

# (Required) Title of your application
title = WiFi Security Tester

# (Required) Package name (lowercase, no spaces, no special characters except underscore)
package.name = wifisecuritytester

# (Required) Package domain (e.g., org.kivy, com.example)
package.domain = org.ahmed.wifitester

# (Required) Source code directory ('.' for the current directory)
source.dir = .

# (Required) Main Python file to run (relative to source.dir)
main.py = WiFiSecurityTester_Final.py

# (List) List of file extensions to include in the project
source.include_exts = py,png,jpg,kv,atlas,json,txt,ttf,m4

# (List) List of directories to exclude from the project
source.exclude_dirs = .buildozer, bin, build, venv, __pycache__, .git, .github

# (Str) Application version (e.g., 1.0.0). Will be updated by GitHub Actions.
version = 8.0

# (List) Kivy requirements
# قائمة المكتبات التي يعتمد عليها مشروعك. هذه هي القائمة الصحيحة لمشروعنا.
# تم حذف 'reportlab' لحل مشاكل التجميع.
requirements = kivy,kivymd,pyjnius,plyer,https://github.com/kivy-garden/graph/archive/master.zip

# (Str) Custom application icon (e.g. icon.png). Path relative to source.dir.
icon.filename = wimax/assets/icons/app_icon.png

# (Str) Presplash background color (for Android AAB)
# presplash.color = #000000

# (Str) Presplash image (e.g., presplash.png). Path relative to source.dir.
# presplash.filename = wimax/assets/icons/presplash.png

# (Str) Orientation (all, portrait, landscape)
orientation = portrait

# (Boolean) Indicate if the application should be fullscreen or not
fullscreen = 0


# -----------------------------------------------------------------------------
# Buildozer specific options
# -----------------------------------------------------------------------------
[buildozer]

# (Int) Log level (0 = error, 1 = info, 2 = debug). Will be updated by GitHub Actions.
log_level = 1

# (Int) Display warning if buildozer is run as root (0 = False, 1 = True). Will be updated by GitHub Actions.
warn_on_root = 1

# -----------------------------------------------------------------------------
# Android specific options
# -----------------------------------------------------------------------------
[android]

# (List) Android permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE

# (Int) Android API to use (API 28: معروف بالاستقرار)
android.api = 28

# (Int) Minimum API required (API 21: توافق واسع)
android.minapi = 21

# (Str) Android NDK version to use (NDK 23b: معروف بالاستقرار مع P4A)
android.ndk = 23b

# (Int) Android SDK version to use (لا تحتاج لتحديده عادة)
# android.sdk = 24

# (Str) The Android arch to build for
android.arch = arm64-v8a, armeabi-v7a

# (Int) The Android version code. (Will be updated by GitHub Actions)
android.versioncode = 1

# (List) A list of paths to files that will be copied to the /assets folder
android.add_src = wimax/assets

# (Boolean) Create an Android App Bundle (aab).
android.release.aab = False

# (Str) Keystore used to sign the AAB (for release builds only)
# android.release.keystore = /path/to/keystore.keystore
# android.release.keystore.alias = alias_name
# android.release.keystore.password = keystore_password
# android.release.keystore.alias_password = alias_password
