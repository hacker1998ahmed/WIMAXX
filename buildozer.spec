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
# تم تحديث هذه القائمة لحذف 'reportlab' وضمان التوافق.
# 'python3' هو إصدار المفسر وليس مكتبة PIP
requirements = kivy,kivymd,pyjnius,plyer,https://github.com/kivy-garden/graph/archive/master.zip

# (Str) Custom application icon (e.g. icon.png). Path relative to source.dir.
# تأكد من وجود هذا الملف في المسار المحدد
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
# قائمة الصلاحيات الضرورية لعمل التطبيق (الإنترنت، الواي فاي، الموقع، التخزين، خدمة الواجهة الأمامية)
# ACCESS_FINE_LOCATION و ACCESS_COARSE_LOCATION مهمتان لفحص الواي فاي الحديث
# FOREGROUND_SERVICE قد تكون ضرورية للعمليات الطويلة في الخلفية
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE

# (Int) Android API to use (هذا الإصدار 28 أكثر استقرارًا لـ pyjnius والمكتبات الأخرى)
android.api = 28

# (Int) Minimum API required (API 21 هو خيار جيد للتوافق الأوسع)
android.minapi = 21

# (Str) Android NDK version to use (مثل r21e, r23b, r25b). r23b غالبًا ما يكون مستقرًا.
android.ndk = 23b

# (Int) Android SDK version to use (عادة لا تحتاج لتحديده، Buildozer يختار الأحدث)
# android.sdk = 24

# (Str) The Android arch to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
# arm64-v8a هو المعيار للأجهزة الحديثة، و armeabi-v7a للأجهزة الأقدم 32 بت.
android.arch = arm64-v8a, armeabi-v7a

# (Int) The Android version code. (Each update on the store should have a higher version code)
# سيتم تحديثه بواسطة GitHub Actions بناءً على رقم تشغيل الـ Workflow
android.versioncode = 1

# (List) A list of paths to files that will be copied to the /assets folder
# Files and directories in this list will be recursively copied.
# ✅ هذه هي الخطوة الأهم: تضمين مجلد الأدوات والأيقونات داخل حزمة التطبيق
android.add_src = wimax/assets

# (Boolean) Create an Android App Bundle (aab). يمكن تفعيله لاحقًا للرفع إلى متجر Google Play.
android.release.aab = False

# (Str) Keystore used to sign the AAB (for release builds only)
# android.release.keystore = /path/to/keystore.keystore
# android.release.keystore.alias = alias_name
# android.release.keystore.password = keystore_password
# android.release.keystore.alias_password = alias_password
