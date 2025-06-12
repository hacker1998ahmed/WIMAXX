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

# (Required) Package name
package.name = wifisecuritytester

# (Required) Package domain (usually reverse domain name)
package.domain = org.ahmed.wifitester

# (Required) Source code directory ('.' for the current directory)
source.dir = .

# (Required) Main Python file to run
# تأكد من أن هذا هو الاسم الصحيح للملف الرئيسي لتطبيقك
main.py = WiFiSecurityTester_Final.py

# (List) List of file extensions to include in the project
source.include_exts = py,png,jpg,kv,atlas,json,txt,ttf

# (List) List of directories to exclude from the project
# source.exclude_dirs = tests, .github, etc.

# (Str) Application versioning
version = 8.0

# (List) Kivy requirements
# قائمة المكتبات التي يعتمد عليها مشروعك. هذه هي القائمة الصحيحة لمشروعنا.
requirements = python3,kivy,kivymd,reportlab,pyjnius,plyer,https://github.com/kivy-garden/graph/archive/master.zip

# (Str) Custom application icon (e.g. icon.png)
icon.filename = %(source.dir)s/wimax/assets/icons/app_icon.png

# (Str) Presplash background color (for new android AAB)
# presplash.color = #000000

# (Str) Presplash image
# presplash.filename = %(source.dir)s/wimax/assets/icons/presplash.png

# (Str) Orientation (all, portrait, landscape)
orientation = portrait

# (Boolean) Indicate if the application should be fullscreen or not
fullscreen = 0


[buildozer]

# (Int) Log level (0 = error, 1 = info, 2 = debug)
# يتم تعديله إلى 2 بواسطة GitHub Actions
log_level = 1

# (Int) Display warning if buildozer is run as root (0 = False, 1 = True)
# يتم تعديله إلى 0 بواسطة GitHub Actions
warn_on_root = 1

# -----------------------------------------------------------------------------
# Android specific options
# -----------------------------------------------------------------------------
[android]

# (List) Android permissions
# قائمة الصلاحيات الضرورية لعمل التطبيق (الواي فاي، الموقع، التخزين)
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE

# (Int) Android API to use
android.api = 30

# (Int) Minimum API required
android.minapi = 21

# (Int) Android NDK version to use
# android.ndk = 19c

# (Int) Android SDK version to use
# android.sdk = 24

# (Str) The Android arch to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
android.arch = armeabi-v7a

# (Int) The Android version code. (Each update on the store should have a higher version code)
# سيتم تحديثه بواسطة GitHub Actions
android.versioncode = 1

# (List) The Android libraries to be included (.so files)
# android.add_libs_armeabi_v7a = libs/armeabi-v7a/*.so

# (List) The jars to be included in the public class path
# android.add_jars = libs/android/special.jar

# (List) A list of paths to java source files to include
# android.add_java_src = src/java

# (List) A list of paths to python code that will be added to the python path
# android.python_path = ./src

# (List) A list of paths to files that will be copied to the /assets folder
# Files and directories in this list will be recursively copied.
# ✅ هذه هي الخطوة الأهم: تضمين مجلد الأدوات والأيقونات داخل حزمة التطبيق
android.add_src = wimax/assets

# (Boolean) If True, the app will not be allowed to be installed on an SD card
# android.install_location = internalOnly

# (Boolean) Create an Android App Bundle (aab)
# buildozer android release aab
android.release.aab = False

# (Str) Keystore used to sign the AAB
# android.release.keystore = /path/to/keystore.keystore
# android.release.keystore.alias = alias_name
# android.release.keystore.password = keystore_password
# android.release.keystore.alias_password = alias_password