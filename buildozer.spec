# ==============================================================================
#      Buildozer Specification File for WiFi Security Tester - FINAL
# ==============================================================================
#
# هذا الملف هو خارطة الطريق لـ Buildozer لبناء تطبيق الأندرويد.
# يجب أن يكون هذا الملف في الجذر الرئيسي لمشروعك (your_project_root/).
# يحتوي على كل الإعدادات المثلى والمعتمدة مباشرة.
#
# ==============================================================================

[app]

# (Required) Title of your application
title = WiFi Security Tester

# (Required) Package name (يجب أن يكون فريدًا إذا أردت رفعه لمتجر Play Store)
package.name = wifisecuritytester

# (Required) Package domain (عادةً عكس اسم الدومين الخاص بك أو اسم شخصي)
package.domain = org.ahmed.wifitester

# (Required) Source code directory ('.' لتعني المجلد الحالي)
source.dir = .

# (Required) Main Python file to run
# تأكد من أن هذا هو الاسم الصحيح للملف الرئيسي لتطبيقك
main.py = WiFiSecurityTester_Final.py

# (List) List of file extensions to include in the project
# تأكد من تضمين 'ttf' لملفات الخطوط
source.include_exts = py,png,jpg,kv,atlas,json,txt,ttf

# (List) List of directories to exclude from the project
# يمكنك استبعاد المجلدات التي لا تحتاجها في التطبيق النهائي
# source.exclude_dirs = tests, .github, docs

# (Str) Application versioning
# يتم تحديد الإصدار هنا مباشرة (يمكن تحديثه يدويًا أو عبر سكريبت خارجي بسيط)
version = 9.0

# (List) Kivy requirements
# قائمة المكتبات التي يعتمد عليها مشروعك. هذه هي القائمة الصحيحة والمطلوبة.
requirements = python3,kivy,kivymd,reportlab,pyjnius,plyer,https://github.com/kivy-garden/graph/archive/master.zip

# (Str) Custom application icon (e.g. icon.png)
# يجب أن يكون مسار الأيقونة صحيحًا بالنسبة لجذر المشروع
icon.filename = %(source.dir)s/wimax/assets/icons/app_icon.png

# (Str) Presplash background color (for new android AAB)
# presplash.color = #000000

# (Str) Presplash image (مسار الصورة التي تظهر عند بدء التطبيق)
# presplash.filename = %(source.dir)s/wimax/assets/icons/presplash.png

# (Str) Orientation (all, portrait, landscape)
orientation = portrait

# (Boolean) Indicate if the application should be fullscreen or not
fullscreen = 0


[buildozer]

# (Int) Log level (0 = error, 1 = info, 2 = debug)
# تم تعيينه مباشرة إلى 2 للحصول على سجلات مفصلة دائمًا في CI
log_level = 2

# (Int) Display warning if buildozer is run as root (0 = False, 1 = True)
# تم تعيينه مباشرة إلى 0 لمنع التوقف في بيئة CI
warn_on_root = 0

# -----------------------------------------------------------------------------
# Android specific options
# -----------------------------------------------------------------------------
[android]

# (List) Android permissions
# قائمة الصلاحيات الضرورية لعمل التطبيق (الواي فاي، الموقع، التخزين)
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE

# (Int) Android API to use (هذا هو API level الذي ستستهدفه، API 30 جيد)
android.api = 30

# (Int) Minimum API required (أقل إصدار Android يمكن للتطبيق أن يعمل عليه)
android.minapi = 21

# (Int) Android NDK version to use (Buildozer عادة ما يختار الأفضل)
# ✅ تحديث NDK API إلى 26 هنا مباشرة
android.ndk_api = 26

# (Int) Android SDK version to use (Buildozer عادة ما يختار الأفضل)
# android.sdk = 24

# (Str) The Android arch to build for, choices: armeabi-v7a, arm64-v8a, x86, x86_64
android.arch = armeabi-v7a

# (Int) The Android version code. (يجب أن يزداد مع كل تحديث على المتجر)
# يمكنك تحديثه يدويًا هنا، أو استخدام سكريبت بسيط (ليس sed) في الـ workflow إذا أردت أتمتة كاملة
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
# الملفات والمجلدات في هذه القائمة سيتم نسخها بشكل متكرر.
# ✅ هذا هو المفتاح لتضمين مجلد الأدوات والأيقونات والخطوط
android.add_src = wimax/assets

# (Boolean) If True, the app will not be allowed to be installed on an SD card
# android.install_location = internalOnly

# (Boolean) Create an Android App Bundle (aab) (True إذا أردت رفع AAB لـ Play Store)
android.release.aab = False

# (Str) Keystore used to sign the AAB (مطلوب إذا كان android.release.aab = True)
# android.release.keystore = /path/to/keystore.keystore
# android.release.keystore.alias = alias_name
# android.release.keystore.password = keystore_password
# android.release.keystore.alias_password = alias_password
