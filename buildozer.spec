# buildozer.spec

[app]
title = WiFi Security Tester
package.name = wifisecuritytester
package.domain = org.ahmed.wifitester
source.dir = .
main.py = WiFiSecurityTester_Final.py
source.include_exts = py,png,jpg,kv,atlas,json,txt,ttf,m4
source.exclude_dirs = .buildozer, bin, build, venv, __pycache__, .git, .github
version = 8.0

# إعادة pyjnius إلى المتطلبات
requirements = hostpython3,kivy,kivymd,pyjnius,plyer,https://github.com/kivy-garden/graph/archive/master.zip

icon.filename = wimax/assets/icons/app_icon.png
orientation = portrait
fullscreen = 0

[buildozer]
log_level = 1 # سيتم تعديله بواسطة GitHub Actions
warn_on_root = 1 # سيتم تعديله بواسطة GitHub Actions

[android]
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE
android.api = 28
android.minapi = 21

# العودة إلى NDK 23b (الذي كان يسبب مشاكل libffi لكننا سنحاول تجاوزها بـ Docker)
android.ndk = 23b 

android.arch = arm64-v8a, armeabi-v7a
android.versioncode = 1 # سيتم تعديله بواسطة GitHub Actions
android.add_src = wimax/assets
android.release.aab = False

# سنعتمد على Docker Buildozer لإدارة p4a_version
# android.p4a_version = develop 
