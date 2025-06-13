# ==============================================================================
#      WiFi Security Tester - Final Complete and Corrected Version 9.0 (Android - NO PYJNIUS)
#              Developed by: Ahmed Mustafa Ibrahim (GOGOM8870@GMAIL.COM)
# ==============================================================================
#
# هذا الملف هو النسخة النهائية والمصححة بالكامل لتطبيق اختبار أمان الواي فاي.
# تم تعديله ليعمل على أندرويد باستخدام Kivy/KivyMD.
#
# **ملاحظة هامة:** تم تعطيل مكتبة 'pyjnius' هنا لتجاوز مشاكل التجميع المتعلقة بـ 'libffi'.
# هذا يعني أن الوظائف التي تتطلب صلاحيات Root أو التفاعل العميق مع نظام Android
# (مثل فحص الواي فاي المتقدم، التحكم في وضع المراقبة، تشغيل أدوات CLI) لن تعمل.
# سيظل التطبيق يُبنى ويُشغّل، ولكن مع وظائف محدودة.
#
# ==============================================================================

import os
import sys
import subprocess
import threading
import json
import time
from datetime import datetime
from functools import partial

# --- Kivy, KivyMD & Garden Imports ---
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.properties import StringProperty, ListProperty, DictProperty, NumericProperty, ObjectProperty
from kivy.clock import Clock
from kivy.utils import platform, get_color_from_hex
from kivy.core.window import Window
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.gridlayout import MDGridLayout # Added for explicit import
from kivymd.uix.label import MDLabel, MDIcon
from kivymd.uix.button import MDRaisedButton, MDFloatingActionButton, MDIconButton, MDFlatButton
from kivymd.uix.card import MDCard
from kivymd.uix.list import MDList, TwoLineAvatarIconListItem, IconLeftWidget, ThreeLineAvatarIconListItem
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.textfield import MDTextField
from kivymd.uix.spinner import MDSpinner
from kivymd.uix.snackbar import Snackbar
from kivymd.uix.dialog import MDDialog
from kivymd.uix.tab import MDTabs, MDTabsBase
from kivymd.uix.floatlayout import MDFloatLayout
from kivy_garden.graph import Graph, MeshLinePlot

# --- Plyer for File Chooser ---
try:
    from plyer import filechooser
except ImportError:
    filechooser = None # Placeholder if plyer is not installed

# --- JNIus for Android Specific APIs (DISABLED) ---
# تم تعطيل JNIus هنا لغرض البناء وتجاوز مشاكل libffi
autoclass = None
PythonActivity = None
activity = None
Context = None
WifiManager = None
Permission = None
# في بيئة الإنتاج أو عندما تكون مشكلة libffi محلولة،
# يمكنك إعادة تفعيل هذا القسم:
# if platform == 'android':
#     try:
#         from jnius import autoclass
#         from android.permissions import request_permissions, Permission
#         PythonActivity = autoclass('org.kivy.android.PythonActivity')
#         activity = PythonActivity.mActivity
#         Context = autoclass('android.content.Context')
#         WifiManager = autoclass('android.net.wifi.WifiManager')
#     except ImportError:
#         pass # Remain None if not found


# --- ReportLab for PDF Reports (Dummy if not installed) ---
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_LEFT, TA_CENTER # Added for explicit import
except ImportError:
    class SimpleDocTemplate:
        def __init__(self, filename): pass
        def build(self, story): pass
    class Paragraph:
        def __init__(self, text, style): pass
    class Spacer:
        def __init__(self, width, height): pass
    def getSampleStyleSheet():
        class Styles:
            def __getitem__(self, key): return None
            def add(self, style): pass
        return Styles()
    ParagraphStyle = object
    TA_LEFT = 0
    TA_CENTER = 1


# ==============================================================================
# 1. Localization & Translation System
# ==============================================================================
LANGUAGES = {
    "en": {
        "app_title": "WiFi Security Tester",
        "home": "Home", "discovery": "Discovery", "exploitation": "Exploitation", "tools": "Tools", "settings": "Settings", "about": "About",
        "status": "System Status", "root_access": "Root Access", "network_status": "Network Status", "quick_actions": "Quick Actions",
        "scan_networks": "Scan Networks", "checking": "Checking...", "granted": "Granted", "denied": "Denied", "connected_to": "Connected to: {}",
        "disconnected": "Disconnected", "wifi_disabled": "WiFi is disabled.", "start_full_scan": "Start Full Scan",
        "found_networks": "Found {} networks. Analyzing...", "no_networks": "No networks found or permissions denied.",
        "all_networks": "All", "wps_enabled": "WPS Enabled", "wpa_wpa2": "WPA/WPA2", "open_networks": "Open",
        "monitor_mode_control": "Monitor Mode Control", "original_interface": "Original Interface (e.g., wlan0)",
        "start_monitor_mode": "Start Monitor", "stop_monitor_mode": "Stop Monitor",
        "wps_attacks": "WPS Attacks", "wpa_attacks": "WPA/WPA2 Attacks", "deauth_attack": "Deauthentication Attack",
        "scan_for_wps": "Scan (wash)", "start_reaver": "Reaver Attack (Pixie-Dust)", "capture_handshake": "Capture Handshake",
        "start_aircrack_attack": "Dictionary Attack (Aircrack-ng)", "start_evil_twin": "Start Evil Twin (airbase-ng)",
        "target_bssid": "Target BSSID", "target_channel": "Target Channel", "monitor_interface": "Monitor Interface",
        "output_file_prefix": "Output File Prefix", "handshake_cap_file": "Handshake File (.cap)", "wordlist_file_path": "Wordlist Path",
        "choose_wordlist": "Choose Wordlist", "stop_all_attacks": "Stop All Attacks", "report_generated": "Report generated: {}", "report_failed": "Failed to generate report: {}",
        "export_pdf_report": "Export PDF Report", "language": "Language", "theme": "Theme", "dark_mode": "Dark Mode",
        "light_mode": "Light Mode", "check_tool_status": "Check Tool Status", "tool_ready": "Ready", "tool_missing": "Missing or not executable",
        "attack_options_for": "Attack Options for {}", "vulnerabilities": "Vulnerabilities: {}", "about_title": "About WiFi Security Tester", "version": "Version", "developer": "Developer",
        "contact": "Contact", "phone": "Phone", "email": "Email", "disclaimer": "Disclaimer",
        "disclaimer_text": "This application is intended for educational and security testing purposes only on networks you own or have explicit permission to test. Unauthorized use is illegal. The developer is not responsible for any misuse.",
        "signal_dbm": "Signal (dBm)", "network": "Network", "current_active_attacks": "Currently Active Attacks",
        "target_client": "Target Client (optional, FF:..:FF)", "ssid_to_clone": "SSID to Clone",
        "bssid_iface_required": "BSSID and Interface are required.", "all_handshake_fields_required": "All handshake fields are required.",
        "cap_wordlist_required": "Handshake file and Wordlist are required.", "wordlist_not_found": "Wordlist file not found.",
        "handshake_not_found": "Handshake capture file not found.", "ssid_iface_required": "SSID and Interface are required."
    },
    "ar": {
        "app_title": "مختبر أمان الواي فاي",
        "home": "الرئيسية", "discovery": "الاكتشاف", "exploitation": "الاستغلال", "tools": "الأدوات", "settings": "الإعدادات", "about": "حول",
        "status": "حالة النظام", "root_access": "صلاحيات الروت", "network_status": "حالة الشبكة", "quick_actions": "إجراءات سريعة",
        "scan_networks": "فحص الشبكات", "checking": "جاري التحقق...", "granted": "ممنوح", "denied": "مرفوض", "connected_to": "متصل بـ: {}",
        "disconnected": "غير متصل", "wifi_disabled": "الواي فاي معطل.", "start_full_scan": "ابدأ الفحص الكامل",
        "found_networks": "تم العثور على {} شبكة. جاري التحليل...", "no_networks": "لم يتم العثور على شبكات أو تم رفض الأذونات.",
        "all_networks": "الكل", "wps_enabled": "WPS مفعّل", "wpa_wpa2": "WPA/WPA2", "open_networks": "مفتوحة",
        "monitor_mode_control": "التحكم في وضع المراقبة", "original_interface": "الواجهة الأصلية (مثال: wlan0)",
        "start_monitor_mode": "بدء المراقبة", "stop_monitor_mode": "إيقاف المراقبة",
        "wps_attacks": "هجمات WPS", "wpa_attacks": "هجمات WPA/WPA2", "deauth_attack": "هجوم قطع الاتصال",
        "scan_for_wps": "فحص (wash)", "start_reaver": "هجوم Reaver (Pixie-Dust)", "capture_handshake": "التقاط المصافحة",
        "start_aircrack_attack": "هجوم القاموس (Aircrack-ng)", "start_evil_twin": "بدء التوأم الشرير (airbase-ng)",
        "target_bssid": "BSSID الهدف", "target_channel": "قناة الهدف", "monitor_interface": "واجهة المراقبة",
        "output_file_prefix": "اسم ملف الإخراج", "handshake_cap_file": "ملف المصافحة (.cap)", "wordlist_file_path": "مسار قائمة الكلمات",
        "choose_wordlist": "اختر قائمة الكلمات", "stop_all_attacks": "إيقاف كل الهجمات", "report_generated": "تم إنشاء التقرير: {}", "report_failed": "فشل إنشاء التقرير: {}",
        "export_pdf_report": "تصدير تقرير PDF", "language": "اللغة", "theme": "المظهر", "dark_mode": "الوضع الداكن",
        "light_mode": "الوضع الفاتح", "check_tool_status": "فحص حالة الأدوات", "tool_ready": "جاهزة", "tool_missing": "مفقودة أو غير قابلة للتنفيذ",
        "attack_options_for": "خيارات الهجوم على {}", "vulnerabilities": "الثغرات: {}", "about_title": "حول مختبر أمان الواي فاي", "version": "الإصدار", "developer": "المطور",
        "contact": "للتواصل", "phone": "الهاتف", "email": "البريد الإلكتروني", "disclaimer": "إخلاء مسؤولية",
        "disclaimer_text": "هذا التطبيق مخصص للأغراض التعليمية واختبار الأمان فقط على الشبكات التي تملكها أو لديك إذن صريح لاختبارها. الاستخدام غير المصرح به غير قانوني. المطور غير مسؤول عن أي سوء استخدام.",
        "signal_dbm": "الإشارة (dBm)", "network": "الشبكة", "current_active_attacks": "الهجمات النشطة الحالية",
        "target_client": "العميل الهدف (اختياري، FF:..:FF)", "ssid_to_clone": "SSID للاستنساخ",
        "bssid_iface_required": "حقل BSSID والواجهة مطلوبان.", "all_handshake_fields_required": "جميع حقول المصافحة مطلوبة.",
        "cap_wordlist_required": "ملف المصافحة وقائمة الكلمات مطلوبان.", "wordlist_not_found": "ملف قائمة الكلمات غير موجود.",
        "handshake_not_found": "ملف المصافحة غير موجود.", "ssid_iface_required": "حقل SSID والواجهة مطلوبان."
    }
}

class Translator:
    def __init__(self, language="en"): self.set_language(language)
    def set_language(self, language): self.language, self.translations = language, LANGUAGES.get(language, LANGUAGES["en"])
    def get(self, key): return self.translations.get(key, key)
tr = Translator()

# ==============================================================================
# 2. Managers & Helpers
# ==============================================================================

class LogPanel(ScrollView):
    """Kivy widget to display logs."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.log_label = MDLabel(
            text="",
            adaptive_height=True,
            markup=True,
            font_style="Code",
            theme_text_color="Custom"
        )
        self.add_widget(self.log_label)
    
    def update_log(self, log_entry):
        # Colorize log entries for better readability
        if "Error" in log_entry or "Denied" in log_entry or "failed" in log_entry:
            color = "F44336" # Red
        elif "Success" in log_entry or "Granted" in log_entry or "finished" in log_entry:
            color = "4CAF50" # Green
        elif "Warning" in log_entry or "Starting" in log_entry:
            color = "FFC107" # Yellow
        else:
            color = "A9B7C6" # Default log color (light grey/blue)
        
        self.log_label.text += f"[color=#{color}]{log_entry}[/color]\n"
        self.scroll_y = 0 # Auto-scroll to bottom

class LogManager:
    """Manages logging to a file and a UI widget."""
    def __init__(self, log_widget_instance): # Accept the widget instance
        self.log_widget = log_widget_instance # Store the actual LogPanel instance
        self.log_file = os.path.join(App.get_running_app().user_data_dir, "app_log.txt")
        self.add_log(tr.get("app_title") + " LogManager initialized.")

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(f"LOG: {log_entry}")  # For console debugging
        # Update UI widget
        Clock.schedule_once(lambda dt: self.log_widget.update_log(log_entry))
        # Append to file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')

def check_root():
    """Checks for root access by running 'su -c id'."""
    if platform != 'android':
        return True, tr.get("granted") # Assume rooted on desktop for development/testing
    # Actual Android root check (disabled in this build without Pyjnius)
    return False, tr.get("denied") # Default to denied if Pyjnius is not active for check

class ToolExecutor:
    """Executes external tools with or without root, asynchronously."""
    def __init__(self, log_manager, app_data_dir):
        self.log_manager = log_manager
        self.app_data_dir = app_data_dir
        self.tools_path = os.path.join(app_data_dir, 'tools') # Path where tools are extracted
        self.active_processes = {} # To keep track of running processes by key

    def execute(self, command_list, requires_root=False, callback=None, process_key=None):
        if process_key and process_key in self.active_processes and self.active_processes[process_key].poll() is None:
            self.log_manager.add_log(f"Process '{process_key}' is already running."); return

        # Disabled root operations and CLI tools on Android without Pyjnius
        if platform == 'android' and requires_root:
            self.log_manager.add_log("Error: Root operations and CLI tools are disabled in this Android build (missing Pyjnius). Command skipped.")
            if callback: Clock.schedule_once(lambda dt: callback(f"Error: Command '{command_list[0]}' skipped (Root/Pyjnius disabled).", True))
            return
        if platform == 'android' and command_list[0] in ['iwconfig', 'ip', 'netsh', 'wash', 'airmon-ng', 'airodump-ng', 'reaver', 'aircrack-ng', 'aireplay-ng', 'airbase-ng', 'busybox', 'mdk3']:
            self.log_manager.add_log(f"Warning: Tool '{command_list[0]}' is likely disabled in this Android build without Pyjnius. Command may fail.")
            # Still attempt execution to show error, but expect failure
            
        def run_in_thread():
            try:
                tool_name = command_list[0]
                tool_path = os.path.join(self.tools_path, tool_name)

                # Use embedded tool if exists, otherwise assume system path
                if os.path.exists(tool_path):
                    final_command = [tool_path] + command_list[1:]
                else:
                    final_command = command_list
                    self.log_manager.add_log(f"Tool '{tool_name}' not in assets, trying system PATH.")
                
                # For root commands (only on Linux/macOS as Android is disabled here)
                if requires_root and platform.system() == "Linux":
                    final_command = ['sudo'] + final_command
                    self.log_manager.add_log("Admin privileges required. Ensure sudo is configured.")

                self.log_manager.add_log(f"Executing: {' '.join(final_command)}")
                
                process = subprocess.Popen(
                    final_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, # Merge stderr into stdout for easier logging
                    text=True, bufsize=1, encoding='utf-8', errors='replace'
                )
                
                if process_key: self.active_processes[process_key] = process

                for line in iter(process.stdout.readline, ''):
                    if callback: Clock.schedule_once(lambda dt, l=line.strip(): callback(l, False))
                
                process.stdout.close()
                return_code = process.wait()

                if process_key and process_key in self.active_processes:
                    del self.active_processes[process_key]

                if callback:
                    if return_code != 0:
                        Clock.schedule_once(lambda dt: callback(f"Process '{command_list[0]}' finished with exit code {return_code}. Error.", True))
                    else:
                        Clock.schedule_once(lambda dt: callback(f"Process '{command_list[0]}' finished successfully.", False))

            except FileNotFoundError:
                err_msg = f"Error: Command '{command_list[0]}' not found."
                self.log_manager.add_log(err_msg)
                if callback: Clock.schedule_once(lambda dt: callback(err_msg, True))
            except Exception as e:
                err_msg = f"Execution failed: {e}"
                self.log_manager.add_log(err_msg)
                if callback: Clock.schedule_once(lambda dt: callback(err_msg, True))
        
        thread = threading.Thread(target=run_in_thread); thread.daemon = True; thread.start()

    def stop_all(self):
        """Stops all currently tracked active processes."""
        self.log_manager.add_log(tr.get("stop_all_attacks"))
        for key in list(self.active_processes.keys()):
            self.stop_process(key)

    def stop_process(self, process_key):
        """Stops a specific process by its key."""
        if process_key in self.active_processes:
            process = self.active_processes[process_key]
            self.log_manager.add_log(f"Stopping process '{process_key}' (PID: {process.pid})...")
            try:
                # Use busybox kill -9 (force kill) for reliability
                kill_cmd = [os.path.join(self.tools_path, 'busybox'), 'kill', '-9', str(process.pid)]
                subprocess.run(['su', '-c', ' '.join(kill_cmd)], timeout=5)
                self.log_manager.add_log(f"Process '{process_key}' killed successfully.")
            except Exception as e:
                self.log_manager.add_log(f"Error stopping process {process_key}: {e}")
            finally:
                if process_key in self.active_processes:
                    del self.active_processes[process_key]
        else:
            self.log_manager.add_log(f"No active process with key '{process_key}' to stop.")

# Dummy WifiScanner if JNIus is not available
class WifiScanner:
    def __init__(self, log_manager): self.log_manager = log_manager
    
    def start_scan(self, callback):
        self.log_manager.add_log("WiFi scanning (via Android API) is not available in this build (missing JNIus).")
        callback([]) # Return empty results

class NetworkAnalyzer:
    """Analyzes WiFi scan results for security weaknesses."""
    def analyze(self, scan_results_raw):
        # This will receive results from WifiScanner (which is dummy here)
        # Or from CLI tools if they were enabled.
        # For this build, it will largely be fed empty data or dummy data.
        self.log_manager.add_log("Analyzing network data (limited functionality without JNIus/CLI tools).")
        analyzed_networks = []
        if not scan_results_raw: return []
        
        # This parsing is for Android API results
        for r in scan_results_raw:
            ssid = r.SSID if r.SSID and r.SSID != '<hidden ssid>' else "<Hidden SSID>"
            bssid = r.BSSID
            capabilities = r.capabilities
            level = r.level
            
            vulnerabilities = []
            if "WPA" not in capabilities and "WEP" not in capabilities: vulnerabilities.append("Open")
            if "WEP" in capabilities: vulnerabilities.append("WEP")
            if "[WPS]" in capabilities: vulnerabilities.append("WPS")
            
            if "Open" in vulnerabilities: security_icon, security_color, security_text = "lock-open-variant", "F44336", tr.get("open_networks")
            elif "WEP" in vulnerabilities: security_icon, security_color, security_text = "lock-alert", "FFC107", tr.get("wpa_wpa2")
            elif "WPS" in vulnerabilities: security_icon, security_color, security_text = "key-wireless", "00A2FF", tr.get("wps_enabled")
            else: security_icon, security_color, security_text = "lock", "4CAF50", tr.get("wpa_wpa2")

            analyzed_networks.append({
                'ssid': ssid, 'bssid': bssid, 'signal': level, 'capabilities': capabilities,
                'vulnerabilities': vulnerabilities, 'security_icon': security_icon,
                'security_color': security_color, 'security_text': security_text,
                'channel': "N/A", 'wps_locked': "N/A"
            })
        return analyzed_networks

# ==============================================================================
# 3. UI Widgets & Screens
# ==============================================================================

class BaseScreen(MDScreen):
    """A base screen class to handle language updates."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.app = MDApp.get_running_app()
        self.app.bind(language=self.update_language)
    
    def update_language(self, *args):
        # This method should be implemented by child screens
        pass

class HomeScreen(BaseScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
    
    def build_ui(self):
        layout = MDBoxLayout(orientation='vertical', padding="20dp", spacing="20dp")
        
        status_card = MDCard(padding="15dp", elevation=2, radius=[15,])
        status_box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="10dp")
        self.status_title = MDLabel(font_style="H6", adaptive_height=True)
        
        root_status_layout = MDBoxLayout(adaptive_height=True)
        root_status_layout.add_widget(MDIcon(icon="cellphone-key", theme_text_color="Primary"))
        self.root_access_label = MDLabel(adaptive_height=True)
        self.root_label = MDLabel(adaptive_height=True)
        root_status_layout.add_widget(self.root_access_label)
        root_status_layout.add_widget(self.root_label)
        
        net_status_layout = MDBoxLayout(adaptive_height=True)
        net_status_layout.add_widget(MDIcon(icon="wifi", theme_text_color="Primary"))
        self.net_status_label_title = MDLabel(adaptive_height=True)
        self.net_label = MDLabel(adaptive_height=True)
        net_status_layout.add_widget(self.net_status_label_title)
        net_status_layout.add_widget(self.net_label)
        
        status_box.add_widget(self.status_title)
        status_box.add_widget(root_status_layout)
        status_box.add_widget(net_status_layout)
        status_card.add_widget(status_box)

        actions_card = MDCard(padding="15dp", elevation=2, radius=[15,])
        actions_box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="10dp")
        self.actions_title = MDLabel(font_style="H6", adaptive_height=True)
        
        btn_layout = MDGridLayout(cols=2, spacing="10dp", adaptive_height=True)
        self.scan_btn = MDRaisedButton(on_release=lambda x: self.app.change_screen('discovery'))
        self.exploit_btn = MDRaisedButton(on_release=lambda x: self.app.change_screen('exploitation'))
        btn_layout.add_widget(self.scan_btn)
        btn_layout.add_widget(self.exploit_btn)
        actions_box.add_widget(self.actions_title)
        actions_box.add_widget(btn_layout)
        actions_card.add_widget(actions_box)

        layout.add_widget(status_card)
        layout.add_widget(actions_card)
        layout.add_widget(BoxLayout()) # Spacer
        
        self.add_widget(layout)
        self.update_language()

    def on_enter(self, *args):
        self.update_status()
    
    def update_status(self):
        is_rooted, msg = check_root()
        self.root_label.text = tr.get(msg.lower()) if msg.lower() in tr.translations else msg
        
        # Network Status (simplified due to disabled JNIus)
        if platform == 'android':
            self.net_label.text = tr.get("network_status") + ": " + tr.get("disabled") # Show as disabled
        else: # For desktop testing
            try:
                # Basic check for internet connectivity on desktop
                subprocess.run(['ping', '-c', '1', 'google.com'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.net_label.text = tr.get("connected_to").format("Internet")
            except subprocess.CalledProcessError:
                self.net_label.text = tr.get("disconnected")

    def update_language(self, *args):
        self.status_title.text = tr.get("status")
        self.root_access_label.text = tr.get("root_access")
        self.net_status_label_title.text = tr.get("network_status")
        self.actions_title.text = tr.get("quick_actions")
        self.scan_btn.text = tr.get("discovery")
        self.exploit_btn.text = tr.get("exploitation")
        self.update_status() # Update status text with new language

class DiscoveryScreen(BaseScreen):
    """
    صفحة الاكتشاف الموحدة: تجمع نتائج الفحص من مصادر متعددة.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.scan_results = {} # Store results by BSSID to avoid duplicates and update info
        self.attack_dialog = None # Keep track of the active dialog

        layout = MDFloatLayout()
        
        self.tabs = MDTabs(pos_hint={'center_x': 0.5, 'top': 1}, size_hint_y=0.9, tab_bar_height="48dp")
        self.tabs.bind(on_tab_switch=self.on_tab_switch) # Not used directly for logic, but good practice
        
        layout.add_widget(self.tabs)
        
        self.spinner = MDSpinner(active=False, size_hint=(None, None), size=("46dp", "46dp"), pos_hint={'center_x': .5, 'center_y': .5})
        layout.add_widget(self.spinner)

        scan_button = MDFloatingActionButton(
            icon="radar",
            pos_hint={'center_x': 0.9, 'center_y': 0.1},
            on_release=self.start_full_scan
        )
        layout.add_widget(scan_button)
        
        self.add_widget(layout)
        self.update_language()

    def start_full_scan(self, instance):
        self.spinner.active = True
        self.scan_results = {} # Clear previous results
        self.tabs.clear_widgets() # Clear old tabs and contents
        
        self.app.log_manager.add_log(tr.get("start_full_scan"))
        
        # On Android, if JNIus is disabled, we cannot perform proper WiFi scans.
        # So we just return empty results.
        if platform == 'android':
            self.app.log_manager.add_log("WiFi scanning on Android is disabled in this build (missing JNIus).")
            self.spinner.active = False
            self.populate_tabs()
            self.app.on_discovery_results([]) # Send empty results for PDF
            return

        # For desktop testing (Linux/Windows)
        self.app.log_manager.add_log("Starting basic scan (desktop functionality)...")
        if platform.system() == "Windows":
            command = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'] # Show BSSID info
            self.app.tool_executor.execute(command, requires_root=True, callback=self.process_windows_scan_results, process_key='netsh_scan')
        elif platform.system() == "Linux":
            command = ['iwlist', 'wlan0', 'scan'] # Default to wlan0 on Linux
            self.app.tool_executor.execute(command, requires_root=True, callback=self.process_linux_scan_results, process_key='iwlist_scan')

    def process_windows_scan_results(self, output_lines, is_error):
        if is_error:
            self.app.log_manager.add_log(f"Netsh scan failed: {output_lines[-1]}")
            self.spinner.active = False
            self.populate_tabs()
            self.app.on_discovery_results([])
            return

        # Simplified parsing for basic network info on Windows
        current_net = {}
        for line in output_lines:
            if "SSID" in line:
                if current_net: self.scan_results[current_net['bssid']] = current_net
                current_net = {"ssid": line.split(":")[-1].strip(), "bssid": "N/A", "signal": "N/A", "channel": "N/A", "security_text": "N/A", "vulnerabilities": []}
            elif "BSSID" in line: current_net['bssid'] = line.split(":")[-1].strip()
            elif "Signal" in line: current_net['signal'] = line.split(":")[-1].strip()
            elif "Authentication" in line:
                auth = line.split(":")[-1].strip()
                current_net['security_text'] = auth
                if "Open" in auth: current_net['vulnerabilities'].append("Open")
                if "WEP" in auth: current_net['vulnerabilities'].append("WEP")
        if current_net: self.scan_results[current_net['bssid']] = current_net

        self.spinner.active = False
        self.app.log_manager.add_log("Desktop scan finished. WPS scan (wash) is not supported here.")
        self.populate_tabs()
        self.app.on_discovery_results(list(self.scan_results.values()))

    def process_linux_scan_results(self, output_lines, is_error):
        if is_error:
            self.app.log_manager.add_log(f"iwlist scan failed: {output_lines[-1]}")
            self.spinner.active = False
            self.populate_tabs()
            self.app.on_discovery_results([])
            return
        
        # Simplified parsing for iwlist (basic info)
        current_net = {}
        for line in output_lines:
            if "Cell" in line and "Address" in line:
                if current_net: self.scan_results[current_net['bssid']] = current_net
                bssid = line.split("Address:")[-1].strip()
                current_net = {"ssid": "N/A", "bssid": bssid, "signal": "N/A", "channel": "N/A", "security_text": "N/A", "vulnerabilities": [], "security_icon": "wifi", "security_color": "A9B7C6"}
            elif "ESSID" in line: current_net['ssid'] = line.split(":")[-1].strip().strip('"')
            elif "Channel" in line: current_net['channel'] = line.split(":")[-1].strip()
            elif "Signal level" in line: current_net['signal'] = line.split("level=")[-1].strip().split()[0]
            elif "Encryption key:off" in line: current_net['security_text'] = "Open"; current_net['vulnerabilities'].append("Open")
            elif "WPA" in line: current_net['security_text'] = "WPA/WPA2"
            elif "WEP" in line: current_net['security_text'] = "WEP"; current_net['vulnerabilities'].append("WEP")
            if "WPS" in line: current_net['vulnerabilities'].append("WPS") # Check for WPS in raw output

        if current_net: self.scan_results[current_net['bssid']] = current_net
        
        # Try to run wash if possible and rooted
        is_rooted, _ = check_root()
        if is_rooted and platform.system() == "Linux":
            self.app.log_manager.add_log("Starting 'wash' scan for WPS details (Linux, requires monitor mode)...")
            monitor_iface = self.app.sm.get_screen('exploitation').monitor_iface_input.text.strip()
            if not monitor_iface or monitor_iface == "wlan0":
                self.app.log_manager.add_log("Warning: Monitor interface not set or not in monitor mode. Skipping wash scan.")
                self.spinner.active = False; self.populate_tabs(); self.app.on_discovery_results(list(self.scan_results.values())); return
            
            self.app.tool_executor.execute(
                ['wash', '-i', monitor_iface], 
                requires_root=True, 
                callback=self.process_wash_output,
                process_key='wash_scan'
            )
        else:
            self.spinner.active = False
            self.app.log_manager.add_log("Device not rooted or wash not supported on this platform. Skipping 'wash' scan.")
            self.populate_tabs()
            self.app.on_discovery_results(list(self.scan_results.values()))

    def process_wash_output(self, line, is_error):
        if is_error and "finished" not in line:
            self.app.log_manager.add_log(f"Wash scan error: {line}")
        elif "BSSID" not in line and "----" not in line and line.strip():
            parts = [p.strip() for p in re.split(r'\s{2,}', line)]
            if len(parts) >= 6:
                bssid, channel, rssi, wps_version, wps_locked, essid_parts = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5:]
                essid = " ".join(essid_parts)
                bssid = bssid.upper()
                
                if bssid in self.scan_results:
                    net_info = self.scan_results[bssid]
                    net_info['channel'] = channel
                    net_info['wps_locked'] = wps_locked
                    if "WPS" not in net_info['vulnerabilities']: net_info['vulnerabilities'].append("WPS")
                    net_info['security_icon'] = "key-wireless"
                    net_info['security_text'] = tr.get("wps_enabled")
                else: # Add new entry if wash finds a network API scan missed
                    self.scan_results[bssid] = {
                        'ssid': essid, 'bssid': bssid, 'signal': int(rssi),
                        'capabilities': "[WPS]", 'vulnerabilities': ["WPS"],
                        'security_icon': "key-wireless", 'security_color': "00A2FF", 'security_text': tr.get("wps_enabled"),
                        'channel': channel, 'wps_locked': wps_locked
                    }
        
        if "finished" in line or is_error: # End of wash scan or error
            self.spinner.active = False
            self.app.log_manager.add_log(f"Full discovery finished. Found {len(self.scan_results)} networks. Populating UI.")
            self.populate_tabs()
            self.app.on_discovery_results(list(self.scan_results.values()))

    def populate_tabs(self):
        self.tabs.clear_widgets()
        
        all_nets = list(self.scan_results.values())
        wps_nets = [n for n in all_nets if "WPS" in n['vulnerabilities']]
        wpa_nets = [n for n in all_nets if "WPA" in str(n.get('security_text', '')) or "WPA2" in str(n.get('security_text', ''))]
        open_nets = [n for n in all_nets if "Open" in n['vulnerabilities']]

        all_nets.sort(key=lambda x: x['signal'] if isinstance(x['signal'], int) else float('-inf'), reverse=True) # Sort numerically
        wps_nets.sort(key=lambda x: x['signal'] if isinstance(x['signal'], int) else float('-inf'), reverse=True)
        wpa_nets.sort(key=lambda x: x['signal'] if isinstance(x['signal'], int) else float('-inf'), reverse=True)
        open_nets.sort(key=lambda x: x['signal'] if isinstance(x['signal'], int) else float('-inf'), reverse=True)

        categories = {
            "all": {"title": tr.get("all_networks"), "icon": "wifi", "data": all_nets},
            "wps": {"title": tr.get("wps_enabled"), "icon": "key-wireless", "data": wps_nets},
            "wpa": {"title": tr.get("wpa_wpa2"), "icon": "shield-lock", "data": wpa_nets},
            "open": {"title": tr.get("open_networks"), "icon": "lock-open-variant", "data": open_nets},
        }

        for cat_key, cat_info in categories.items():
            tab_item = MDTabsBase(title=cat_info['title'])
            
            scroll = ScrollView()
            content_list = MDList()
            
            for net in cat_info['data']:
                vuln_str = ", ".join(net['vulnerabilities']) if net['vulnerabilities'] else "None"
                item = ThreeLineAvatarIconListItem(
                    text=f"{net['ssid']}",
                    secondary_text=f"BSSID: {net['bssid']} | Signal: {net['signal']} | CH: {net.get('channel', 'N/A')}",
                    tertiary_text=tr.get("vulnerabilities").format(vuln_str),
                    on_release=partial(self.show_attack_dialog, net)
                )
                item.add_widget(IconLeftWidget(icon=net['security_icon'], theme_text_color="Custom", text_color=get_color_from_hex(net['security_color'])))
                content_list.add_widget(item)
            
            scroll.add_widget(content_list)
            tab_item.add_widget(scroll)
            self.tabs.add_widget(tab_item)

    def on_tab_switch(self, instance_tabs, instance_tab, instance_tab_label, tab_text):
        pass # Currently no specific logic needed here

    def show_attack_dialog(self, net_info, instance_list_item):
        if self.attack_dialog: return # Dialog already open
        
        attack_buttons_layout = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        
        # Add basic info to the dialog
        attack_buttons_layout.add_widget(MDLabel(text=f"[b]{net_info['ssid']}[/b]", font_style="H6", halign="center", markup=True))
        attack_buttons_layout.add_widget(MDLabel(text=f"BSSID: {net_info['bssid']}", font_style="Body1", halign="center"))
        
        # Determine available attacks based on vulnerabilities (and platform/root status)
        is_rooted, _ = check_root()
        if not is_rooted:
            attack_buttons_layout.add_widget(MDLabel(text="Root access is required for most attacks.", font_style="Body2", halign="center", theme_text_color="Error"))
        
        if "WPS" in net_info['vulnerabilities'] and is_rooted:
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("start_reaver"), on_release=partial(self.start_attack_from_dialog, 'reaver', net_info)))
        
        if ("WPA" in str(net_info.get('security_text', '')) or "WPA2" in str(net_info.get('security_text', ''))) and is_rooted:
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("capture_handshake"), on_release=partial(self.start_attack_from_dialog, 'airodump', net_info)))
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("start_aircrack_attack"), on_release=partial(self.start_attack_from_dialog, 'aircrack', net_info)))
        
        if is_rooted: # Deauth and Evil Twin generally available if rooted
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("deauth_attack"), on_release=partial(self.start_attack_from_dialog, 'deauth', net_info)))
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("start_evil_twin"), on_release=partial(self.start_attack_from_dialog, 'eviltwin', net_info)))

        # Create the dialog
        self.attack_dialog = MDDialog(
            title=tr.get("attack_options_for").format(net_info['ssid']),
            type="custom",
            content_cls=attack_buttons_layout,
            buttons=[
                MDFlatButton(text="CANCEL", on_release=lambda x: self.attack_dialog.dismiss()),
            ],
            auto_dismiss=False # Prevent dismiss when clicking outside
        )
        self.attack_dialog.bind(on_dismiss=lambda *args: setattr(self, 'attack_dialog', None))
        self.attack_dialog.open()

    def start_attack_from_dialog(self, attack_type, net_info):
        self.attack_dialog.dismiss() # Dismiss the dialog
        
        # Switch to the exploitation screen
        self.app.change_screen('exploitation')
        exploit_screen = self.app.sm.get_screen('exploitation')
        
        # Prefill fields based on attack type and net_info
        if attack_type == 'reaver':
            exploit_screen.prefill_wps_attack(net_info.get('bssid', ''))
            self.app.log_manager.add_log(f"Ready for Reaver on {net_info['ssid']}. Check Exploitation tab.")
        elif attack_type == 'airodump':
            exploit_screen.prefill_handshake_capture(net_info.get('bssid', ''), net_info.get('channel', 'N/A'))
            self.app.log_manager.add_log(f"Ready for handshake capture on {net_info['ssid']}. Check Exploitation tab.")
        elif attack_type == 'aircrack':
            # For aircrack, we only prefill BSSID if that's relevant to the UI,
            # otherwise, the user needs to select a captured .cap and wordlist manually.
            # This is a placeholder; actual aircrack setup might be more complex.
            self.app.log_manager.add_log(f"Ready for Aircrack-ng attack. Select .cap and wordlist in Exploitation tab.")
        elif attack_type == 'deauth':
            exploit_screen.prefill_deauth_attack(net_info.get('bssid', ''))
            self.app.log_manager.add_log(f"Ready for Deauth attack on {net_info['ssid']}. Check Exploitation tab.")
        elif attack_type == 'eviltwin':
            exploit_screen.prefill_evil_twin(net_info.get('ssid', ''))
            self.app.log_manager.add_log(f"Ready for Evil Twin for {net_info['ssid']}. Check Exploitation tab.")
        
        # Automatically scroll to the relevant section or highlight it if possible

    def update_language(self, *args):
        # Re-populate tabs to update titles
        if self.scan_results: # Only if there are existing results
            self.populate_tabs() # This will use new language strings

class ExploitationScreen(BaseScreen):
    """
    صفحة الاستغلال المنظمة: واجهة موحدة لكل الهجمات.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()
        self.current_prefill_bssid = "" # To store BSSID from dialog

    def build_ui(self):
        layout = MDBoxLayout(orientation='vertical', padding="20dp", spacing="20dp")
        scroll = ScrollView()
        main_content = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="20dp", padding="10dp")

        # --- Monitor Mode Control Card ---
        monitor_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        monitor_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.monitor_title = MDLabel(font_style="H6")
        self.monitor_iface_input = MDTextField(hint_text=tr.get("original_interface"), text="wlan0") # Default to wlan0
        
        monitor_btn_box = MDGridLayout(cols=2, spacing="10dp", adaptive_height=True)
        self.start_mon_btn = MDRaisedButton(on_release=self.start_monitor_mode)
        self.stop_mon_btn = MDRaisedButton(on_release=self.stop_monitor_mode, md_bg_color=self.app.theme_cls.error_color)
        monitor_btn_box.add_widget(self.start_mon_btn)
        monitor_btn_box.add_widget(self.stop_mon_btn)
        
        monitor_box.add_widget(self.monitor_title)
        monitor_box.add_widget(self.monitor_iface_input)
        monitor_box.add_widget(monitor_btn_box)
        monitor_card.add_widget(monitor_box)
        main_content.add_widget(monitor_card)

        # --- WPS Attacks Card (Reaver/Wash related) ---
        wps_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        wps_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.wps_title = MDLabel(font_style="H6")
        self.wps_bssid_input = MDTextField(hint_text=tr.get("target_bssid"))
        self.wps_iface_input = MDTextField(hint_text=tr.get("monitor_interface"), text="wlan0mon") # Default to wlan0mon
        self.start_reaver_btn = MDRaisedButton(on_release=self.start_reaver_attack)
        
        wps_box.add_widget(self.wps_title)
        wps_box.add_widget(self.wps_bssid_input)
        wps_box.add_widget(self.wps_iface_input)
        wps_box.add_widget(self.start_reaver_btn) # Reaver attack
        wps_card.add_widget(wps_box)
        main_content.add_widget(wps_card)

        # --- WPA/WPA2 Attacks Card (Handshake/Aircrack-ng) ---
        wpa_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        wpa_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.wpa_title = MDLabel(font_style="H6")
        
        # Handshake capture
        wpa_box.add_widget(MDLabel(text="[b]Handshake Capture[/b]", markup=True, adaptive_height=True))
        self.handshake_bssid_input = MDTextField(hint_text=tr.get("target_bssid"))
        self.handshake_channel_input = MDTextField(hint_text=tr.get("target_channel"))
        self.handshake_iface_input = MDTextField(hint_text=tr.get("monitor_interface"), text="wlan0mon")
        self.handshake_output_prefix = MDTextField(hint_text=tr.get("output_file_prefix"), text="handshake_capture")
        self.start_handshake_btn = MDRaisedButton(on_release=self.start_airodump_capture)
        wpa_box.add_widget(self.handshake_bssid_input)
        wpa_box.add_widget(self.handshake_channel_input)
        wpa_box.add_widget(self.handshake_iface_input)
        wpa_box.add_widget(self.handshake_output_prefix)
        wpa_box.add_widget(self.start_handshake_btn)
        
        # Aircrack-ng attack
        wpa_box.add_widget(MDLabel(text="[b]Aircrack-ng Attack[/b]", markup=True, adaptive_height=True))
        self.aircrack_cap_file_input = MDTextField(hint_text=tr.get("handshake_cap_file"))
        self.aircrack_wordlist_input = MDTextField(hint_text=tr.get("wordlist_file_path"), readonly=True)
        self.choose_wordlist_btn = MDRaisedButton(on_release=self.choose_wordlist_file)
        self.start_aircrack_btn = MDRaisedButton(on_release=self.start_aircrack_attack)
        wpa_box.add_widget(self.aircrack_cap_file_input)
        wpa_box.add_widget(self.aircrack_wordlist_input)
        wpa_box.add_widget(self.choose_wordlist_btn)
        wpa_box.add_widget(self.start_aircrack_btn)
        wpa_card.add_widget(wpa_box)
        main_content.add_widget(wpa_card)

        # --- Deauthentication Attack Card ---
        deauth_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        deauth_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.deauth_title = MDLabel(font_style="H6")
        self.deauth_bssid = MDTextField(hint_text=tr.get("target_bssid"))
        self.deauth_client = MDTextField(hint_text=tr.get("target_client"))
        self.deauth_iface = MDTextField(hint_text=tr.get("monitor_interface"), text="wlan0mon")
        self.start_deauth_btn = MDRaisedButton(on_release=self.start_deauth_attack)
        
        deauth_box.add_widget(self.deauth_title)
        deauth_box.add_widget(self.deauth_bssid)
        deauth_box.add_widget(self.deauth_client)
        deauth_box.add_widget(self.deauth_iface)
        deauth_box.add_widget(self.start_deauth_btn)
        deauth_card.add_widget(deauth_box)
        main_content.add_widget(deauth_card)

        # --- Evil Twin Attack Card ---
        evil_twin_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        evil_twin_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.evil_twin_title = MDLabel(font_style="H6")
        self.evil_twin_ssid_input = MDTextField(hint_text=tr.get("ssid_to_clone"))
        self.evil_twin_iface_input = MDTextField(hint_text=tr.get("monitor_interface"), text="wlan0mon")
        self.start_evil_twin_btn = MDRaisedButton(on_release=self.start_evil_twin_attack)
        
        evil_twin_box.add_widget(self.evil_twin_title)
        evil_twin_box.add_widget(self.evil_twin_ssid_input)
        evil_twin_box.add_widget(self.evil_twin_iface_input)
        evil_twin_box.add_widget(self.start_evil_twin_btn)
        evil_twin_card.add_widget(evil_twin_box)
        main_content.add_widget(evil_twin_card)


        scroll.add_widget(main_content)
        layout.add_widget(scroll)

        # Stop All Attacks Floating Action Button
        self.stop_all_attacks_fab = MDFloatingActionButton(
            icon="stop",
            pos_hint={'center_x': 0.5, 'center_y': 0.05},
            md_bg_color=self.app.theme_cls.error_color,
            on_release=lambda x: self.app.tool_executor.stop_all()
        )
        layout.add_widget(self.stop_all_attacks_fab)

        self.add_widget(layout)
        self.update_language()

    # --- Prefill Methods (called from DiscoveryScreen) ---
    def prefill_wps_attack(self, bssid):
        self.wps_bssid_input.text = bssid
        self.app.log_manager.add_log(f"WPS BSSID pre-filled: {bssid}. Check WPS Attacks section.")
    
    def prefill_handshake_capture(self, bssid, channel):
        self.handshake_bssid_input.text = bssid
        self.handshake_channel_input.text = channel
        self.app.log_manager.add_log(f"Handshake fields pre-filled for {bssid} on Channel {channel}. Check WPA/WPA2 Attacks section.")

    def prefill_deauth_attack(self, bssid):
        self.deauth_bssid.text = bssid
        self.app.log_manager.add_log(f"Deauth BSSID pre-filled: {bssid}. Check Deauthentication Attack section.")

    def prefill_evil_twin(self, ssid):
        self.evil_twin_ssid_input.text = ssid
        self.app.log_manager.add_log(f"Evil Twin SSID pre-filled: {ssid}. Check Evil Twin Attack section.")


    # --- Attack Execution Methods ---
    def start_monitor_mode(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Monitor mode control is disabled in this Android build."); return
        iface = self.monitor_iface_input.text.strip();
        if not iface: return;
        self.app.log_manager.add_log(f"Starting monitor mode on {iface}...");
        self.app.tool_executor.execute(['airmon-ng', 'start', iface], requires_root=True, callback=self.app.log_manager.add_log, process_key='airmon_start')

    def stop_monitor_mode(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Monitor mode control is disabled in this Android build."); return
        monitor_iface = self.handshake_iface_input.text.strip();
        if not monitor_iface or monitor_iface == "wlan0":
            self.app.log_manager.add_log("Error: Please specify the correct monitor interface (e.g., wlan0mon) to stop."); return
        self.app.log_manager.add_log(f"Stopping monitor mode on {monitor_iface}...");
        self.app.tool_executor.execute(['airmon-ng', 'stop', monitor_iface], requires_root=True, callback=self.app.log_manager.add_log, process_key='airmon_stop')

    def start_reaver_attack(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Reaver is disabled in this Android build."); return
        bssid = self.wps_bssid_input.text.strip(); iface = self.wps_iface_input.text.strip();
        if not bssid or not iface: Snackbar(text=tr.get("bssid_iface_required")).open(); return;
        self.app.log_manager.add_log(f"Starting Reaver Pixie-Dust attack on {bssid} using {iface}...");
        command = ['reaver', '-i', iface, '-b', bssid, '-K', '1', '-vv'];
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='reaver')

    def start_airodump_capture(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Airodump-ng is disabled in this Android build."); return
        bssid = self.handshake_bssid_input.text.strip(); channel = self.handshake_channel_input.text.strip(); iface = self.handshake_iface_input.text.strip(); outfile_prefix = self.handshake_output_prefix.text.strip();
        if not all([bssid, channel, iface, outfile_prefix]): Snackbar(text=tr.get("all_handshake_fields_required")).open(); return;
        full_output_path = os.path.join(self.app.user_data_dir, outfile_prefix);
        self.app.log_manager.add_log(f"Starting airodump-ng to capture handshake from {bssid} on channel {channel}...");
        command = ['airodump-ng', '--bssid', bssid, '-c', channel, '-w', full_output_path, iface];
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='airodump')
        expected_cap_file = f"{full_output_path}-01.cap"; self.aircrack_cap_file_input.text = expected_cap_file;

    def choose_wordlist_file(self, instance):
        if not filechooser:
            Snackbar(text="File chooser is not available on this platform (Plyer missing or not supported).").open(); return
        filechooser.open_file(on_selection=self.on_wordlist_selection, filters=['*.txt', '*'])

    def on_wordlist_selection(self, selection):
        if selection:
            filepath = selection[0]; self.aircrack_wordlist_input.text = filepath; self.app.log_manager.add_log(f"Wordlist selected: {filepath}");
        else: self.app.log_manager.add_log("Wordlist selection cancelled.");
    
    def start_aircrack_attack(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Aircrack-ng is disabled in this Android build."); return
        cap_file = self.aircrack_cap_file_input.text.strip(); wordlist = self.aircrack_wordlist_input.text.strip();
        if not cap_file or not wordlist: Snackbar(text=tr.get("cap_wordlist_required")).open(); return;
        if not os.path.exists(cap_file): Snackbar(text=tr.get("handshake_not_found")).open(); return;
        if not os.path.exists(wordlist): Snackbar(text=tr.get("wordlist_not_found")).open(); return;
        self.app.log_manager.add_log("Starting aircrack-ng with wordlist...");
        command = ['aircrack-ng', cap_file, '-w', wordlist];
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='aircrack')

    def start_deauth_attack(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Deauthentication attack is disabled in this Android build."); return
        bssid = self.deauth_bssid.text.strip(); client = self.deauth_client.text.strip(); iface = self.deauth_iface.text.strip();
        if not bssid or not iface: Snackbar(text=tr.get("bssid_iface_required")).open(); return;
        self.app.log_manager.add_log(f"Starting deauthentication attack on {bssid}...");
        command = ['aireplay-ng', '--deauth', '0', '-a', bssid]; if client: command.extend(['-c', client]); command.append(iface);
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='aireplay_deauth')

    def start_evil_twin_attack(self, instance):
        if platform == 'android': self.app.log_manager.add_log("Evil Twin attack is disabled in this Android build."); return
        ssid = self.evil_twin_ssid_input.text.strip(); iface = self.evil_twin_iface_input.text.strip();
        if not ssid or not iface: Snackbar(text=tr.get("ssid_iface_required")).open(); return;
        self.app.log_manager.add_log(f"Starting Evil Twin (airbase-ng) for SSID '{ssid}'...");
        command = ['airbase-ng', '-a', '00:11:22:33:44:55', '--essid', ssid, '-c', '6', iface];
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='airbase')

    def update_language(self, *args):
        # Update elements in this screen
        self.monitor_title.text = tr.get("monitor_mode_control")
        self.monitor_iface_input.hint_text = tr.get("original_interface")
        self.start_mon_btn.text = tr.get("start_monitor_mode")
        self.stop_mon_btn.text = tr.get("stop_monitor_mode")
        
        self.wps_title.text = tr.get("wps_attacks")
        self.wps_bssid_input.hint_text = tr.get("target_bssid")
        self.wps_iface_input.hint_text = tr.get("monitor_interface")
        self.start_reaver_btn.text = tr.get("start_reaver")

        self.wpa_title.text = tr.get("wpa_attacks")
        self.handshake_bssid_input.hint_text = tr.get("target_bssid")
        self.handshake_channel_input.hint_text = tr.get("target_channel")
        self.handshake_iface_input.hint_text = tr.get("monitor_interface")
        self.handshake_output_prefix.hint_text = tr.get("output_file_prefix")
        self.start_handshake_btn.text = tr.get("capture_handshake")
        self.aircrack_cap_file_input.hint_text = tr.get("handshake_cap_file")
        self.aircrack_wordlist_input.hint_text = tr.get("wordlist_file_path")
        self.choose_wordlist_btn.text = tr.get("choose_wordlist")
        self.start_aircrack_btn.text = tr.get("start_aircrack_attack")

        self.deauth_title.text = tr.get("deauth_attack")
        self.deauth_bssid.hint_text = tr.get("target_bssid")
        self.deauth_client.hint_text = tr.get("target_client")
        self.deauth_iface.hint_text = tr.get("monitor_interface")
        self.start_deauth_btn.text = tr.get("start_deauth")

        self.evil_twin_title.text = tr.get("start_evil_twin") # Use tr.get("start_evil_twin") as title
        self.evil_twin_ssid_input.hint_text = tr.get("ssid_to_clone")
        self.evil_twin_iface_input.hint_text = tr.get("monitor_interface")
        self.start_evil_twin_btn.text = tr.get("start_evil_twin")


class ToolsScreen(BaseScreen):
    """
    صفحة الأدوات: تفحص وتعرض حالة كل أداة مدمجة.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()

    def build_ui(self):
        layout = MDBoxLayout(orientation='vertical', padding="10dp", spacing="10dp")
        self.tools_list_widget = MDList()
        scroll = ScrollView()
        scroll.add_widget(self.tools_list_widget)
        
        self.check_btn = MDRaisedButton(on_release=self.check_tools)
        layout.add_widget(self.check_btn)
        layout.add_widget(scroll)
        self.add_widget(layout)
        self.update_language()
        
    def on_enter(self, *args):
        self.check_tools()

    def check_tools(self, *args):
        self.tools_list_widget.clear_widgets()
        tools_path = os.path.join(self.app.user_data_dir, 'tools')
        
        if not os.path.isdir(tools_path):
            self.app.log_manager.add_log(f"Tools directory not found: {tools_path}"); return
        
        expected_tools = [
            'airmon-ng', 'airodump-ng', 'aircrack-ng', 'aireplay-ng',
            'airbase-ng', 'reaver', 'wash', 'busybox', 'mdk3', 'iw'
        ]
        
        for tool in expected_tools:
            tool_path = os.path.join(tools_path, tool)
            status_text = tr.get("tool_missing")
            icon = "alert-circle"
            color = "F44336" # Red
            
            if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
                status_text = tr.get("tool_ready")
                icon = "check-circle"
                color = "4CAF50" # Green
            
            item = TwoLineAvatarIconListItem(text=tool, secondary_text=status_text)
            item.add_widget(IconLeftWidget(icon=icon, theme_text_color="Custom", text_color=get_color_from_hex(color)))
            self.tools_list_widget.add_widget(item)

    def update_language(self, *args):
        self.check_btn.text = tr.get("check_tool_status")

class SettingsScreen(BaseScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()

    def build_ui(self):
        layout = MDBoxLayout(orientation='vertical', padding="20dp", spacing="20dp")
        
        # Language Card
        lang_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        lang_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.lang_title = MDLabel(font_style="H6")
        
        en_btn = MDRaisedButton(text="English", on_release=lambda x: self.app.set_language("en"))
        ar_btn = MDRaisedButton(text="العربية", on_release=lambda x: self.app.set_language("ar"), font_name="Roboto") # Assuming Roboto supports Arabic
        
        lang_btn_box = MDGridLayout(cols=2, spacing="10dp", adaptive_height=True)
        lang_btn_box.add_widget(en_btn)
        lang_btn_box.add_widget(ar_btn)
        
        lang_box.add_widget(self.lang_title)
        lang_box.add_widget(lang_btn_box)
        lang_card.add_widget(lang_box)

        # Theme Card
        theme_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        theme_box = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        self.theme_title = MDLabel(font_style="H6")
        
        dark_mode_btn = MDRaisedButton(on_release=lambda x: self.app.set_theme("Dark"))
        light_mode_btn = MDRaisedButton(on_release=lambda x: self.app.set_theme("Light"))
        
        theme_btn_box = MDGridLayout(cols=2, spacing="10dp", adaptive_height=True)
        theme_btn_box.add_widget(dark_mode_btn)
        theme_btn_box.add_widget(light_mode_btn)
        
        theme_box.add_widget(self.theme_title)
        theme_box.add_widget(theme_btn_box)
        theme_card.add_widget(theme_box)

        # PDF Export Card
        pdf_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        self.pdf_export_btn = MDRaisedButton(on_release=self.export_pdf)
        pdf_card.add_widget(self.pdf_export_btn)
        
        layout.add_widget(lang_card)
        layout.add_widget(theme_card)
        layout.add_widget(pdf_card)
        layout.add_widget(BoxLayout()) # Spacer
        self.add_widget(layout)
        self.update_language()

    def export_pdf(self, instance):
        self.app.log_manager.add_log(tr.get("export_pdf_report"))
        system_info = {
            tr.get('root_access'): check_root()[1],
            tr.get('app_title'): tr.get('app_title') + " v9.0",
            tr.get('developer'): "Ahmed Mustafa Ibrahim"
        }
        report_path = self.app.report_generator.generate_pdf(self.app.last_scan_results, system_info)
        
        if report_path:
            Snackbar(text=tr.get("report_generated").format(os.path.basename(report_path))).open()
        else:
            Snackbar(text=tr.get("report_failed")).open()

    def update_language(self, *args):
        self.lang_title.text = tr.get("language")
        self.theme_title.text = tr.get("theme")
        self.pdf_export_btn.text = tr.get("export_pdf_report")

class AboutScreen(BaseScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.build_ui()

    def build_ui(self):
        layout = MDBoxLayout(orientation='vertical', padding="20dp", spacing="20dp")
        
        # App Info Card
        app_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        app_box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="10dp")
        self.title_label = MDLabel(font_style="H5", adaptive_height=True, halign="center")
        self.version_label = MDLabel(font_style="Body1", adaptive_height=True, halign="center")
        app_box.add_widget(self.title_label)
        app_box.add_widget(self.version_label)
        app_card.add_widget(app_box)
        
        # Developer Info Card
        dev_card = MDCard(padding="15dp", elevation=2, radius=[15,], adaptive_height=True)
        dev_box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="10dp")
        self.dev_title = MDLabel(font_style="H6")
        dev_box.add_widget(self.dev_title)
        dev_box.add_widget(MDLabel(text="Ahmed Mustafa Ibrahim", adaptive_height=True))
        
        dev_box.add_widget(MDBoxLayout(adaptive_height=True, children=[MDIcon(icon="phone"), MDLabel(text=tr.get("phone") + ": 01225155329", adaptive_height=True)]))
        dev_box.add_widget(MDBoxLayout(adaptive_height=True, children=[MDIcon(icon="email"), MDLabel(text=tr.get("email") + ": GOGOM8870@GMAIL.COM", adaptive_height=True)]))
        dev_card.add_widget(dev_box)

        # Disclaimer Card
        disclaimer_card = MDCard(padding="15dp", md_bg_color=self.app.theme_cls.error_color, elevation=2, radius=[15,], adaptive_height=True)
        disclaimer_box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing="10dp")
        self.disclaimer_title = MDLabel(font_style="H6", theme_text_color="Custom", text_color=(1,1,1,1))
        self.disclaimer_text_label = MDLabel(adaptive_height=True, theme_text_color="Custom", text_color=(1,1,1,1))
        disclaimer_box.add_widget(self.disclaimer_title)
        disclaimer_box.add_widget(self.disclaimer_text_label)
        disclaimer_card.add_widget(disclaimer_box)
        
        layout.add_widget(app_card)
        layout.add_widget(dev_card)
        layout.add_widget(disclaimer_card)
        layout.add_widget(BoxLayout()) # Spacer

        self.add_widget(layout)
        self.update_language()

    def update_language(self, *args):
        self.title_label.text = tr.get("about_title")
        self.version_label.text = f"{tr.get('version')} 9.0"
        self.dev_title.text = tr.get("developer")
        self.disclaimer_title.text = tr.get("disclaimer")
        self.disclaimer_text_label.text = tr.get("disclaimer_text")


# ==============================================================================
# 4. Main Application Class
# ==============================================================================
class WiFiSecurityTesterApp(MDApp):
    language = StringProperty("en")
    
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.accent_palette = "Cyan"

        # --- App Data Directory Setup ---
        # استخدام user_data_dir الخاص بـ Kivy على Android
        if platform == 'android': self.user_data_dir = self.user_data_dir
        else: self.user_data_dir = os.path.join(os.path.dirname(__file__), 'app_data_kivy_final')
        os.makedirs(os.path.join(self.user_data_dir, 'tools'), exist_ok=True)
        
        # --- Initialize Log Panel and Managers ---
        self.log_widget = LogPanel(size_hint_y=0.3) # Instantiate LogPanel here
        self.log_manager = LogManager(self.log_widget) # Pass the instance
        self.tool_executor = ToolExecutor(self.log_manager, self.user_data_dir)
        self.wifi_scanner = WifiScanner(self.log_manager) # Pass LogManager instance
        self.network_analyzer = NetworkAnalyzer() # Does not need log_manager directly
        self.report_generator = ReportGenerator(self.log_manager, self.user_data_dir)
        self.last_scan_results = [] # To store results for PDF report

        # --- Build UI Layout ---
        root_layout = MDBoxLayout(orientation='vertical')
        
        self.top_app_bar = MDTopAppBar(elevation=4)
        self.top_app_bar.right_action_items = [["theme-light-dark", lambda x: self.toggle_theme()]]
        
        self.sm = ScreenManager(transition=FadeTransition())
        self.sm.add_widget(HomeScreen(name='home'))
        self.sm.add_widget(DiscoveryScreen(name='discovery'))
        self.sm.add_widget(ExploitationScreen(name='exploitation'))
        self.sm.add_widget(ToolsScreen(name='tools'))
        self.sm.add_widget(SettingsScreen(name='settings'))
        self.sm.add_widget(AboutScreen(name='about'))
        
        self.bottom_nav = MDBottomNavigation(panel_color=self.theme_cls.bg_dark)
        
        root_layout.add_widget(self.top_app_bar)
        root_layout.add_widget(self.sm)
        root_layout.add_widget(self.log_widget) # Add the LogPanel instance
        root_layout.add_widget(self.bottom_nav)

        self.update_language_and_ui() # Initial UI setup and language
        return root_layout
    
    def on_start(self):
        self.log_manager.add_log(tr.get("app_title") + " v9.0 " + tr.get("checking"))
        self.extract_and_prepare_tools()

    def toggle_theme(self):
        self.theme_cls.theme_style = "Light" if self.theme_cls.theme_style == "Dark" else "Dark"
    
    def set_theme(self, theme_name): # New method for explicit theme setting
        self.theme_cls.theme_style = theme_name

    def set_language(self, lang_code):
        self.language = lang_code
        tr.set_language(lang_code)
        self.update_language_and_ui() # Update all UI elements and tabs

    def update_language_and_ui(self, *args):
        self.top_app_bar.title = tr.get("app_title")
        self.bottom_nav.clear_widgets() # Clear and re-add tabs to update text
        
        tabs_config = {
            'home': {'text': tr.get('home'), 'icon': 'home'},
            'discovery': {'text': tr.get('discovery'), 'icon': 'radar'},
            'exploitation': {'text': tr.get('exploitation'), 'icon': 'sword-cross'},
            'tools': {'text': tr.get('tools'), 'icon': 'hammer-wrench'},
            'settings': {'text': tr.get('settings'), 'icon': 'cog'},
            'about': {'text': tr.get('about'), 'icon': 'information-outline'},
        }
        
        for name, config in tabs_config.items():
            item = MDBottomNavigationItem(name=name, text=config['text'], icon=config['icon'], on_tab_press=self.on_tab_press)
            self.bottom_nav.add_widget(item)

    def on_tab_press(self, instance_tabs):
        self.sm.current = instance_tabs.name
    
    def change_screen(self, screen_name):
        self.sm.current = screen_name
        # Ensure bottom nav highlights the correct tab
        for item in self.bottom_nav.children:
            if item.name == screen_name:
                self.bottom_nav.switch_tab(item.name)
                break

    def on_discovery_results(self, results):
        """Callback from DiscoveryScreen to store latest scan results for PDF."""
        self.last_scan_results = results

    def extract_and_prepare_tools(self):
        self.log_manager.add_log(tr.get("current_active_attacks")) # This line was misplaced, moved here
        self.log_manager.add_log("--- " + tr.get("check_tool_status") + " ---")
        target_tools_dir = os.path.join(self.user_data_dir, 'tools')
        
        if platform == 'android':
            from kivy.resources import resource_find
            source_dir = resource_find('wimax/assets/tools')
        else:
            source_dir = os.path.join(os.path.dirname(__file__), 'wimax/assets/tools')

        if not source_dir or not os.path.isdir(source_dir):
            self.log_manager.add_log(f"CRITICAL: Tools source directory not found: {source_dir}. Please check your 'wimax/assets/tools' folder."); return

        tools_to_extract = os.listdir(source_dir)
        for tool in tools_to_extract:
            source_path = os.path.join(source_dir, tool)
            target_path = os.path.join(target_tools_dir, tool)
            try:
                import shutil
                shutil.copy(source_path, target_path)
                os.chmod(target_path, 0o755) # Grant full execute permissions
                self.log_manager.add_log(f"Synced & Set +x: {tool}")
            except Exception as e:
                self.log_manager.add_log(f"Error syncing {tool}: {e}")
        self.log_manager.add_log("--- Tool setup finished ---")

if __name__ == '__main__':
    # Register font for Arabic support (assuming 'Roboto' or similar TTF is available in assets/fonts)
    # You might need to place a 'Roboto.ttf' file in wimax/assets/fonts/
    from kivy.core.text import LabelBase
    try:
        LabelBase.register(name="Roboto", fn_regular=os.path.join(os.path.dirname(__file__), 'wimax/assets/fonts/Roboto.ttf'))
    except Exception:
        print("Warning: Roboto font not found or could not be registered.")
        pass # Continue without custom font if not found

    WiFiSecurityTesterApp().run()
