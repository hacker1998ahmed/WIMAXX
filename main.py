import os
import sys
import subprocess
import threading
import queue
import re
import platform
import webbrowser
import time
from datetime import datetime
import pyperclip

# ==============================================================================
# 1. المتطلبات
# ==============================================================================
# pip install customtkinter Pillow pyperclip

# ==============================================================================
# 2. المنطق الخلفي والمدراء (Backend & Managers)
# ==============================================================================

# --- JNIus for Android Specific APIs (DISABLED) ---
# تم تعطيل Pyjnius. سيتم استخدام وظائف Dummy في حالة عدم توفرها.
autoclass = None
PythonActivity = None
activity = None
Context = None
WifiManager = None
Permission = None
# قم بتعطيل هذا الجزء إذا كنت تبني بدون JNIus
# if platform.system() == 'android':
#     try:
#         from jnius import autoclass, PythonJavaClass, java_method
#         from android.permissions import request_permissions, Permission
#         WifiManager = autoclass('android.net.wifi.WifiManager')
#         Context = autoclass('android.content.Context')
#         PythonActivity = autoclass('org.kivy.android.PythonActivity')
#         activity = PythonActivity.mActivity
#     except ImportError:
#         pass # Remain None if not found

class ToolExecutor:
    """ينفذ أوامر CLI في thread منفصل ويرسل المخرجات إلى queue.
    بدون Pyjnius، لن يتمكن من الوصول إلى Root أو الأدوات الخارجية بسهولة على Android.
    """
    def __init__(self, log_queue):
        self.log_queue = log_queue
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.tools_path = os.path.join(base_dir, 'wimax', 'assets', 'tools')
        self.current_process = None

    def log(self, message): self.log_queue.put(message)

    def execute(self, command_list, requires_admin=False, process_key=None, on_finish_callback=None):
        if platform.system() == 'android' and requires_admin:
            self.log("Admin/Root operations are not available without Pyjnius. Command skipped.")
            if on_finish_callback: self.log_queue.put(("callback", (on_finish_callback, ["Error: Root operations not available."])))
            return

        def run_in_thread():
            output_lines = []
            try:
                is_windows = (platform.system() == "Windows")
                tool_name = command_list[0]
                if is_windows and not tool_name.endswith('.exe'): tool_name += '.exe'
                
                tool_path = os.path.join(self.tools_path, tool_name)
                if not os.path.exists(tool_path):
                    final_command = command_list
                    self.log(f"Tool '{tool_name}' not in assets, trying system PATH.")
                else:
                    final_command = [tool_path] + command_list[1:]

                self.log(f"Executing: {' '.join(final_command)}")

                if requires_admin and not is_windows:
                    final_command = ['sudo'] + final_command # For Linux/macOS
                
                startupinfo = None
                creationflags = 0
                if is_windows:
                    startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    creationflags = subprocess.CREATE_NO_WINDOW
                
                self.current_process = subprocess.Popen(final_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding='utf-8', errors='ignore', startupinfo=startupinfo, creationflags=creationflags)
                if process_key: App.active_processes[process_key] = self.current_process

                for line in iter(self.current_process.stdout.readline, ''):
                    line = line.strip(); self.log(line); output_lines.append(line)
                
                self.current_process.stdout.close(); self.current_process.wait()
                self.log(f"Process '{tool_name}' finished.")

            except FileNotFoundError: self.log(f"Error: Command '{command_list[0]}' not found."); output_lines.append(f"Error: Command '{command_list[0]}' not found.")
            except Exception as e: self.log(f"Execution failed: {e}"); output_lines.append(f"Execution failed: {e}")
            finally:
                if process_key and process_key in App.active_processes: del App.active_processes[process_key]
                self.current_process = None
                if on_finish_callback: self.log_queue.put(("callback", (on_finish_callback, output_lines)))
        
        thread = threading.Thread(target=run_in_thread); thread.daemon = True; thread.start()

# Dummy WifiScanner if pyjnius is not available
class WifiScanner:
    def __init__(self, log_queue): self.log_queue = log_queue
    def log(self, message): self.log_queue.put(message)

    def start_scan(self, callback):
        self.log("WiFi scanning is not available without Pyjnius/Android APIs.")
        callback([]) # Return empty results

# Rest of the classes (LiveBruteForceThread, AdvancedNetworkParser, ReportGenerator, App) remain the same.
# Make sure to paste the full code of these classes from the v8.0 version.
# For example, paste the entire App class.

# ==============================================================================
# 3. الواجهة الرسومية الرئيسية (Main App Class)
# ==============================================================================
class App(ctk.CTk):
    active_processes = {}
    selected_network_info = {}

    def __init__(self):
        super().__init__()

        self.title("WiFi Security Tester - The Complete Platform v17")
        self.geometry("1280x820"); self.minsize(1100, 750)
        ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")

        self.log_queue = queue.Queue()
        self.log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_log.txt")
        self.tool_executor = ToolExecutor(self.log_queue)
        self.parser = AdvancedNetworkParser(self.log_queue) 
        self.report_generator = ReportGenerator(self.log_queue, os.path.dirname(os.path.abspath(__file__)))
        self.wifi_scanner = WifiScanner(self.log_queue) # Use the dummy scanner
        
        self.grid_columnconfigure(1, weight=1); self.grid_rowconfigure(0, weight=1)

        # --- الشريط الجانبي ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0); self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)
        ctk.CTkLabel(self.sidebar_frame, text="WiFi Tester", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=20, pady=20)
        
        nav_items = {"Home": "home", "Discovery": "discovery", "Exploitation": "exploitation", "Tools": "tools", "Saved Profiles": "profiles", "Logs": "logs", "Settings": "settings", "About": "about"}
        for i, (text, name) in enumerate(nav_items.items(), 1):
            button = ctk.CTkButton(self.sidebar_frame, text=text, command=lambda n=name: self.select_frame(n)); button.grid(row=i, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(self.sidebar_frame, text="Appearance:").grid(row=9, column=0, padx=20, pady=(10, 0), sticky="s")
        self.theme_switch = ctk.CTkSwitch(self.sidebar_frame, text="Light Mode", command=self.change_theme); self.theme_switch.grid(row=10, column=0, padx=20, pady=20, sticky="s")

        # --- الإطارات الرئيسية ---
        self.main_frames = {}
        for name in nav_items.values(): self.main_frames[name] = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        self.create_home_widgets()
        self.create_discovery_widgets()
        self.create_exploitation_widgets()
        self.create_tools_widgets()
        self.create_profiles_widgets()
        self.create_logs_widgets()
        self.create_settings_widgets()
        self.create_about_widgets()

        # --- لوحة السجلات ---
        self.log_frame = ctk.CTkFrame(self); self.log_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        self.log_frame.grid_rowconfigure(0, weight=1); self.log_frame.grid_columnconfigure(0, weight=1)
        self.log_textbox = ctk.CTkTextbox(self.log_frame, state="disabled", font=("Courier New", 12)); self.log_textbox.grid(row=0, column=0, sticky="nsew")
        
        self.select_frame("home"); self.process_log_queue()

    def select_frame(self, name):
        for frame_name, frame in self.main_frames.items():
            if frame_name == name: frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
            else: frame.grid_forget()
        if name == "tools" or name == "discovery": self.refresh_interfaces()
        if name == "logs": self.refresh_log_viewer()
        if name == "profiles": self.load_saved_profiles()

    def change_theme(self): ctk.set_appearance_mode("light" if self.theme_switch.get() == 1 else "dark")

    def process_log_queue(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                message = ""
                if isinstance(item, tuple):
                    if item[0] == "callback": item[1][0](item[1][1]); continue
                    elif item[0] == "attack_finished":
                        if hasattr(self, 'live_start_btn'): self.live_start_btn.configure(state="normal")
                        if hasattr(self, 'live_stop_btn'): self.live_stop_btn.configure(state="disabled")
                        continue
                else: message = str(item)
                self.log_textbox.configure(state="normal"); self.log_textbox.insert("end", message + "\n"); self.log_textbox.configure(state="disabled"); self.log_textbox.see("end")
                with open(self.log_file_path, "a", encoding='utf-8') as f: f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
        except queue.Empty: pass
        self.after(100, self.process_log_queue)

    def browse_file(self, entry_widget):
        filepath = filedialog.askopenfilename(filetypes=[("Wordlists", "*.txt"), ("Capture Files", "*.cap"), ("All files", "*.*")])
        if filepath: entry_widget.delete(0, "end"); entry_widget.insert(0, filepath)

    # ==========================================================================
    # --- بناء واجهات الصفحات ---
    # ==========================================================================
    def create_home_widgets(self):
        frame = self.main_frames["home"]; frame.pack_propagate(0)
        ctk.CTkLabel(frame, text="WiFi Security Tester\nAll-in-One Platform", font=ctk.CTkFont(size=28, weight="bold")).pack(pady=50, padx=20)
        ctk.CTkLabel(frame, text="Welcome! Use the sidebar to navigate.\nStart with the 'Tools' page to configure your interface, then 'Discovery' to find networks.", font=ctk.CTkFont(size=16), wraplength=600).pack(pady=10, padx=20)

    def create_discovery_widgets(self):
        frame = self.main_frames["discovery"]; frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(1, weight=1)
        scan_frame = ctk.CTkFrame(frame); scan_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkLabel(scan_frame, text="Interface:").pack(side="left", padx=10, pady=10)
        self.scan_iface_combobox = ctk.CTkComboBox(scan_frame, values=["Detecting..."], command=self.update_scan_buttons); self.scan_iface_combobox.pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(scan_frame, text="Run Full Scan", command=self.run_full_scan).pack(side="left", padx=10, pady=10)
        self.results_tree = ttk.Treeview(frame, columns=("SSID", "BSSID", "Signal", "Channel", "Security", "Vulnerabilities"), show="headings")
        headings = {"SSID": 200, "BSSID": 150, "Signal": 80, "Channel": 80, "Security": 120, "Vulnerabilities": 180}
        for col, width in headings.items(): self.results_tree.heading(col, text=col); self.results_tree.column(col, width=width, anchor="w")
        self.results_tree.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.results_tree.bind("<Button-3>", self.show_attack_menu) 

    def create_exploitation_widgets(self):
        frame = self.main_frames["exploitation"]; frame.grid_columnconfigure(0, weight=1)
        target_info_card = ctk.CTkFrame(frame); target_info_card.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ctk.CTkLabel(target_info_card, text="Target Network Information", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.target_info_label = ctk.CTkLabel(target_info_card, text="Right-click a network from the Discovery page to select a target.", anchor="w", justify="left"); self.target_info_label.pack(pady=5, padx=10, fill="x")
        self.attack_details_frame = ctk.CTkFrame(frame, fg_color="transparent"); self.attack_details_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

    def create_tools_widgets(self):
        frame = self.main_frames["tools"]; frame.grid_columnconfigure(0, weight=1)
        iface_card = ctk.CTkFrame(frame); iface_card.pack(fill="x", padx=5, pady=5)
        iface_card.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(iface_card, text="Network Interface Management", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, columnspan=3, pady=5)
        ctk.CTkLabel(iface_card, text="Detected Interfaces:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.tools_iface_combobox = ctk.CTkComboBox(iface_card, values=["Detecting..."])
        self.tools_iface_combobox.configure(command=self.display_interface_info) 
        self.tools_iface_combobox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(iface_card, text="Refresh", command=self.refresh_interfaces).grid(row=1, column=2, padx=5, pady=5)
        self.iface_info_textbox = ctk.CTkTextbox(iface_card, height=100, state="disabled"); self.iface_info_textbox.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        ctk.CTkButton(iface_card, text="Start Monitor Mode", command=self.start_monitor, fg_color="#006400").grid(row=3, column=0, padx=5, pady=10)
        ctk.CTkButton(iface_card, text="Stop Monitor Mode", command=self.stop_monitor, fg_color="#8B0000").grid(row=3, column=1, padx=5, pady=10, sticky="w")
        
    def create_profiles_widgets(self):
        frame = self.main_frames["profiles"]; frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(1, weight=1)
        top_frame = ctk.CTkFrame(frame); top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ctk.CTkLabel(top_frame, text="Saved WiFi Profiles", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(top_frame, text="Load Saved Profiles", command=self.load_saved_profiles).pack(side="left", padx=10, pady=10)
        self.profiles_tree = ttk.Treeview(frame, columns=("SSID", "Password"), show="headings")
        self.profiles_tree.heading("SSID", text="Network Name (SSID)"); self.profiles_tree.column("SSID", width=200, anchor="w")
        self.profiles_tree.heading("Password", text="Password"); self.profiles_tree.column("Password", width=200, anchor="w")
        self.profiles_tree.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.profiles_tree.bind("<Double-1>", self.on_profile_select)

    def create_logs_widgets(self):
        frame = self.main_frames["logs"]; frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(1, weight=1)
        top_frame = ctk.CTkFrame(frame); top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ctk.CTkLabel(top_frame, text="Application Log Viewer", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(top_frame, text="Refresh Log", command=self.refresh_log_viewer).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(top_frame, text="Clear Log File", command=self.clear_log_file, fg_color="#8B0000").pack(side="left", padx=10, pady=10)
        self.full_log_textbox = ctk.CTkTextbox(frame, state="disabled", font=("Courier New", 11)); self.full_log_textbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    def create_settings_widgets(self):
        frame = self.main_frames["settings"]; frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="Application Settings", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, padx=20, pady=20, sticky="w")
        log_card = ctk.CTkFrame(frame); log_card.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkLabel(log_card, text="Export Application Log", font=ctk.CTkFont(weight="bold")).pack(pady=5, padx=10)
        ctk.CTkButton(log_card, text="Save Log to File", command=self.save_log_to_file).pack(pady=10, padx=10)

    def create_about_widgets(self):
        frame = self.main_frames["about"]; frame.grid_columnconfigure(1, weight=1)
        dev_info = {"Version": "17.0 (The Complete Platform)", "Developer": "Ahmed Mustafa Ibrahim", "Phone": "01225155329", "Email": "GOGOM8870@GMAIL.COM"}
        for i, (key, value) in enumerate(dev_info.items()):
            label_key = ctk.CTkLabel(frame, text=f"{key}:", font=ctk.CTkFont(weight="bold")); label_key.grid(row=i, column=0, padx=10, pady=5, sticky="w")
            if key == "Email": label_value = ctk.CTkButton(frame, text=value, fg_color="transparent", text_color=("blue", "lightblue"), anchor="w", command=lambda e=value: webbrowser.open(f"mailto:{e}"))
            else: label_value = ctk.CTkLabel(frame, text=value, anchor="w")
            label_value.grid(row=i, column=1, padx=10, pady=5, sticky="w")
        disclaimer = "This application is for educational and authorized security testing only. Unauthorized use is illegal."; ctk.CTkLabel(frame, text=disclaimer, wraplength=500, font=ctk.CTkFont(slant="italic"), text_color="gray").grid(row=len(dev_info), column=0, columnspan=2, pady=30, sticky="ew")

    # ==========================================================================
    # --- دوال المنطق والتحكم (معدلة لتعطيل وظائف Pyjnius) ---
    # ==========================================================================
    def update_scan_buttons(self, selected_iface):
        # هذه الوظيفة تعتمد على وجود واجهة
        pass # No change needed here, as the combobox values are already affected

    def run_full_scan(self):
        self.results_tree.delete(*self.results_tree.get_children())
        iface = self.scan_iface_combobox.get()
        if "Detecting" in iface or "No" in iface: messagebox.showerror("Error", "Please select a valid interface."); return
        
        self.parser = AdvancedNetworkParser(self.log_queue)
        self.log_queue.put("--- Starting Full Scan ---")

        if platform.system() == "Windows":
            self.log_queue.put(f"Step 1: Running netsh scan on {iface}...")
            command = ['netsh', 'wlan', 'show', 'networks', f'interface="{iface}"']
            self.tool_executor.execute(command, requires_admin=True, on_finish_callback=self.process_windows_scan_results)
        elif platform.system() == "Linux":
            self.log_queue.put(f"Step 1: Running iwlist scan on {iface}...")
            command = ['iwlist', iface, 'scan']
            self.tool_executor.execute(command, requires_admin=True, on_finish_callback=self.process_linux_scan_results)
        else: # Android (بدون Pyjnius)
            self.log_queue.put("WiFi scanning on Android requires Pyjnius, which is disabled. Skipping scan.")
            self.populate_discovery_results([]) # Populate with empty results


    def process_windows_scan_results(self, output_lines):
        self.parser.parse_netsh_output(output_lines)
        self.log_queue.put("WPS scan (wash) is not available on Windows. Scan finished.")
        self.populate_discovery_results([]) # Populate with netsh results only

    def process_linux_scan_results(self, output_lines):
        self.parser.parse_iwlist(output_lines)
        self.log_queue.put("Step 2: WPS scan on wlan0mon (requires Monitor Mode)...")
        
        def check_mon_mode_and_run_wash_callback(iface_output_lines):
            output_str = "\n".join(iface_output_lines)
            if "Mode:Monitor" in output_str or "type monitor" in output_str:
                self.tool_executor.execute(['wash', '-i', 'wlan0mon'], requires_admin=True, on_finish_callback=self.populate_discovery_results)
            else:
                self.log_queue.put("Error: wlan0mon is not in monitor mode. Skipping WPS scan.")
                self.populate_discovery_results([]) # Populate with iwlist results only
        
        self.tool_executor.execute(['iwconfig', 'wlan0mon'], requires_admin=True, on_finish_callback=check_mon_mode_and_run_wash_callback)

    def populate_discovery_results(self, wash_output):
        self.parser.parse_wash(wash_output)
        self.results_tree.delete(*self.results_tree.get_children())
        for net in self.parser.networks.values():
            vulns = ", ".join(net["vulnerabilities"]) if net["vulnerabilities"] else "None"
            self.results_tree.insert("", "end", values=(net['ssid'], net['bssid'], net['signal'], net['channel'], net['security'], vulns))
        self.log_queue.put("--- Full Scan Finished ---")

    def show_attack_menu(self, event):
        item_id = self.results_tree.identify_row(event.y)
        if not item_id: return
        self.results_tree.selection_set(item_id)
        item_values = self.results_tree.item(item_id, "values")
        keys = ["ssid", "bssid", "signal", "channel", "security", "vulnerabilities"]
        self.selected_network_info = dict(zip(keys, item_values))
        
        attack_menu = tk.Menu(self, tearoff=0)
        attack_menu.add_command(label="Attacks unavailable without Root/Jnius", state="disabled") # Disable attacks if no root/jnius
        
        # Enable attacks based on platform (Windows Live Brute-Force)
        if platform.system() == "Windows":
             attack_menu.add_command(label="Live Brute-Force (Windows)", command=lambda: self.setup_attack_ui("live_bruteforce"))
        
        attack_menu.tk_popup(event.x_root, event.y_root)

    def setup_attack_ui(self, attack_type):
        self.select_frame("exploitation")
        for widget in self.attack_details_frame.winfo_children(): widget.destroy()
        info = self.selected_network_info
        info_text = f"Target: {info['ssid']}  |  BSSID: {info['bssid']}  |  Channel: {info.get('channel', 'N/A')}"
        self.target_info_label.configure(text=info_text)
        card = ctk.CTkFrame(self.attack_details_frame); card.pack(fill="x", padx=5, pady=5)
        
        if attack_type == "live_bruteforce":
            ctk.CTkLabel(card, text="Live Brute-Force Attack (Windows Only)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
            self.live_wordlist_entry = ctk.CTkEntry(card, placeholder_text="Wordlist File", width=300); self.live_wordlist_entry.pack(pady=5, padx=10, side="left", expand=True, fill="x")
            ctk.CTkButton(card, text="Browse...", width=100, command=lambda: self.browse_file(self.live_wordlist_entry)).pack(pady=5, padx=10, side="left")
            self.live_delay_spinbox = tk.Spinbox(card, from_=1, to=60, width=5); self.live_delay_spinbox.pack(pady=5, padx=10, side="left")
            self.live_start_btn = ctk.CTkButton(card, text="Start Attack", command=self.start_live_brute_force); self.live_start_btn.pack(pady=5, padx=10, side="left")
            self.live_stop_btn = ctk.CTkButton(card, text="Stop", command=self.stop_live_brute_force, fg_color="#8B0000", state="disabled"); self.live_stop_btn.pack(pady=5, padx=10, side="left")
        
        else:
            ctk.CTkLabel(card, text="Advanced attacks (WPS, Handshake, Dictionary, Deauth, Evil Twin) require root access and Pyjnius, which are not enabled in this build.", wraplength=500).pack(pady=20)
            ctk.CTkLabel(card, text="Please build with Pyjnius enabled for full functionality.", wraplength=500).pack(pady=10)

    def start_live_brute_force(self):
        target_ssid = self.selected_network_info.get("ssid")
        wordlist_path = self.live_wordlist_entry.get()
        delay = int(self.live_delay_spinbox.get())
        if not target_ssid or not wordlist_path or not os.path.exists(wordlist_path):
            messagebox.showerror("Error", "Please select a target network and a valid wordlist.")
            return
        self.live_start_btn.configure(state="disabled")
        self.live_stop_btn.configure(state="normal")
        self.live_bruteforce_thread = LiveBruteForceThread(target_ssid, wordlist_path, delay, self.log_queue)
        self.live_bruteforce_thread.start()

    def stop_live_brute_force(self):
        if hasattr(self, 'live_bruteforce_thread') and self.live_bruteforce_thread.is_alive(): self.live_bruteforce_thread.stop()
        
    def start_monitor(self): self.log_queue.put("Monitor mode control not available without Pyjnius/Root."); messagebox.showinfo("Info", "Monitor mode control not available without Pyjnius/Root.")
    def stop_monitor(self): self.log_queue.put("Monitor mode control not available without Pyjnius/Root."); messagebox.showinfo("Info", "Monitor mode control not available without Pyjnius/Root.")
    
    def start_wash(self): self.log_queue.put("Wash not available without Pyjnius/Root."); messagebox.showinfo("Info", "Wash not available without Pyjnius/Root.")
    def start_reaver(self): self.log_queue.put("Reaver not available without Pyjnius/Root."); messagebox.showinfo("Info", "Reaver not available without Pyjnius/Root.")
    def start_airodump_capture(self): self.log_queue.put("Airodump-ng not available without Pyjnius/Root."); messagebox.showinfo("Info", "Airodump-ng not available without Pyjnius/Root.")
    def start_aircrack_dict_attack(self): self.log_queue.put("Aircrack-ng not available without Pyjnius/Root."); messagebox.showinfo("Info", "Aircrack-ng not available without Pyjnius/Root.")
    def start_deauth_attack(self): self.log_queue.put("Aireplay-ng not available without Pyjnius/Root."); messagebox.showinfo("Info", "Aireplay-ng not available without Pyjnius/Root.")
    def start_evil_twin(self): self.log_queue.put("Airbase-ng not available without Pyjnius/Root."); messagebox.showinfo("Info", "Airbase-ng not available without Pyjnius/Root.")

    def refresh_interfaces(self):
        if platform.system() == "Windows":
            self.tool_executor.execute(['netsh', 'wlan', 'show', 'interfaces'], on_finish_callback=self.populate_windows_interfaces)
        elif platform.system() == "Linux":
            self.tool_executor.execute(['ip', 'link', 'show'], on_finish_callback=self.populate_linux_interfaces)
        else: # Android (بدون Pyjnius)
            self.tools_iface_combobox.set("No interfaces (Jnius disabled)"); self.scan_iface_combobox.set("No interfaces (Jnius disabled)")
            self.iface_info_textbox.configure(state="normal"); self.iface_info_textbox.delete("1.0", "end"); self.iface_info_textbox.insert("end", "Interface detection and management not available without Pyjnius.")
            self.iface_info_textbox.configure(state="disabled")

    def populate_windows_interfaces(self, output_lines):
        interfaces = []; info_text = ""
        for line in output_lines:
            if "Name" in line and "interface" in line:
                iface_name = line.split(":")[-1].strip()
                interfaces.append(iface_name)
                info_text += f"Interface: {iface_name}\n"
            if "Description" in line or "State" in line or "MAC" in line: info_text += line + "\n"
        self.tools_iface_combobox.configure(values=interfaces or ["No interfaces found"]); self.scan_iface_combobox.configure(values=interfaces or ["No interfaces found"])
        if interfaces: self.tools_iface_combobox.set(interfaces[0]); self.scan_iface_combobox.set(interfaces[0])
        self.iface_info_textbox.configure(state="normal"); self.iface_info_textbox.delete("1.0", "end"); self.iface_info_textbox.insert("end", info_text)
        self.iface_info_textbox.configure(state="disabled")

    def populate_linux_interfaces(self, output_lines):
        interfaces = []; info_text = ""
        current_iface = ""
        for line in output_lines:
            if re.match(r'^\d+:', line):
                parts = line.split(':')
                iface_name = parts[1].strip()
                interfaces.append(iface_name)
                current_iface = iface_name
                info_text += f"\nInterface: {iface_name}\n"
            else: info_text += line.strip() + "\n"
        self.tools_iface_combobox.configure(values=interfaces or ["No interfaces found"]); self.scan_iface_combobox.configure(values=interfaces or ["No interfaces found"])
        if interfaces: self.tools_iface_combobox.set(interfaces[0]); self.scan_iface_combobox.set(interfaces[0])
        self.iface_info_textbox.configure(state="normal"); self.iface_info_textbox.delete("1.0", "end"); self.iface_info_textbox.insert("end", info_text)
        self.iface_info_textbox.configure(state="disabled")

    def display_interface_info(self, selected_iface):
        if not selected_iface: return
        self.log_queue.put(f"Displaying info for {selected_iface}")
        # Re-run ip link show and filter for selected interface
        if platform.system() == "Windows":
            command = ['netsh', 'wlan', 'show', 'interfaces', f'name="{selected_iface}"']
        elif platform.system() == "Linux":
            command = ['ip', 'link', 'show', selected_iface]
        else:
            self.iface_info_textbox.configure(state="normal"); self.iface_info_textbox.delete("1.0", "end"); self.iface_info_textbox.insert("end", "Interface info not available.")
            self.iface_info_textbox.configure(state="disabled")
            return
        
        def update_info_textbox(output_lines):
            self.iface_info_textbox.configure(state="normal"); self.iface_info_textbox.delete("1.0", "end"); self.iface_info_textbox.insert("end", "\n".join(output_lines))
            self.iface_info_textbox.configure(state="disabled")

        self.tool_executor.execute(command, on_finish_callback=update_info_textbox)

    def load_saved_profiles(self):
        self.profiles_tree.delete(*self.profiles_tree.get_children())
        self.log_queue.put("Loading saved profiles is not implemented in this build without Android API access.")
        messagebox.showinfo("Not Implemented", "Loading saved profiles is not implemented in this build without Android API access.")

    def on_profile_select(self, event):
        item = self.profiles_tree.selection()[0]
        profile_data = self.profiles_tree.item(item, "values")
        ssid, password = profile_data[0], profile_data[1]
        messagebox.showinfo("Profile Selected", f"Selected: SSID={ssid}, Password={password}\n(Connect logic not implemented in this build)")

    def refresh_log_viewer(self):
        self.full_log_textbox.configure(state="normal"); self.full_log_textbox.delete("1.0", "end")
        if os.path.exists(self.log_file_path):
            with open(self.log_file_path, "r", encoding='utf-8') as f: self.full_log_textbox.insert("end", f.read())
        self.full_log_textbox.configure(state="disabled"); self.full_log_textbox.see("end")

    def clear_log_file(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear the log file?"):
            with open(self.log_file_path, "w", encoding='utf-8') as f: f.write("")
            self.refresh_log_viewer()
            self.log_queue.put("Log file cleared.")

    def save_log_to_file(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            with open(self.log_file_path, "r", encoding='utf-8') as src:
                with open(filepath, "w", encoding='utf-8') as dst: dst.write(src.read())
            messagebox.showinfo("Success", f"Log saved to {filepath}")

# Placeholder classes for removed functionality
class AdvancedNetworkParser:
    def __init__(self, log_queue): self.log_queue = log_queue
    def parse_iwlist(self, output_lines): return [] # Dummy
    def parse_netsh_output(self, output_lines): return [] # Dummy
    def parse_wash(self, output_lines): return [] # Dummy

class ReportGenerator:
    def __init__(self, log_queue, app_data_dir): self.log_queue = log_queue
    def generate_pdf(self, scan_results, system_info):
        self.log_queue.put("PDF report generation is not available without reportlab.")
        messagebox.showinfo("Not Available", "PDF report generation is not available without reportlab.")
        return None

if __name__ == "__main__":
    app = App()
    app.mainloop()
