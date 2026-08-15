import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from datetime import datetime

from hash_utils import calculate_sha256
from signature_manager import SignatureManager
from quarantine import QuarantineManager
from history_manager import HistoryManager
from scanner import ScannerEngine

# Appearance settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AntivirusApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Basic Antivirus Simulation – Signature Scanner")
        self.geometry("1100 × 720")
        self.minsize(950, 650)

        # Initialize core engine modules
        self.sig_manager = SignatureManager()
        self.quarantine_manager = QuarantineManager()
        self.history_manager = HistoryManager()
        self.scanner_engine = ScannerEngine(self.sig_manager)

        # State tracking variables
        self.selected_folder = ""
        self.current_scan_results = []
        self.active_scan_threats = []

        # Configure layout grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Build UI layout
        self.create_sidebar()
        self.create_main_frames()
        self.show_frame("dashboard")

        # Refresh metric stats
        self.refresh_dashboard_metrics()

    # -------------------------------------------------------------------
    # SIDEBAR NAVIGATION
    # -------------------------------------------------------------------
    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        # App Title Logo
        logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="🛡️ AG-Antivirus\nSimulation", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 20))

        # Nav Buttons
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar_frame, text="🏠 Dashboard", anchor="w",
            command=lambda: self.show_frame("dashboard")
        )
        self.btn_dashboard.grid(row=1, column=0, padx=15, pady=8, sticky="ew")

        self.btn_scanner = ctk.CTkButton(
            self.sidebar_frame, text="🔍 File Scanner", anchor="w",
            command=lambda: self.show_frame("scanner")
        )
        self.btn_scanner.grid(row=2, column=0, padx=15, pady=8, sticky="ew")

        self.btn_quarantine = ctk.CTkButton(
            self.sidebar_frame, text="🛡️ Quarantine", anchor="w",
            command=lambda: self.show_frame("quarantine")
        )
        self.btn_quarantine.grid(row=3, column=0, padx=15, pady=8, sticky="ew")

        self.btn_signatures = ctk.CTkButton(
            self.sidebar_frame, text="📋 Signature DB", anchor="w",
            command=lambda: self.show_frame("signatures")
        )
        self.btn_signatures.grid(row=4, column=0, padx=15, pady=8, sticky="ew")

        self.btn_history = ctk.CTkButton(
            self.sidebar_frame, text="📊 Scan History", anchor="w",
            command=lambda: self.show_frame("history")
        )
        self.btn_history.grid(row=5, column=0, padx=15, pady=8, sticky="ew")

        self.btn_about = ctk.CTkButton(
            self.sidebar_frame, text="ℹ️ About & Legal", anchor="w",
            command=lambda: self.show_frame("about")
        )
        self.btn_about.grid(row=6, column=0, padx=15, pady=8, sticky="ew")

        # System Status Footer
        self.status_box = ctk.CTkFrame(self.sidebar_frame, fg_color="#1a2e1a", corner_radius=10)
        self.status_box.grid(row=8, column=0, padx=15, pady=20, sticky="ew")
        
        self.lbl_protection_status = ctk.CTkLabel(
            self.status_box, 
            text="● PROTECTION ACTIVE", 
            text_color="#4CAF50",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.lbl_protection_status.pack(padx=10, pady=10)

    # -------------------------------------------------------------------
    # MAIN FRAMES CONTAINER
    # -------------------------------------------------------------------
    def create_main_frames(self):
        self.frames = {}

        # 1. Dashboard View
        self.frames["dashboard"] = self.build_dashboard_frame()
        # 2. Scanner View
        self.frames["scanner"] = self.build_scanner_frame()
        # 3. Quarantine View
        self.frames["quarantine"] = self.build_quarantine_frame()
        # 4. Signature DB View
        self.frames["signatures"] = self.build_signatures_frame()
        # 5. History View
        self.frames["history"] = self.build_history_frame()
        # 6. About View
        self.frames["about"] = self.build_about_frame()

        for name, frame in self.frames.items():
            frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def show_frame(self, name):
        """Switches visible frame and updates relevant views."""
        frame = self.frames[name]
        frame.tkraise()

        if name == "dashboard":
            self.refresh_dashboard_metrics()
        elif name == "quarantine":
            self.refresh_quarantine_view()
        elif name == "signatures":
            self.refresh_signatures_view()
        elif name == "history":
            self.refresh_history_view()

    # -------------------------------------------------------------------
    # 1. DASHBOARD FRAME
    # -------------------------------------------------------------------
    def build_dashboard_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Title Header
        lbl_title = ctk.CTkLabel(
            frame, text="Security Dashboard", 
            font=ctk.CTkFont(size=26, weight="bold")
        )
        lbl_title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 15))

        # Status Banner
        self.dash_banner = ctk.CTkFrame(frame, fg_color="#1E293B", corner_radius=12)
        self.dash_banner.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(0, 20))
        
        self.dash_banner_label = ctk.CTkLabel(
            self.dash_banner, 
            text="🛡️  System Status: Protected & Monitoring Active", 
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#10B981"
        )
        self.dash_banner_label.pack(padx=20, pady=15, side="left")

        # Metric Cards (4 Grid Boxes)
        self.card_total = self.create_card(frame, row=2, col=0, title="Total Files Scanned", val="0", color="#3B82F6")
        self.card_safe = self.create_card(frame, row=2, col=1, title="Safe Files", val="0", color="#10B981")
        self.card_threats = self.create_card(frame, row=2, col=2, title="Threats Detected", val="0", color="#EF4444")
        self.card_quarantine = self.create_card(frame, row=2, col=3, title="Quarantined Files", val="0", color="#F59E0B")

        # Quick Actions Card
        actions_frame = ctk.CTkFrame(frame, corner_radius=12)
        actions_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=20)
        
        lbl_actions = ctk.CTkLabel(actions_frame, text="Quick Security Actions", font=ctk.CTkFont(size=16, weight="bold"))
        lbl_actions.pack(anchor="w", padx=20, pady=(15, 10))

        btn_box = ctk.CTkFrame(actions_frame, fg_color="transparent")
        btn_box.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkButton(
            btn_box, text="⚡ Select & Scan Folder", fg_color="#2563EB", hover_color="#1D4ED8",
            command=self.action_quick_scan
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_box, text="🛡️ Manage Quarantine", fg_color="#374151", hover_color="#4B5563",
            command=lambda: self.show_frame("quarantine")
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            btn_box, text="🔄 Generate Test Threat", fg_color="#059669", hover_color="#047857",
            command=self.action_generate_test_threat
        ).pack(side="left", padx=10)

        # Overview Summary Box
        summary_frame = ctk.CTkFrame(frame, corner_radius=12)
        summary_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", pady=(0, 10))
        
        lbl_summary_header = ctk.CTkLabel(summary_frame, text="Antivirus Engine Specifications", font=ctk.CTkFont(size=15, weight="bold"))
        lbl_summary_header.pack(anchor="w", padx=20, pady=(15, 10))

        info_text = (
            "• Hash Algorithm   : SHA-256 (256-bit Secure Hash Algorithm)\n"
            "• Detection Method : Cryptographic Signature Pattern Matching\n"
            "• File Handling    : Safe Non-Executable Chunked Binary Stream (64KB Chunks)\n"
            "• Quarantine       : Isolated Folder with Encrypted Metadata Tracking Manifest\n"
            "• Execution Mode   : Educational Multithreaded Sandbox Simulation"
        )
        lbl_info = ctk.CTkLabel(summary_frame, text=info_text, justify="left", font=ctk.CTkFont(size=13))
        lbl_info.pack(anchor="w", padx=20, pady=(0, 15))

        return frame

    def create_card(self, parent, row, col, title, val, color):
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=row, column=col, padx=8, pady=10, sticky="ew")

        lbl_title = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color="#9CA3AF")
        lbl_title.pack(padx=15, pady=(15, 5))

        lbl_val = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(size=28, weight="bold"), text_color=color)
        lbl_val.pack(padx=15, pady=(0, 15))
        return lbl_val

    def refresh_dashboard_metrics(self):
        history = self.history_manager.get_history()
        quarantine_items = self.quarantine_manager.get_quarantined_items()

        total_scanned = sum(item.get("scanned_count", item.get("total_files", 0)) for item in history)
        safe_files = sum(item.get("safe_files", 0) for item in history)
        threats_detected = sum(item.get("threats_detected", 0) for item in history)
        quarantined_count = len(quarantine_items)

        self.card_total.configure(text=str(total_scanned))
        self.card_safe.configure(text=str(safe_files))
        self.card_threats.configure(text=str(threats_detected))
        self.card_quarantine.configure(text=str(quarantined_count))

        if threats_detected > 0 and quarantined_count < threats_detected:
            self.dash_banner_label.configure(
                text="⚠️  System Status: Unresolved Threats Found in Scan Logs! Check Quarantine.",
                text_color="#F59E0B"
            )
        else:
            self.dash_banner_label.configure(
                text="🛡️  System Status: Protected & Monitoring Active",
                text_color="#10B981"
            )

    def action_quick_scan(self):
        self.show_frame("scanner")
        self.select_folder()

    def action_generate_test_threat(self):
        from create_test_threat import generate_test_environment
        try:
            generate_test_environment()
            messagebox.showinfo(
                "Test Environment Created", 
                "Harmless test threat file and test_files/ directory created successfully!\n\n"
                "You can now select the 'test_files' folder in the File Scanner to test detection."
            )
            self.sig_manager.load_signatures()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate test environment: {e}")

    # -------------------------------------------------------------------
    # 2. FILE SCANNER FRAME
    # -------------------------------------------------------------------
    def build_scanner_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        # Header
        lbl_title = ctk.CTkLabel(frame, text="File & Folder Signature Scanner", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Folder Selection Section
        folder_card = ctk.CTkFrame(frame, corner_radius=12)
        folder_card.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        lbl_select = ctk.CTkLabel(folder_card, text="Target Folder:", font=ctk.CTkFont(size=14, weight="bold"))
        lbl_select.pack(side="left", padx=(15, 10), pady=15)

        self.entry_folder_path = ctk.CTkEntry(folder_card, placeholder_text="Click 'Browse Folder' to select directory...", width=450)
        self.entry_folder_path.pack(side="left", padx=5, pady=15, fill="x", expand=True)

        btn_browse = ctk.CTkButton(folder_card, text="📁 Browse Folder", width=120, command=self.select_folder)
        btn_browse.pack(side="left", padx=10, pady=15)

        self.btn_start_scan = ctk.CTkButton(
            folder_card, text="▶ Start Scan", width=120, fg_color="#10B981", hover_color="#059669",
            command=self.start_scan
        )
        self.btn_start_scan.pack(side="left", padx=(0, 15), pady=15)

        # Progress & Status Card
        progress_card = ctk.CTkFrame(frame, corner_radius=12)
        progress_card.grid(row=2, column=0, sticky="ew", pady=(0, 15))

        self.lbl_scan_status = ctk.CTkLabel(progress_card, text="Status: Ready to scan", font=ctk.CTkFont(size=13, weight="bold"))
        self.lbl_scan_status.pack(anchor="w", padx=20, pady=(12, 5))

        self.progress_bar = ctk.CTkProgressBar(progress_card)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))
        self.progress_bar.set(0.0)

        self.lbl_current_file = ctk.CTkLabel(
            progress_card, text="Current File: None", font=ctk.CTkFont(size=11),
            text_color="#9CA3AF", anchor="w"
        )
        self.lbl_current_file.pack(fill="x", padx=20, pady=(0, 12))

        # Threat Alert Banner (Hidden by default)
        self.threat_alert_banner = ctk.CTkFrame(frame, fg_color="#7F1D1D", corner_radius=10)
        # Not gridded initially
        self.lbl_threat_alert = ctk.CTkLabel(
            self.threat_alert_banner, 
            text="🚨 THREAT DETECTED! Malicious Signature Match Identified.",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#FCA5A5"
        )
        self.lbl_threat_alert.pack(side="left", padx=20, pady=10)

        self.btn_quarantine_all = ctk.CTkButton(
            self.threat_alert_banner, text="🛡️ Quarantine All Threats",
            fg_color="#EF4444", hover_color="#DC2626",
            command=self.quarantine_all_threats
        )
        self.btn_quarantine_all.pack(side="right", padx=20, pady=10)

        # Scanned Results Scrollable View
        results_container = ctk.CTkFrame(frame, corner_radius=12)
        results_container.grid(row=4, column=0, sticky="nsew")
        results_container.grid_rowconfigure(1, weight=1)
        results_container.grid_columnconfigure(0, weight=1)

        lbl_res_header = ctk.CTkLabel(results_container, text="Scan Results Log", font=ctk.CTkFont(size=15, weight="bold"))
        lbl_res_header.grid(row=0, column=0, sticky="w", padx=15, pady=10)

        self.scroll_results = ctk.CTkScrollableFrame(results_container, fg_color="transparent")
        self.scroll_results.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        return frame

    def select_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self.selected_folder = folder
            self.entry_folder_path.delete(0, tk.END)
            self.entry_folder_path.insert(0, folder)

    def start_scan(self):
        folder = self.entry_folder_path.get().strip()
        if not folder or not os.path.exists(folder):
            messagebox.showwarning("Invalid Folder", "Please select a valid folder before starting the scan.")
            return

        # Clear previous results
        for widget in self.scroll_results.winfo_children():
            widget.destroy()

        self.current_scan_results.clear()
        self.active_scan_threats.clear()
        self.threat_alert_banner.grid_forget()

        self.btn_start_scan.configure(state="disabled", text="Scanning...")
        self.lbl_scan_status.configure(text="Status: Scanning files...", text_color="#3B82F6")
        self.progress_bar.set(0.0)

        # Start background scan thread
        self.scanner_engine.start_scan(
            target_folder=folder,
            on_progress=self._on_scan_progress,
            on_complete=self._on_scan_complete,
            on_error=self._on_scan_error
        )

    def _on_scan_progress(self, scanned_count, total_files, filepath, result_item):
        def update_gui():
            pct = scanned_count / max(total_files, 1)
            self.progress_bar.set(pct)
            self.lbl_scan_status.configure(text=f"Status: Scanned {scanned_count} of {total_files} files")
            self.lbl_current_file.configure(text=f"Current: {filepath}")

            self.current_scan_results.append(result_item)
            if result_item["status"] == "THREAT DETECTED":
                self.active_scan_threats.append(result_item)
                self.threat_alert_banner.grid(row=3, column=0, sticky="ew", pady=(0, 15))

            self.render_result_row(result_item)

        self.after(0, update_gui)

    def render_result_row(self, item):
        row = ctk.CTkFrame(self.scroll_results, corner_radius=8, fg_color="#1F2937")
        row.pack(fill="x", padx=5, pady=4)

        status = item["status"]
        if status == "THREAT DETECTED":
            badge_color = "#EF4444"
            badge_text = "🚨 THREAT"
        elif status == "SAFE":
            badge_color = "#10B981"
            badge_text = "✔ SAFE"
        else:
            badge_color = "#F59E0B"
            badge_text = "⚠️ READ ERR"

        # Status badge
        lbl_badge = ctk.CTkLabel(
            row, text=badge_text, fg_color=badge_color, text_color="white",
            corner_radius=6, font=ctk.CTkFont(size=11, weight="bold"), width=80
        )
        lbl_badge.pack(side="left", padx=10, pady=8)

        # File Details
        info_frame = ctk.CTkFrame(row, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        lbl_filename = ctk.CTkLabel(info_frame, text=item["filename"], font=ctk.CTkFont(size=13, weight="bold"), anchor="w")
        lbl_filename.pack(anchor="w")

        sub_text = f"Path: {item['filepath']}  |  SHA-256: {item['sha256'][:24]}..."
        if item["threat_name"]:
            sub_text = f"Malware: {item['threat_name']}  |  " + sub_text

        lbl_sub = ctk.CTkLabel(info_frame, text=sub_text, font=ctk.CTkFont(size=11), text_color="#9CA3AF", anchor="w")
        lbl_sub.pack(anchor="w")

        # Action Button (Quarantine if threat)
        if status == "THREAT DETECTED":
            btn_quar = ctk.CTkButton(
                row, text="Quarantine", width=90, height=28,
                fg_color="#DC2626", hover_color="#B91C1C",
                command=lambda f=item["filepath"], h=item["sha256"], t=item["threat_name"], r=row: self.quarantine_single_file(f, h, t, r)
            )
            btn_quar.pack(side="right", padx=10, pady=8)

    def quarantine_single_file(self, filepath, sha256, threat_name, row_widget):
        success, msg = self.quarantine_manager.quarantine_file(filepath, sha256, threat_name)
        if success:
            messagebox.showinfo("Quarantine Successful", msg)
            row_widget.destroy()
            self.refresh_dashboard_metrics()
        else:
            messagebox.showerror("Quarantine Failed", msg)

    def quarantine_all_threats(self):
        if not self.active_scan_threats:
            messagebox.showinfo("No Threats", "No unhandled threats to quarantine.")
            return

        success_count = 0
        for item in list(self.active_scan_threats):
            filepath = item["filepath"]
            sha256 = item["sha256"]
            threat_name = item["threat_name"]
            ok, _ = self.quarantine_manager.quarantine_file(filepath, sha256, threat_name)
            if ok:
                success_count += 1

        messagebox.showinfo("Bulk Quarantine", f"Successfully quarantined {success_count} threat file(s).")
        self.threat_alert_banner.grid_forget()
        self.refresh_dashboard_metrics()
        # Refresh current view
        for widget in self.scroll_results.winfo_children():
            widget.destroy()
        for item in self.current_scan_results:
            if not os.path.exists(item["filepath"]):
                item["status"] = "QUARANTINED"
            self.render_result_row(item)

    def _on_scan_complete(self, summary, results_list):
        def finalize():
            self.btn_start_scan.configure(state="normal", text="▶ Start Scan")
            self.progress_bar.set(1.0)
            self.lbl_current_file.configure(text="Scan Finished.")

            status_msg = f"Completed! Scanned {summary['scanned_count']} files. Threats Found: {summary['threat_count']}"
            color = "#10B981" if summary['threat_count'] == 0 else "#EF4444"
            self.lbl_scan_status.configure(text=status_msg, text_color=color)

            # Save scan history
            self.history_manager.log_scan(
                folder_path=summary["target_folder"],
                total_files=summary["scanned_count"],
                safe_files=summary["safe_count"],
                threats_detected=summary["threat_count"],
                quarantined_files=0,
                duration_seconds=summary["duration"]
            )
            self.refresh_dashboard_metrics()

            messagebox.showinfo(
                "Scan Finished",
                f"Scan Complete!\n\n"
                f"• Total Files Scanned : {summary['scanned_count']}\n"
                f"• Safe Files          : {summary['safe_count']}\n"
                f"• Threats Detected    : {summary['threat_count']}\n"
                f"• Scan Duration       : {summary['duration']:.2f} seconds"
            )

        self.after(0, finalize)

    def _on_scan_error(self, err_msg):
        def handle_err():
            self.btn_start_scan.configure(state="normal", text="▶ Start Scan")
            self.lbl_scan_status.configure(text=f"Error: {err_msg}", text_color="#EF4444")
            messagebox.showerror("Scan Error", err_msg)
        self.after(0, handle_err)

    # -------------------------------------------------------------------
    # 3. QUARANTINE FRAME
    # -------------------------------------------------------------------
    def build_quarantine_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        lbl_title = ctk.CTkLabel(frame, text="Quarantined Files Manager", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.grid(row=0, column=0, sticky="w", pady=(0, 15))

        container = ctk.CTkFrame(frame, corner_radius=12)
        container.grid(row=1, column=0, sticky="nsew")
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(container, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=15, pady=10)

        ctk.CTkLabel(top_bar, text="Isolated Threats in Sandbox", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        ctk.CTkButton(top_bar, text="🔄 Refresh List", width=100, command=self.refresh_quarantine_view).pack(side="right")

        self.scroll_quarantine = ctk.CTkScrollableFrame(container, fg_color="transparent")
        self.scroll_quarantine.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        return frame

    def refresh_quarantine_view(self):
        for widget in self.scroll_quarantine.winfo_children():
            widget.destroy()

        items = self.quarantine_manager.get_quarantined_items()
        if not items:
            lbl_empty = ctk.CTkLabel(
                self.scroll_quarantine, text="No files currently in quarantine.",
                font=ctk.CTkFont(size=14), text_color="#9CA3AF"
            )
            lbl_empty.pack(pady=40)
            return

        for item in items:
            row = ctk.CTkFrame(self.scroll_quarantine, corner_radius=8, fg_color="#1F2937")
            row.pack(fill="x", padx=5, pady=5)

            lbl_icon = ctk.CTkLabel(row, text="🛡️", font=ctk.CTkFont(size=20))
            lbl_icon.pack(side="left", padx=12, pady=10)

            info_box = ctk.CTkFrame(row, fg_color="transparent")
            info_box.pack(side="left", fill="x", expand=True, padx=5)

            lbl_name = ctk.CTkLabel(
                info_box, text=f"{item['original_filename']} ({item['threat_name']})",
                font=ctk.CTkFont(size=13, weight="bold"), anchor="w"
            )
            lbl_name.pack(anchor="w")

            meta = f"Original Path: {item['original_path']}\nQuarantined Date: {item['timestamp']}  |  SHA-256: {item['sha256_hash'][:24]}..."
            lbl_meta = ctk.CTkLabel(info_box, text=meta, font=ctk.CTkFont(size=11), text_color="#9CA3AF", justify="left", anchor="w")
            lbl_meta.pack(anchor="w")

            btn_box = ctk.CTkFrame(row, fg_color="transparent")
            btn_box.pack(side="right", padx=10)

            ctk.CTkButton(
                btn_box, text="Restore", width=75, height=28, fg_color="#3B82F6", hover_color="#2563EB",
                command=lambda q_id=item["id"]: self.action_restore_quarantine(q_id)
            ).pack(side="left", padx=4)

            ctk.CTkButton(
                btn_box, text="Delete", width=75, height=28, fg_color="#EF4444", hover_color="#DC2626",
                command=lambda q_id=item["id"]: self.action_delete_quarantine(q_id)
            ).pack(side="left", padx=4)

    def action_restore_quarantine(self, item_id):
        if messagebox.askyesno("Confirm Restore", "Are you sure you want to restore this file to its original path?"):
            ok, msg = self.quarantine_manager.restore_file(item_id)
            if ok:
                messagebox.showinfo("Restored", msg)
            else:
                messagebox.showerror("Error", msg)
            self.refresh_quarantine_view()
            self.refresh_dashboard_metrics()

    def action_delete_quarantine(self, item_id):
        if messagebox.askyesno("Confirm Permanent Delete", "Are you sure you want to permanently delete this file from quarantine?"):
            ok, msg = self.quarantine_manager.delete_quarantined_file(item_id)
            if ok:
                messagebox.showinfo("Deleted", msg)
            else:
                messagebox.showerror("Error", msg)
            self.refresh_quarantine_view()
            self.refresh_dashboard_metrics()

    # -------------------------------------------------------------------
    # 4. SIGNATURE DATABASE FRAME
    # -------------------------------------------------------------------
    def build_signatures_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        lbl_title = ctk.CTkLabel(frame, text="Malware Signature Database (signatures.json)", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Add Custom Signature Card
        add_card = ctk.CTkFrame(frame, corner_radius=12)
        add_card.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        lbl_add_hdr = ctk.CTkLabel(add_card, text="➕ Register New Test Signature", font=ctk.CTkFont(size=14, weight="bold"))
        lbl_add_hdr.pack(anchor="w", padx=15, pady=(12, 8))

        form_box = ctk.CTkFrame(add_card, fg_color="transparent")
        form_box.pack(fill="x", padx=15, pady=(0, 12))

        self.ent_sig_name = ctk.CTkEntry(form_box, placeholder_text="Malware Name (e.g., Test_Virus_A)", width=200)
        self.ent_sig_name.pack(side="left", padx=5)

        self.ent_sig_hash = ctk.CTkEntry(form_box, placeholder_text="SHA-256 Hash (64 hex chars)", width=360)
        self.ent_sig_hash.pack(side="left", padx=5)

        self.ent_sig_desc = ctk.CTkEntry(form_box, placeholder_text="Description", width=220)
        self.ent_sig_desc.pack(side="left", padx=5)

        btn_add_sig = ctk.CTkButton(form_box, text="Add Signature", width=110, command=self.add_custom_signature)
        btn_add_sig.pack(side="left", padx=5)

        # Database View Scrollable
        db_container = ctk.CTkFrame(frame, corner_radius=12)
        db_container.grid(row=2, column=0, sticky="nsew")
        db_container.grid_rowconfigure(1, weight=1)
        db_container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(db_container, text="Active Known Malware Hash Signatures", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w", padx=15, pady=10)

        self.scroll_signatures = ctk.CTkScrollableFrame(db_container, fg_color="transparent")
        self.scroll_signatures.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        return frame

    def refresh_signatures_view(self):
        for widget in self.scroll_signatures.winfo_children():
            widget.destroy()

        sigs = self.sig_manager.get_all_signatures()
        if not sigs:
            ctk.CTkLabel(self.scroll_signatures, text="No signatures loaded.", text_color="#9CA3AF").pack(pady=20)
            return

        for item in sigs:
            row = ctk.CTkFrame(self.scroll_signatures, corner_radius=8, fg_color="#1F2937")
            row.pack(fill="x", padx=5, pady=4)

            lbl_badge = ctk.CTkLabel(
                row, text=item.get("severity", "HIGH"), fg_color="#DC2626", text_color="white",
                corner_radius=6, font=ctk.CTkFont(size=10, weight="bold"), width=90
            )
            lbl_badge.pack(side="left", padx=10, pady=8)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=5, pady=6)

            ctk.CTkLabel(info, text=item["malware_name"], font=ctk.CTkFont(size=13, weight="bold"), anchor="w").pack(anchor="w")
            
            sub = f"SHA-256: {item['sha256_hash']}\nDescription: {item.get('description', 'N/A')}"
            ctk.CTkLabel(info, text=sub, font=ctk.CTkFont(size=11), text_color="#9CA3AF", justify="left", anchor="w").pack(anchor="w")

    def add_custom_signature(self):
        name = self.ent_sig_name.get().strip()
        h_val = self.ent_sig_hash.get().strip()
        desc = self.ent_sig_desc.get().strip() or "Custom user added test signature"

        if not name or not h_val:
            messagebox.showwarning("Missing Data", "Please provide both Malware Name and SHA-256 Hash.")
            return

        ok, msg = self.sig_manager.add_signature(name, h_val, desc)
        if ok:
            messagebox.showinfo("Success", msg)
            self.ent_sig_name.delete(0, tk.END)
            self.ent_sig_hash.delete(0, tk.END)
            self.ent_sig_desc.delete(0, tk.END)
            self.refresh_signatures_view()
        else:
            messagebox.showerror("Error", msg)

    # -------------------------------------------------------------------
    # 5. SCAN HISTORY FRAME
    # -------------------------------------------------------------------
    def build_history_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        lbl_title = ctk.CTkLabel(frame, text="Scan History & Logs", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.grid(row=0, column=0, sticky="w", pady=(0, 15))

        container = ctk.CTkFrame(frame, corner_radius=12)
        container.grid(row=1, column=0, sticky="nsew")
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(container, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=15, pady=10)

        ctk.CTkLabel(top, text="Previous Scan Audit Logs", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="🗑️ Clear Logs", width=100, fg_color="#DC2626", hover_color="#B91C1C", command=self.clear_scan_history).pack(side="right")

        self.scroll_history = ctk.CTkScrollableFrame(container, fg_color="transparent")
        self.scroll_history.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        return frame

    def refresh_history_view(self):
        for widget in self.scroll_history.winfo_children():
            widget.destroy()

        history = self.history_manager.get_history()
        if not history:
            ctk.CTkLabel(self.scroll_history, text="No scan history available.", text_color="#9CA3AF").pack(pady=30)
            return

        for item in history:
            row = ctk.CTkFrame(self.scroll_history, corner_radius=8, fg_color="#1F2937")
            row.pack(fill="x", padx=5, pady=4)

            t_count = item.get("threats_detected", 0)
            status_color = "#EF4444" if t_count > 0 else "#10B981"
            status_text = f"🚨 {t_count} THREATS" if t_count > 0 else "✔ SECURE"

            lbl_b = ctk.CTkLabel(
                row, text=status_text, fg_color=status_color, text_color="white",
                corner_radius=6, font=ctk.CTkFont(size=11, weight="bold"), width=95
            )
            lbl_b.pack(side="left", padx=10, pady=10)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=5, pady=6)

            ctk.CTkLabel(info, text=f"Scan Date: {item['timestamp']}  |  Folder: {item['folder_scanned']}", font=ctk.CTkFont(size=13, weight="bold"), anchor="w").pack(anchor="w")

            metrics_str = f"Scanned: {item.get('scanned_count', item.get('total_files', 0))}  |  Safe: {item.get('safe_files', 0)}  |  Threats: {item.get('threats_detected', 0)}  |  Duration: {item.get('duration_seconds', 0.0)}s"
            ctk.CTkLabel(info, text=metrics_str, font=ctk.CTkFont(size=11), text_color="#9CA3AF", anchor="w").pack(anchor="w")

    def clear_scan_history(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all scan history logs?"):
            self.history_manager.clear_history()
            self.refresh_history_view()
            self.refresh_dashboard_metrics()

    # -------------------------------------------------------------------
    # 6. ABOUT & LEGAL FRAME
    # -------------------------------------------------------------------
    def build_about_frame(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)

        lbl_title = ctk.CTkLabel(frame, text="About & Educational Disclaimer", font=ctk.CTkFont(size=24, weight="bold"))
        lbl_title.pack(anchor="w", pady=(0, 15))

        card = ctk.CTkFrame(frame, corner_radius=12)
        card.pack(fill="both", expand=True)

        lbl_hdr = ctk.CTkLabel(card, text="Basic Antivirus Simulation – Signature Scanner", font=ctk.CTkFont(size=18, weight="bold"))
        lbl_hdr.pack(anchor="w", padx=20, pady=(20, 10))

        disclaimer_text = (
            "⚠️ EDUCATIONAL & ETHICAL NOTICE:\n\n"
            "This antivirus simulation is developed strictly for educational and ethical cybersecurity purposes. "
            "It demonstrates signature-based malware detection using SHA-256 cryptographic hashes and does not replace real commercial antivirus software.\n\n"
            "PROJECT HIGHLIGHTS:\n"
            "1. SHA-256 File Hashing : Reads files in non-executable 64KB binary chunks using hashlib.\n"
            "2. Signature DB Matching: Compares calculated hashes against known malware signatures in signatures.json.\n"
            "3. Isolated Quarantine   : Moves detected threat files safely into a local quarantine folder without auto-deleting.\n"
            "4. Multithreaded Engine  : Asynchronous file scanning ensuring an ultra-responsive CustomTkinter GUI.\n"
            "5. Safe Demonstration   : Includes create_test_threat.py to safely generate benign test threats for internship presentation.\n\n"
            "DEVELOPED FOR:\n"
            "Academic Evaluation & Internship Presentation Demonstration."
        )

        lbl_desc = ctk.CTkLabel(
            card, text=disclaimer_text, justify="left",
            font=ctk.CTkFont(size=13), text_color="#E2E8F0"
        )
        lbl_desc.pack(anchor="w", padx=20, pady=(0, 20))

        return frame

if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()
