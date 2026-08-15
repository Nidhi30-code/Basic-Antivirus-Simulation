import json
import os
from datetime import datetime

DEFAULT_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")

class HistoryManager:
    """
    Logs scan metrics and historical logs to scan_history.json.
    """
    def __init__(self, history_file=DEFAULT_HISTORY_FILE):
        self.history_file = history_file
        self.history = self.load_history()

    def load_history(self):
        """Loads scan history from JSON file."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
            except Exception as e:
                print(f"[HistoryManager Error] Failed to load scan history: {e}")
        return []

    def save_history(self):
        """Saves scan history back to JSON file."""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"[HistoryManager Error] Failed to save scan history: {e}")

    def log_scan(self, folder_path, total_files, safe_files, threats_detected, quarantined_files=0, duration_seconds=0.0):
        """
        Appends a new scan result log entry.
        """
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "folder_scanned": folder_path,
            "total_files": total_files,
            "safe_files": safe_files,
            "threats_detected": threats_detected,
            "quarantined_files": quarantined_files,
            "duration_seconds": round(duration_seconds, 2)
        }

        self.history.insert(0, record)  # Newest scans first
        self.save_history()
        return record

    def get_history(self):
        """Returns all history logs."""
        return self.history

    def clear_history(self):
        """Clears history logs."""
        self.history.clear()
        self.save_history()
