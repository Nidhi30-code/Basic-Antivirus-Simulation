import os
import time
import threading
from hash_utils import calculate_sha256

class ScannerEngine:
    """
    Multithreaded signature scanning engine that recursively searches folders,
    computes file hashes, checks against signature database, and emits progress updates.
    """
    def __init__(self, signature_manager):
        self.sig_manager = signature_manager
        self.is_scanning = False
        self.stop_requested = False
        self.scan_thread = None

    def start_scan(self, target_folder, on_progress=None, on_complete=None, on_error=None):
        """
        Starts a background scanning thread.

        :param target_folder: Directory path to scan recursively.
        :param on_progress: Callback function(scanned_count, total_files, current_file, file_result)
        :param on_complete: Callback function(summary_dict, results_list)
        :param on_error: Callback function(error_message_str)
        """
        if self.is_scanning:
            if on_error:
                on_error("A scan is already in progress.")
            return

        if not os.path.exists(target_folder) or not os.path.isdir(target_folder):
            if on_error:
                on_error("Invalid or non-existent folder selected.")
            return

        self.is_scanning = True
        self.stop_requested = False

        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target_folder, on_progress, on_complete, on_error),
            daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self):
        """Requests cancellation of current scan."""
        if self.is_scanning:
            self.stop_requested = True

    def _run_scan(self, target_folder, on_progress, on_complete, on_error):
        start_time = time.time()
        file_paths = []

        # 1. Discover all files recursively
        try:
            for root, _, files in os.walk(target_folder):
                for f in files:
                    file_paths.append(os.path.join(root, f))
        except Exception as e:
            self.is_scanning = False
            if on_error:
                on_error(f"Error reading folder tree: {str(e)}")
            return

        total_files = len(file_paths)
        scanned_count = 0
        safe_count = 0
        threat_count = 0
        error_count = 0
        results_list = []

        # 2. Iterate through files and analyze
        for filepath in file_paths:
            if self.stop_requested:
                break

            scanned_count += 1
            filename = os.path.basename(filepath)

            # Compute hash
            sha256, err = calculate_sha256(filepath)

            result_item = {
                "filename": filename,
                "filepath": filepath,
                "sha256": sha256 or "N/A",
                "status": "SAFE",
                "threat_name": None,
                "description": None,
                "severity": None,
                "error": err
            }

            if err:
                error_count += 1
                result_item["status"] = "READ ERROR"
            else:
                # Check database
                is_match, sig_info = self.sig_manager.check_hash(sha256)
                if is_match:
                    threat_count += 1
                    result_item["status"] = "THREAT DETECTED"
                    result_item["threat_name"] = sig_info.get("malware_name", "Unknown Threat")
                    result_item["description"] = sig_info.get("description", "Known malicious signature match.")
                    result_item["severity"] = sig_info.get("severity", "HIGH")
                else:
                    safe_count += 1

            results_list.append(result_item)

            if on_progress:
                on_progress(scanned_count, total_files, filepath, result_item)

            # Brief yield to keep GUI ultra smooth
            time.sleep(0.001)

        duration = time.time() - start_time
        self.is_scanning = False

        summary = {
            "target_folder": target_folder,
            "total_files": total_files,
            "scanned_count": scanned_count,
            "safe_count": safe_count,
            "threat_count": threat_count,
            "error_count": error_count,
            "duration": duration,
            "cancelled": self.stop_requested
        }

        if on_complete:
            on_complete(summary, results_list)
