import os
import shutil
import json
import uuid
from datetime import datetime

DEFAULT_QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), "quarantine")
MANIFEST_FILE = os.path.join(DEFAULT_QUARANTINE_DIR, "quarantine_manifest.json")

class QuarantineManager:
    """
    Manages isolating threat files into a secure quarantine directory.
    Maintains a metadata manifest to log original locations and timestamps.
    """
    def __init__(self, quarantine_dir=DEFAULT_QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        self.manifest_file = os.path.join(self.quarantine_dir, "quarantine_manifest.json")
        self._ensure_dir()
        self.items = self._load_manifest()

    def _ensure_dir(self):
        """Creates quarantine directory if it doesn't exist."""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)

    def _load_manifest(self):
        """Loads metadata manifest of quarantined items."""
        if os.path.exists(self.manifest_file):
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Quarantine Error] Manifest load failed: {e}")
        return []

    def _save_manifest(self):
        """Saves updated metadata manifest to JSON."""
        try:
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=2)
        except Exception as e:
            print(f"[Quarantine Error] Manifest save failed: {e}")

    def quarantine_file(self, file_path, sha256_hash, threat_name="Unknown Threat"):
        """
        Safely moves a detected threat file into the quarantine directory.
        
        :param file_path: Path to target file.
        :param sha256_hash: File's SHA-256 hash.
        :param threat_name: Name of detected threat.
        :return: (success: bool, message: str)
        """
        if not os.path.exists(file_path):
            return False, "Target file no longer exists on disk."

        filename = os.path.basename(file_path)
        item_id = str(uuid.uuid4())[:8]
        # Rename quarantined file to avoid collisions and prevent accidental execution
        quarantined_filename = f"QUARANTINED_{item_id}_{filename}.vir"
        quarantined_path = os.path.join(self.quarantine_dir, quarantined_filename)

        try:
            # Move file safely
            shutil.move(file_path, quarantined_path)

            record = {
                "id": item_id,
                "original_filename": filename,
                "original_path": file_path,
                "quarantined_filename": quarantined_filename,
                "quarantined_path": quarantined_path,
                "sha256_hash": sha256_hash,
                "threat_name": threat_name,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            self.items.append(record)
            self._save_manifest()

            return True, f"Successfully quarantined file to {quarantined_filename}"

        except PermissionError:
            return False, "Permission denied when moving file to quarantine."
        except Exception as e:
            return False, f"Failed to quarantine file: {str(e)}"

    def get_quarantined_items(self):
        """Returns list of currently quarantined items."""
        return self.items

    def restore_file(self, item_id):
        """
        Restores a quarantined file back to its original location if requested.
        """
        for item in self.items:
            if item["id"] == item_id:
                quarantined_path = item["quarantined_path"]
                original_path = item["original_path"]

                if not os.path.exists(quarantined_path):
                    return False, "Quarantined file is missing from quarantine folder."

                orig_dir = os.path.dirname(original_path)
                if not os.path.exists(orig_dir):
                    os.makedirs(orig_dir, exist_ok=True)

                try:
                    shutil.move(quarantined_path, original_path)
                    self.items.remove(item)
                    self._save_manifest()
                    return True, f"Restored {item['original_filename']} back to {original_path}"
                except Exception as e:
                    return False, f"Failed to restore file: {str(e)}"

        return False, "Quarantined record not found."

    def delete_quarantined_file(self, item_id):
        """
        Permanently deletes a file from the quarantine folder upon user confirmation.
        """
        for item in self.items:
            if item["id"] == item_id:
                quarantined_path = item["quarantined_path"]
                try:
                    if os.path.exists(quarantined_path):
                        os.remove(quarantined_path)
                    self.items.remove(item)
                    self._save_manifest()
                    return True, f"Permanently deleted {item['original_filename']} from quarantine."
                except Exception as e:
                    return False, f"Failed to delete file: {str(e)}"

        return False, "Quarantined record not found."
