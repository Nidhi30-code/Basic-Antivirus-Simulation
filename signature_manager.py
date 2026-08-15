import json
import os

DEFAULT_SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), "signatures.json")

class SignatureManager:
    """
    Manages loading, querying, and updating the database of known malware SHA-256 signatures.
    """
    def __init__(self, db_path=DEFAULT_SIGNATURES_FILE):
        self.db_path = db_path
        self.signatures = {}  # sha256_hash.lower() -> dict record
        self.load_signatures()

    def load_signatures(self):
        """Loads malware signatures from signatures.json."""
        self.signatures.clear()
        if not os.path.exists(self.db_path):
            # Create default empty signatures file if missing
            self.save_signatures([])
            return

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        h = item.get("sha256_hash", "").strip().lower()
                        if h:
                            self.signatures[h] = item
        except Exception as e:
            print(f"[SignatureManager Error] Failed to load signatures: {e}")

    def check_hash(self, sha256_hash):
        """
        Checks if a given SHA-256 hash exists in the signature database.
        
        :param sha256_hash: SHA-256 hex string.
        :return: (is_malicious: bool, signature_info: dict or None)
        """
        if not sha256_hash:
            return False, None
        
        clean_hash = sha256_hash.strip().lower()
        if clean_hash in self.signatures:
            return True, self.signatures[clean_hash]
        
        return False, None

    def get_all_signatures(self):
        """Returns a list of all signatures."""
        return list(self.signatures.values())

    def add_signature(self, malware_name, sha256_hash, description="Harmless test signature", severity="MEDIUM (DEMO)"):
        """
        Adds a new signature record to the database and persists it to JSON.
        """
        clean_hash = sha256_hash.strip().lower()
        if not clean_hash or len(clean_hash) != 64:
            return False, "Invalid SHA-256 hash length (must be 64 hexadecimal characters)."

        record = {
            "malware_name": malware_name,
            "sha256_hash": clean_hash,
            "description": description,
            "severity": severity
        }

        self.signatures[clean_hash] = record

        try:
            records = list(self.signatures.values())
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
            return True, "Signature successfully added to database."
        except Exception as e:
            return False, f"Failed to save to JSON file: {str(e)}"
