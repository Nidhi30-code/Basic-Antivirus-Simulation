import os
import hashlib
from signature_manager import SignatureManager

def generate_test_environment():
    """
    Creates a test directory with sample safe files and one harmless simulated threat file.
    Calculates the SHA-256 hash of the threat file and registers it in signatures.json
    for demonstration during presentations.
    """
    base_dir = os.path.dirname(__file__)
    test_dir = os.path.join(base_dir, "test_files")
    os.makedirs(test_dir, exist_ok=True)

    # 1. Create harmless safe files
    safe_file1 = os.path.join(test_dir, "sample_document.txt")
    with open(safe_file1, "w", encoding="utf-8") as f:
        f.write("This is a benign sample text file used to test safe file scanning.\nNo threats here!")

    safe_file2 = os.path.join(test_dir, "notes.txt")
    with open(safe_file2, "w", encoding="utf-8") as f:
        f.write("Project notes: Signature scanning matches SHA-256 cryptographic hashes.\nEverything is secure.")

    # 2. Create harmless educational test threat file
    # (Note: Using a custom educational string so real host antivirus doesn't intercept it)
    threat_file = os.path.join(test_dir, "simulated_threat_file.txt")
    threat_content = "BENIGN_SIMULATED_MALWARE_TEST_PATTERN_HASH_MATCH_2026_EDUCATIONAL_DEMO"
    with open(threat_file, "w", encoding="utf-8") as f:
        f.write(threat_content)

    # 3. Calculate SHA-256 hash of the harmless threat file
    hasher = hashlib.sha256()
    with open(threat_file, "rb") as f:
        hasher.update(f.read())
    threat_hash = hasher.hexdigest().lower()

    # 4. Register hash in signatures.json using SignatureManager
    sig_mgr = SignatureManager()
    success, msg = sig_mgr.add_signature(
        malware_name="Simulated_Educational_Threat_Pattern",
        sha256_hash=threat_hash,
        description="Harmless educational signature used to demonstrate threat detection in presentations.",
        severity="HIGH (DEMO)"
    )

    print("=" * 65)
    print("      BENIGN TEST THREAT GENERATED SUCCESSFULLY")
    print("=" * 65)
    print(f"[+] Test Directory Created : {os.path.abspath(test_dir)}")
    print(f"[+] Safe File 1            : {os.path.basename(safe_file1)}")
    print(f"[+] Safe File 2            : {os.path.basename(safe_file2)}")
    print(f"[+] Harmless Threat File   : {os.path.basename(threat_file)}")
    print(f"[+] Computed SHA-256 Hash  : {threat_hash}")
    print(f"[+] Signature DB Status    : {msg}")
    print("=" * 65)
    print("\nYou can now open the Antivirus GUI, select the 'test_files' folder,")
    print("and click 'Start Scan' to see threat detection in action!\n")

if __name__ == "__main__":
    generate_test_environment()
