import os
import time
from hash_utils import calculate_sha256
from signature_manager import SignatureManager
from quarantine import QuarantineManager
from history_manager import HistoryManager
from scanner import ScannerEngine

def run_headless_tests():
    print("[1] Testing Signature Manager...")
    sig_mgr = SignatureManager()
    sigs = sig_mgr.get_all_signatures()
    print(f"    Loaded {len(sigs)} signatures.")

    test_folder = os.path.join(os.path.dirname(__file__), "test_files")
    threat_file = os.path.join(test_folder, "simulated_threat_file.txt")

    print("[2] Testing Hash Calculation...")
    h, err = calculate_sha256(threat_file)
    print(f"    Threat file hash: {h}")

    print("[3] Testing Signature Matching...")
    is_match, sig_info = sig_mgr.check_hash(h)
    print(f"    Match status: {is_match}, Malware: {sig_info.get('malware_name') if sig_info else None}")
    assert is_match, "Signature match failed!"

    print("[4] Testing Scanner Engine...")
    scanner = ScannerEngine(sig_mgr)
    done_event = False
    final_summary = None

    def on_prog(c, total, cur_f, item):
        pass

    def on_comp(summary, results):
        nonlocal done_event, final_summary
        final_summary = summary
        done_event = True

    scanner.start_scan(test_folder, on_progress=on_prog, on_complete=on_comp)

    # Wait for scan thread
    for _ in range(50):
        if done_event:
            break
        time.sleep(0.1)

    print(f"    Scanned: {final_summary['scanned_count']}, Threats: {final_summary['threat_count']}, Safe: {final_summary['safe_count']}")
    assert final_summary['threat_count'] >= 1, "Scanner failed to detect threat!"

    print("[5] Testing Quarantine System...")
    quarantine = QuarantineManager()
    ok, q_msg = quarantine.quarantine_file(threat_file, h, "Simulated_Educational_Threat_Pattern")
    print(f"    Quarantine result: {ok} -> {q_msg}")
    assert ok, "Quarantine failed!"

    q_items = quarantine.get_quarantined_items()
    print(f"    Quarantined items count: {len(q_items)}")

    print("[6] Testing File Restore...")
    last_id = q_items[-1]["id"]
    rest_ok, r_msg = quarantine.restore_file(last_id)
    print(f"    Restore result: {rest_ok} -> {r_msg}")
    assert rest_ok, "Restore failed!"

    print("[7] Testing History Manager...")
    history = HistoryManager()
    log = history.log_scan(test_folder, 3, 2, 1, 1, 0.05)
    print(f"    Log recorded: {log['timestamp']} | Threats: {log['threats_detected']}")

    print("\n[SUCCESS] ALL BACKEND TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_headless_tests()
