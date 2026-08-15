# Basic Antivirus Simulation – Signature Scanner

A professional, educational, beginner-friendly Python cybersecurity project demonstrating signature-based malware detection using **SHA-256 cryptographic hashes**, **CustomTkinter GUI**, isolated **quarantine management**, and **scan history audit logging**.

---

## ⚠️ Educational Disclaimer
> **This antivirus simulation is developed strictly for educational and ethical cybersecurity purposes. It demonstrates signature-based malware detection using SHA-256 hashes and does not replace real antivirus software. Do NOT use or download real malware.**

---

## 📌 Problem Statement
Traditional computer systems are exposed to malicious software (malware). Modern security systems employ multiple layers of defense, with **signature-based scanning** being one of the fundamental techniques. This project addresses the educational need to understand how signature scanners calculate file fingerprints (hashes), compare them with known threat databases, isolate malicious files without executing them, and maintain audit logs.

---

## 🎯 Project Objective
1. Demystify signature-based antivirus mechanics using clear Python 3 code.
2. Demonstrate memory-safe file reading and cryptographic hashing (**SHA-256**).
3. Build a modern, responsive cybersecurity dashboard UI using **CustomTkinter**.
4. Provide a safe sandbox quarantine system using `shutil` and metadata manifests.
5. Offer a 100% harmless, reproducible test environment for internship evaluation and presentation.

---

## 🛠️ Technologies Used
- **Python 3**: Core language.
- **CustomTkinter**: Modern GUI framework for dark-mode desktop applications.
- **hashlib**: Standard library module for computing SHA-256 hashes.
- **os & pathlib**: Operating system interface for file system traversal.
- **shutil**: Secure file relocation for quarantine operations.
- **json**: Lightweight storage for signature database, quarantine manifest, and scan history logs.
- **threading**: Background processing ensuring the GUI remains responsive during scans.

---

## 🌟 Core Features

1. **Cybersecurity Dashboard**:
   - Live system protection status indicator.
   - 4 real-time stat cards: Total Files Scanned, Safe Files, Threats Detected, Quarantined Files.
   - Quick action shortcuts.

2. **Folder Scanner Engine**:
   - Recursive folder traversal (`os.walk`).
   - Non-executable binary file reading in 64KB chunks (`hashlib.sha256()`).
   - Multithreaded scanning (zero GUI freezing).
   - Real-time progress bar, current file label, and results table with status badges (`SAFE`, `THREAT`, `READ ERROR`).

3. **Signature Database (`signatures.json`)**:
   - JSON-backed signature repository storing `malware_name`, `sha256_hash`, `description`, and `severity`.
   - UI form to dynamically register custom test signatures.

4. **Quarantine Sandbox System**:
   - Moves threat files into an isolated `quarantine/` directory.
   - Appends `.vir` extension and random ID to prevent accidental execution.
   - Stores metadata (original path, quarantine timestamp, hash, threat name) in `quarantine_manifest.json`.
   - Options to **Restore** file back to original location or **Delete** permanently upon user confirmation.

5. **Scan History & Audit Logs**:
   - Logs scan sessions (`scan_history.json`) with timestamps, folder path, total files, safe files, threats detected, and duration.
   - Dedicated GUI section to view and audit previous scans.

6. **Robust Error Handling**:
   - Catches `PermissionError`, missing files, unreadable binaries, and directory permission locks without crashing.

---

## 📁 Project Structure

```
basic_antivirus/
│
├── main.py                 # Main CustomTkinter GUI application & navigation
├── scanner.py              # Multithreaded scanning engine & file hashing loop
├── hash_utils.py           # Memory-safe SHA-256 chunked hashing helper
├── quarantine.py           # Sandbox quarantine manager & manifest logger
├── signature_manager.py    # Signature DB manager (loads & queries signatures.json)
├── history_manager.py      # Historical scan logger (loads & saves scan_history.json)
├── create_test_threat.py   # Script to generate benign test files & test signatures
├── signatures.json         # Known malware SHA-256 signature database
├── scan_history.json       # Historical scan audit logs
├── quarantine/             # Isolated directory for quarantined threat files
├── test_files/             # Sample test directory containing harmless test files
├── README.md               # Detailed project documentation & presentation guide
└── requirements.txt        # Python dependency list (customtkinter, pillow)
```

---

## ⚙️ How It Works (Technical Explanation)

### 1. Signature-Based Detection Mechanics
Signature-based detection compares unique "fingerprints" of files against a database of known malware fingerprints. If a file's hash matches a known malicious hash in `signatures.json`, it is flagged as a threat.

### 2. SHA-256 Hashing Workflow
- The scanner opens files in **binary read mode (`rb`)**.
- It reads data in fixed **64KB (65,536 bytes) chunks**.
- This chunked reading ensures that even large files (e.g. 2GB) can be hashed efficiently without crashing system RAM.
- `hashlib.sha256()` outputs a unique 64-character hexadecimal digest.

### 3. Quarantine Workflow
- When a threat is detected, the user can click **Quarantine**.
- `shutil.move()` safely transfers the file from its original folder into `quarantine/`.
- The filename is obfuscated (e.g. `QUARANTINED_a1b2c3d4_filename.vir`).
- The original path and metadata are saved to `quarantine_manifest.json` so the user can restore it if it was a false positive.

---

## 🚀 Installation & Setup Instructions

### Step 1: Open Terminal / Command Prompt
Navigate to the project folder:
```bash
cd "C:\Users\Nidhi Rohit Jaiswar\.gemini\antigravity\scratch\basic_antivirus"
```

### Step 2: Install Dependencies
Install required packages using pip:
```bash
pip install -r requirements.txt
```

---

## 🧪 Safe Testing Procedure (Demonstration Setup)

Follow these steps to demonstrate the application to evaluators:

### Step 1: Generate Harmless Test Environment
Run the test setup script:
```bash
python create_test_threat.py
```
This automatically:
1. Creates a `test_files/` directory.
2. Writes benign text files (`sample_document.txt`, `notes.txt`).
3. Writes a harmless simulated threat file (`eicar_simulated_threat.txt`).
4. Computes the SHA-256 hash of the test threat file and registers it in `signatures.json`.

### Step 2: Launch the Antivirus Simulation
Run the main GUI application:
```bash
python main.py
```

### Step 3: Demonstrate Threat Detection & Quarantine
1. On the **Dashboard**, click **⚡ Select & Scan Folder** (or navigate to **🔍 File Scanner**).
2. Click **📁 Browse Folder** and select the `test_files` directory inside `basic_antivirus`.
3. Click **▶ Start Scan**.
4. Observe the progress bar and real-time scanning log.
5. Notice the **🚨 THREAT DETECTED** red banner appearing for `eicar_simulated_threat.txt`.
6. Click **Quarantine** next to the file (or **Quarantine All Threats**).
7. Navigate to **🛡️ Quarantine** to view the isolated file, metadata, and test the **Restore** or **Delete** feature.
8. Navigate to **📊 Scan History** to show the saved audit trail log.

---

## ⚠️ Limitations
- **Signature Only**: Does not detect unknown/zero-day threats (requires heuristic/behavioral analysis).
- **Exact Hash Matching**: Slight modification to a file changes its SHA-256 hash entirely (avalanche effect).
- **Manual Database Updates**: Signatures must be registered in `signatures.json`.

---

## 🔮 Future Enhancements
- Fuzzy hashing (e.g., SSDEEP / Trend Micro Locality Sensitive Hashing) for partial malware pattern matching.
- Real-time file system watcher (`watchdog` module) to scan files as soon as they are created or modified.
- Cloud database API integration for signature updates.
- YARA rule engine integration.

---

## 🎓 Academic Presentation & Viva Q&A Guide

**Q1: Why did you use SHA-256 instead of MD5?**  
*Answer:* MD5 is cryptographically broken due to hash collision vulnerabilities. SHA-256 provides a 256-bit secure fingerprint resistant to collisions.

**Q2: How do you prevent memory overload during file hashing?**  
*Answer:* We read files in 64KB chunks (`f.read(65536)`) using `hashlib`, ensuring constant RAM usage regardless of file size.

**Q3: How does quarantine prevent accidental malware execution?**  
*Answer:* The file is moved to an isolated project folder (`quarantine/`), renamed with a random ID, and assigned a `.vir` non-executable file extension.

**Q4: Why does the GUI remain smooth during scanning?**  
*Answer:* The file processing loop runs inside a separate background thread (`threading.Thread`), communicating with the CustomTkinter main loop asynchronously.
