# EBS Sentinel DFIR X

Advanced Android DFIR (Digital Forensics & Incident Response), Threat Hunting, Mobile EDR and Active Response Platform.

## Features

### Device Forensics

* Android device acquisition via ADB
* Device metadata collection
* Security patch analysis
* System access auditing

### Application Analysis

* Installed application inventory
* Permission analysis
* Risk scoring engine
* Application categorization

### Network Intelligence

* Socket analysis
* Remote endpoint identification
* Country detection
* ASN and company attribution
* Threat intelligence enrichment

### Crash & Log Analysis

* Logcat monitoring
* Crash detection
* Suspicious activity classification
* Real-time forensic alerts

### Threat Hunting

* IOC searching
* Custom hunt queries
* Timeline correlation
* Attack surface discovery

### Mobile EDR

* Active response actions
* Force-stop applications
* Suspend / Unsuspend packages
* Process termination
* Background restriction controls

### Threat Intelligence

* IOC correlation
* MITRE ATT&CK mapping
* Risk scoring
* Threat classification

### Evidence Management

* Evidence locker
* SHA256 hashing
* APK extraction
* Case management

### Reporting

* HTML forensic reports
* Timeline generation
* Risk summaries
* Investigation artifacts

---

## Screenshots

Add screenshots here.

---

## Requirements

* Python 3.10+
* Android Debug Bridge (ADB)
* PySide6

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Connect an Android device:

```bash
adb devices
```

Run:

```bash
python ebs_sentinel.py
```

---

## Project Structure

```text
core/
 ├── adb_client.py
 ├── device_info.py
 ├── app_analyzer.py
 ├── network_analyzer.py
 ├── log_analyzer.py
 ├── system_access.py
 ├── process_monitor.py
 ├── active_response.py
 ├── evidence_locker.py
 ├── risk_engine.py
 ├── timeline.py
 ├── report_generator.py
 ├── threat_intel.py
 └── advanced_features.py

main.py
```

---

## Capabilities

* Android Forensics
* Threat Hunting
* Mobile EDR
* Incident Response
* Threat Intelligence
* YARA Analysis
* Live Log Monitoring
* Evidence Collection
* Timeline Analysis

---

## Disclaimer

This project is intended for authorized security research, incident response, digital forensics and defensive security operations.

Use only on systems and devices for which you have explicit authorization.

---

## License

MIT License

Copyright (c) 2026 EBS Cyber Security
