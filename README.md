# 🛠️ Hack Toolkit: "CISO in a Box"

> *A collection of small, auditable security scripts for CISOs.*

![Toolkit Overview](docs/screenshots/toolkit-overview.png)
*Figure 1: Command-Line Interface Overview*

## Overview

A collection of security tools and scripts designed for CISOs who need auditable, transparent security utilities. Each tool is small, focused, and can be easily reviewed.

## Tools

### 1. `topo-hash`: Topology-Based File Integrity Checker

Uses topological data analysis to create unique file fingerprints that detect even subtle modifications.

#### **Command-Line Interface**

![topo-hash CLI](docs/screenshots/topo-hash-cli.png)
*Figure 2: topo-hash Command Output*

**Usage Example**:
```bash
$ python topo_hash.py --file document.pdf

Topo-hash: a3f8b2c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0
File: document.pdf
Size: 2.4 MB
Complexity: 0.847
```

**Verification**:
```bash
$ python topo_hash.py --file document.pdf --verify a3f8b2c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0

✓ File integrity verified
```

**Modified File Detection**:
```bash
$ python topo_hash.py --file document.pdf --verify a3f8b2c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0

✗ File integrity check failed - file has been modified
Difference detected in topological structure
```

#### **Output Format**

- **Hash Display**: 64-character hexadecimal hash
- **File Metadata**: Size, modification time
- **Topological Metrics**: Complexity score, feature count
- **Color Coding**: 
  - Green (✓) for verified
  - Red (✗) for failed
  - Yellow for warnings

### 2. `iot-sniffer-lite`: Passive IoT Monitor with LLM-Based Log Summarizer

Monitors IoT device traffic and uses a local LLM to summarize security-relevant events.

#### **Command-Line Interface**

![iot-sniffer CLI](docs/screenshots/iot-sniffer-cli.png)
*Figure 3: IoT Sniffer Real-Time Monitoring*

**Usage Example**:
```bash
$ python iot_sniffer_lite.py --interface eth0 --duration 60

Starting IoT sniffer on eth0
Capturing for 60 seconds...
[INFO] Packet captured from device_01
[INFO] Packet captured from device_02
[INFO] Packet captured from device_03
...
Capture complete. Generating summary...

============================================================
Network Activity Summary (since 2024-01-15 10:30:00):

Device 01: 1,234 packets, 2.5 MB, 15 unique connections
Device 02: 856 packets, 1.8 MB, 8 unique connections
Device 03: 432 packets, 0.9 MB, 5 unique connections

Security Assessment:
The network activity shows normal patterns for a smart home 
environment. Device 01 has higher than average connection 
count, which may indicate:
- Multiple service connections (normal for smart hubs)
- Potential scanning activity (investigate if unexpected)

Recommendation: Review Device 01's connection patterns and 
verify all connected services are authorized.
============================================================
```

#### **Real-Time Output**

- **Progress Indicator**: Packet count updates
- **Device Statistics**: Per-device packet/byte counts
- **LLM Summary**: Natural language security assessment
- **Recommendations**: Actionable security advice

### 3. `captcha-cracker-defense`: CAPTCHA Testing Tool

Tests your CAPTCHA implementation against known attack methods to identify weaknesses.

#### **Command-Line Interface**

![captcha-cracker CLI](docs/screenshots/captcha-cracker-cli.png)
*Figure 4: CAPTCHA Security Test Results*

**Usage Example**:
```bash
$ python captcha_cracker_defense.py --url https://example.com/captcha --test

Testing CAPTCHA at https://example.com/captcha
[INFO] Testing basic bypass techniques...
[INFO] Testing timing attacks...
[INFO] Testing common bypass strings...

CAPTCHA Security Test Report
==================================================

Total Tests: 8
Vulnerabilities Found: 2

✗ VULNERABLE - empty_submission
  Note: CAPTCHA accepts empty submissions

✓ PASSED - common_bypass
✓ PASSED - timing_attack
✓ PASSED - response_time_analysis
✓ PASSED - token_validation
✓ PASSED - rate_limiting
✗ VULNERABLE - session_management
  Note: Session tokens not properly invalidated

Recommendations:
1. Reject empty submissions
2. Implement proper session token invalidation
3. Add rate limiting per IP
```

#### **Test Results Display**

- **Summary Table**: Total tests, vulnerabilities found
- **Test Status**: 
  - ✓ PASSED (green)
  - ✗ VULNERABLE (red)
  - ⚠ WARNING (yellow)
- **Detailed Notes**: Explanation of each finding
- **Recommendations**: Actionable security improvements

## Installation

```bash
git clone https://github.com/yksanjo/hack-toolkit.git
cd hack-toolkit
pip install -r requirements.txt
```

## Usage Examples

### File Integrity Checking

```bash
# Generate hash
python topo_hash.py --file important_document.pdf --save document.hash

# Verify later
python topo_hash.py --file important_document.pdf --verify $(cat document.hash)
```

### IoT Monitoring

```bash
# Monitor for 5 minutes
python iot_sniffer_lite.py --interface wlan0 --duration 300

# Monitor specific device
python iot_sniffer_lite.py --interface eth0 --devices smart_home --duration 60
```

### CAPTCHA Testing

```bash
# Test your CAPTCHA
python captcha_cracker_defense.py --url https://yoursite.com/captcha --test

# Export report
python captcha_cracker_defense.py --url https://yoursite.com/captcha --test --output report.txt
```

## Screenshots

### Generating Screenshots

Since these are CLI tools, screenshots are terminal captures:

1. **Terminal Screenshots**:
   - Use terminal's built-in screenshot (Cmd+Shift+4 on Mac)
   - Or use tools like `asciinema` for animated recordings
   - Or `terminalizer` for GIF creation

2. **Recommended Screenshots**:
   - `toolkit-overview.png` - All three tools in action
   - `topo-hash-cli.png` - File integrity checking
   - `iot-sniffer-cli.png` - Real-time monitoring output
   - `captcha-cracker-cli.png` - Security test results

### Terminal Styling

For better screenshots, use:
- **Color Scheme**: Solarized Dark or One Dark
- **Font**: Fira Code or JetBrains Mono
- **Terminal**: iTerm2 (Mac), Windows Terminal, or Alacritty

## Design Philosophy

- **Small & Focused**: Each tool does one thing well
- **Auditable**: Easy to read and understand code
- **Transparent**: Clear output and explanations
- **No Dependencies**: Minimal external requirements
- **CISO-Friendly**: Designed for security professionals

## License

MIT License
