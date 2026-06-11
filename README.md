# soc_ioc_hunter
 Automated IP Threat Intelligence Tool

 # SOC IOC Hunter - Threat Intelligence Tool

## Overview
**SOC IOC Hunter** is an automated threat intelligence tool that checks IP addresses against the AbuseIPDB database to identify malicious, suspicious, and safe indicators of compromise (IOCs).

Built for SOC analysts to reduce manual IOC triage time from minutes to seconds.

---

## Why I Built This
As an aspiring SOC Analyst, I noticed that security teams spend valuable time manually checking IP addresses against threat intelligence feeds. This tool automates that process, allowing analysts to focus on investigation and response.

---

## Key Features
| Feature | Description |
|---------|-------------|
| 🔍 **Bulk IP Checking** | Reads multiple IPs from a file and checks them automatically |
| 📊 **Risk Scoring** | Returns abuse confidence scores (0-100) from AbuseIPDB |
| 🎯 **Automated Verdicts** | Classifies IPs as MALICIOUS, SUSPICIOUS, or SAFE |
| 📄 **CSV Reporting** | Generates professional reports ready for Excel |
| 🚫 **Malicious IP Export** | Creates a separate file with only malicious IPs for blocking |
| ⏱️ **Timestamp Tracking** | Records when each check was performed |
| 🛡️ **Error Handling** | Continues processing even if individual IP checks fail |

---

## Technical Skills Demonstrated
- **Python Scripting** - Core automation logic
- **REST API Integration** - AbuseIPDB API calls with authentication
- **JSON Parsing** - Extracting threat scores from API responses
- **File I/O Operations** - Reading IP lists, writing CSV reports
- **Error Handling** - Try/except blocks for production reliability
- **Secure Coding** - API keys stored separately, not exposed in code

---

## Tools & Technologies
| Category | Tools |
|----------|-------|
| Language | Python 3.x |
| Libraries | Requests, Datetime |
| API | AbuseIPDB (free tier) |
| Output | CSV, TXT files |

---

## How to Run This Tool

### Prerequisites
- Python 3.x installed
- Free API key from [AbuseIPDB](https://www.abuseipdb.com)

