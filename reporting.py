"""Report writers for CSV and malicious IP blocklists."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path


CSV_HEADERS = [
    "Timestamp",
    "IP",
    "Score",
    "Verdict",
    "Country",
    "ISP",
    "TotalReports",
    "UsageType",
]


def create_run_dir(output_dir: str | Path) -> Path:
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = Path(output_dir) / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def open_report(run_dir: Path):
    path = run_dir / "report.csv"
    handle = path.open("w", encoding="utf-8", newline="")
    writer = csv.DictWriter(handle, fieldnames=CSV_HEADERS)
    writer.writeheader()
    return path, handle, writer


def open_malicious_list(run_dir: Path):
    path = run_dir / "malicious_ips.txt"
    handle = path.open("w", encoding="utf-8")
    handle.write("# Malicious IPs to Block\n")
    handle.write(f"# Generated: {datetime.now().isoformat(timespec='seconds')}\n")
    handle.write("#" + "=" * 40 + "\n\n")
    return path, handle


def write_row(
    writer: csv.DictWriter,
    *,
    timestamp: str,
    ip: str,
    score: str | int,
    verdict: str,
    country: str = "",
    isp: str = "",
    total_reports: str | int = "",
    usage_type: str = "",
) -> None:
    writer.writerow(
        {
            "Timestamp": timestamp,
            "IP": ip,
            "Score": score,
            "Verdict": verdict,
            "Country": country,
            "ISP": isp,
            "TotalReports": total_reports,
            "UsageType": usage_type,
        }
    )
