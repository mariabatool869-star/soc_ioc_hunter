"""SOC IOC Hunter — CLI entrypoint for AbuseIPDB IP enrichment."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from abuseipdb_client import AbuseIPDBClient
from classifier import classify, is_private_ip
from config_loader import ConfigLoader
from reporting import (
    create_run_dir,
    open_malicious_list,
    open_report,
    write_row,
)


def load_ips(path: Path) -> list[str]:
    ips: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
    return ips


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enrich IP IOCs with AbuseIPDB and export SOC reports.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML config (default: config.yaml)",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="IP list file (default: input_file from config or ips.txt)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Report directory (default: output_dir from config or ./reports)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = ConfigLoader(args.config)
    except FileNotFoundError as exc:
        print(exc)
        return 1

    try:
        api_key = config.require("api_key")
        base_url = config.require("base_url")
    except ValueError as exc:
        print(exc)
        return 1

    if str(api_key).startswith("YOUR_"):
        print("[FATAL] Replace the placeholder api_key in config.yaml")
        return 1

    retry_attempts = int(config.get("retry_attempts", 3))
    retry_delay = float(config.get("retry_delay", 10))
    request_delay = float(config.get("request_delay", 0.5))
    skip_private = bool(config.get("skip_private_ips", True))
    malicious_threshold = int(config.get("thresholds.malicious", 51))
    suspicious_threshold = int(config.get("thresholds.suspicious", 11))

    input_path = Path(args.input or config.get("input_file", "ips.txt"))
    output_root = Path(args.output_dir or config.get("output_dir", "./reports"))

    print("=" * 50)
    print("SOC IOC HUNTER - Threat Intelligence Tool")
    print("=" * 50)
    print()

    try:
        ip_list = load_ips(input_path)
    except FileNotFoundError:
        print(f"ERROR: input file not found: {input_path}")
        print("Create it with one IP per line (lines starting with # are ignored).")
        return 1

    if not ip_list:
        print(f"ERROR: no IPs found in {input_path}")
        return 1

    print(f"Loaded {len(ip_list)} IP addresses from {input_path}")
    print(f"Config: {args.config}")
    print()

    client = AbuseIPDBClient(
        api_key=str(api_key),
        base_url=str(base_url),
        retry_attempts=retry_attempts,
        retry_delay=retry_delay,
    )

    run_dir = create_run_dir(output_root)
    report_path, report_handle, writer = open_report(run_dir)
    malicious_path, malicious_handle = open_malicious_list(run_dir)

    malicious_count = 0
    suspicious_count = 0
    safe_count = 0
    failed_count = 0
    skipped_count = 0

    try:
        for index, ip in enumerate(ip_list, 1):
            print(f"Checking IP {index} of {len(ip_list)}: {ip}")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if skip_private and is_private_ip(ip):
                skipped_count += 1
                print("  → SKIPPED (private / RFC1918 address)")
                write_row(
                    writer,
                    timestamp=timestamp,
                    ip=ip,
                    score="",
                    verdict="SKIPPED_PRIVATE",
                )
                print()
                continue

            result = client.check(ip)

            if not result.ok:
                failed_count += 1
                print(f"  → {result.error}")
                write_row(
                    writer,
                    timestamp=timestamp,
                    ip=ip,
                    score="API_ERROR",
                    verdict="FAILED",
                )
                if result.fatal_auth:
                    print()
                    print("Stopping: fix api_key in config.yaml, then re-run.")
                    break
            else:
                assert result.score is not None
                verdict = classify(
                    result.score, malicious_threshold, suspicious_threshold
                )
                if verdict == "MALICIOUS":
                    malicious_count += 1
                    malicious_handle.write(
                        f"{ip} | Score: {result.score} | "
                        f"Country: {result.country} | ISP: {result.isp}\n"
                    )
                    print(f"  → Score: {result.score} | MALICIOUS")
                elif verdict == "SUSPICIOUS":
                    suspicious_count += 1
                    print(f"  → Score: {result.score} | SUSPICIOUS")
                else:
                    safe_count += 1
                    print(f"  → Score: {result.score} | SAFE")

                write_row(
                    writer,
                    timestamp=timestamp,
                    ip=ip,
                    score=result.score,
                    verdict=verdict,
                    country=result.country,
                    isp=result.isp,
                    total_reports=result.total_reports or 0,
                    usage_type=result.usage_type,
                )

            print()
            if request_delay > 0 and index < len(ip_list):
                time.sleep(request_delay)
    finally:
        report_handle.close()
        malicious_handle.close()

    api_success = malicious_count + suspicious_count + safe_count
    print("=" * 50)
    print("SUMMARY REPORT")
    print("=" * 50)
    print(f"Total IPs loaded:   {len(ip_list)}")
    print(f"API successes:      {api_success}")
    print(f"MALICIOUS:          {malicious_count}")
    print(f"SUSPICIOUS:         {suspicious_count}")
    print(f"SAFE:               {safe_count}")
    print(f"SKIPPED (private):  {skipped_count}")
    print(f"FAILED:             {failed_count}")
    print()
    print("Reports saved:")
    print(f"  {report_path}")
    print(f"  {malicious_path} ({malicious_count} IPs)")
    print("=" * 50)
    return 0


if __name__ == "__main__":
    sys.exit(main())
