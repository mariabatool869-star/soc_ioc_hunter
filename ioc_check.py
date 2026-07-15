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
from logger import setup_logging
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

    log_dir = config.get("log_dir", "./logs")
    logger, log_file = setup_logging(log_dir)
    logger.info("SOC IOC HUNTER - Threat Intelligence Tool")
    logger.info("Log file: %s", log_file)

    if str(api_key).startswith("YOUR_"):
        logger.error("Replace the placeholder api_key in config.yaml")
        return 1

    retry_attempts = int(config.get("retry_attempts", 3))
    retry_delay = float(config.get("retry_delay", 10))
    request_delay = float(config.get("request_delay", 0.5))
    skip_private = bool(config.get("skip_private_ips", True))
    malicious_threshold = int(config.get("thresholds.malicious", 51))
    suspicious_threshold = int(config.get("thresholds.suspicious", 11))

    input_path = Path(args.input or config.get("input_file", "ips.txt"))
    output_root = Path(args.output_dir or config.get("output_dir", "./reports"))

    try:
        ip_list = load_ips(input_path)
    except FileNotFoundError:
        logger.error("Input file not found: %s", input_path)
        logger.error("Create it with one IP per line (lines starting with # are ignored).")
        return 1

    if not ip_list:
        logger.error("No IPs found in %s", input_path)
        return 1

    logger.info("Loaded %d IP addresses from %s", len(ip_list), input_path)
    logger.info("Config: %s", args.config)

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
            logger.info("Checking IP %d of %d: %s", index, len(ip_list), ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if skip_private and is_private_ip(ip):
                skipped_count += 1
                logger.info("  SKIPPED (private / RFC1918 address)")
                write_row(
                    writer,
                    timestamp=timestamp,
                    ip=ip,
                    score="",
                    verdict="SKIPPED_PRIVATE",
                )
                continue

            result = client.check(ip)

            if not result.ok:
                failed_count += 1
                logger.warning("  %s", result.error)
                write_row(
                    writer,
                    timestamp=timestamp,
                    ip=ip,
                    score="API_ERROR",
                    verdict="FAILED",
                )
                if result.fatal_auth:
                    logger.error("Stopping: fix api_key in config.yaml, then re-run.")
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
                    logger.info("  Score: %d | MALICIOUS", result.score)
                elif verdict == "SUSPICIOUS":
                    suspicious_count += 1
                    logger.info("  Score: %d | SUSPICIOUS", result.score)
                else:
                    safe_count += 1
                    logger.info("  Score: %d | SAFE", result.score)

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

            if request_delay > 0 and index < len(ip_list):
                time.sleep(request_delay)
    finally:
        report_handle.close()
        malicious_handle.close()

    api_success = malicious_count + suspicious_count + safe_count
    logger.info("SUMMARY REPORT")
    logger.info("Total IPs loaded:   %d", len(ip_list))
    logger.info("API successes:      %d", api_success)
    logger.info("MALICIOUS:          %d", malicious_count)
    logger.info("SUSPICIOUS:         %d", suspicious_count)
    logger.info("SAFE:               %d", safe_count)
    logger.info("SKIPPED (private):  %d", skipped_count)
    logger.info("FAILED:             %d", failed_count)
    logger.info("Report: %s", report_path)
    logger.info("Blocklist: %s (%d IPs)", malicious_path, malicious_count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
