"""Quick connectivity check for the AbuseIPDB API key."""

from __future__ import annotations

import argparse
import sys

import requests

from config_loader import ConfigLoader


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate AbuseIPDB API access.")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args(argv)

    print("=" * 40)
    print("API CONNECTION TEST")
    print("=" * 40)
    print()

    try:
        config = ConfigLoader(args.config)
    except FileNotFoundError as exc:
        print(exc)
        return 1

    try:
        api_key = config.require("api_key")
        url = config.require("base_url")
    except ValueError as exc:
        print(exc)
        return 1

    key = str(api_key)
    print(f"API Key (first 5 chars): {key[:5]}...")
    print(f"API Key length: {len(key)} characters")
    print()
    print("Sending request to AbuseIPDB...")
    print()

    try:
        response = requests.get(
            str(url),
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
            timeout=10,
        )
    except requests.RequestException as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"STATUS CODE: {response.status_code}")
    print()

    if response.status_code == 200:
        score = response.json()["data"]["abuseConfidenceScore"]
        print("SUCCESS! API is working.")
        print("IP: 8.8.8.8")
        print(f"Abuse Score: {score}")
        print()
        print("Your API key is VALID. The tool will work.")
        return 0

    if response.status_code == 401:
        print("ERROR: Invalid API key")
        print("Get a new key from https://www.abuseipdb.com/account/api")
        return 1

    print(f"ERROR: Status code {response.status_code}")
    print(response.text[:300])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
