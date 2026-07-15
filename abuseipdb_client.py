"""AbuseIPDB HTTP client with retries."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class LookupResult:
    ok: bool
    score: int | None = None
    country: str = ""
    isp: str = ""
    total_reports: int | None = None
    usage_type: str = ""
    error: str | None = None
    fatal_auth: bool = False


class AbuseIPDBClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        retry_attempts: int = 3,
        retry_delay: float = 10,
        timeout: float = 10,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {"Key": api_key, "Accept": "application/json"}
        )

    def check(self, ip: str, max_age_days: int = 90) -> LookupResult:
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days}

        for attempt in range(1, self.retry_attempts + 1):
            try:
                response = self._session.get(
                    self.base_url, params=params, timeout=self.timeout
                )
            except requests.RequestException as exc:
                if attempt < self.retry_attempts:
                    time.sleep(self.retry_delay)
                    continue
                return LookupResult(ok=False, error=str(exc))

            if response.status_code == 200:
                data: dict[str, Any] = response.json().get("data", {})
                return LookupResult(
                    ok=True,
                    score=int(data.get("abuseConfidenceScore", 0)),
                    country=str(data.get("countryCode") or ""),
                    isp=str(data.get("isp") or ""),
                    total_reports=int(data.get("totalReports") or 0),
                    usage_type=str(data.get("usageType") or ""),
                )

            if response.status_code == 401:
                return LookupResult(
                    ok=False,
                    error=(
                        "Unauthorized (401): api_key in config.yaml "
                        "is invalid or expired"
                    ),
                    fatal_auth=True,
                )

            if (
                response.status_code in (429, 500, 502, 503, 504)
                and attempt < self.retry_attempts
            ):
                time.sleep(self.retry_delay)
                continue

            return LookupResult(
                ok=False,
                error=f"API Error: Status code {response.status_code}",
            )

        return LookupResult(ok=False, error="Max retries exceeded")
