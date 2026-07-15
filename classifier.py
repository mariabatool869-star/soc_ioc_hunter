"""IP classification helpers for SOC IOC Hunter."""

from __future__ import annotations

import ipaddress


def is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def classify(
    score: int,
    malicious_threshold: int,
    suspicious_threshold: int,
) -> str:
    if score >= malicious_threshold:
        return "MALICIOUS"
    if score >= suspicious_threshold:
        return "SUSPICIOUS"
    return "SAFE"
