"""
enrichment/ip_utils.py
=======================
Utility functions for IP address classification.

Used by enrichment_engine.py to decide what enrichment
to apply to each observable:
  - Internal IPs → corporate directory identity lookup
  - External IPs → IOC reputation lookup only

RFC 1918 private ranges:
  10.0.0.0/8       — Class A private
  172.16.0.0/12    — Class B private
  192.168.0.0/16   — Class C private

Additional special ranges:
  127.0.0.0/8      — Loopback
  169.254.0.0/16   — Link-local (APIPA)
  100.64.0.0/10    — Shared address space (RFC 6598)

Usage:
    from enrichment.ip_utils import is_internal, is_external, classify_ip

    is_internal("10.0.0.45")        # True
    is_internal("185.220.101.45")   # False
    classify_ip("10.0.0.45")        # "internal"
    classify_ip("185.220.101.45")   # "external"
"""

import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Private / special IP ranges ───────────────────────────────────────────────

_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Class A
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Class B
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Class C
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


# ── Public functions ──────────────────────────────────────────────────────────

def is_internal(ip: str) -> bool:
    """
    Return True if the IP address is in a private/internal range.

    Parameters
    ----------
    ip : str — IPv4 or IPv6 address string

    Returns
    -------
    bool — True if internal, False if external or unparseable
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return any(addr in network for network in _INTERNAL_NETWORKS)
    except ValueError:
        logger.debug(f"ip_utils: could not parse IP '{ip}' — treating as external")
        return False


def is_external(ip: str) -> bool:
    """Return True if the IP is a public/external address."""
    return not is_internal(ip)


def classify_ip(ip: str) -> str:
    """
    Return 'internal' or 'external' for a given IP address.
    Returns 'invalid' if the string is not a valid IP.
    """
    try:
        ipaddress.ip_address(ip.strip())
        return "internal" if is_internal(ip) else "external"
    except ValueError:
        return "invalid"


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def extract_ips_from_observables(observables: list[dict]) -> dict:
    """
    Partition observables into internal and external IP lists.
    Used by enrichment_engine to decide enrichment strategy per observable.

    Parameters
    ----------
    observables : list of case management platform observable dicts
        Each dict has keys: _id, dataType, data, tags

    Returns
    -------
    dict with keys:
        internal_ips : list of observable dicts where IP is internal
        external_ips : list of observable dicts where IP is external
        emails       : list of observable dicts where dataType is mail
        hashes       : list of observable dicts where dataType is hash
        urls         : list of observable dicts where dataType is url
        domains      : list of observable dicts where dataType is domain
        other        : list of remaining observables
    """
    result = {
        "internal_ips": [],
        "external_ips": [],
        "emails":        [],
        "hashes":        [],
        "urls":          [],
        "domains":       [],
        "other":         [],
    }

    for obs in observables:
        data_type = obs.get("dataType", "")
        value     = obs.get("data", "")

        if data_type == "ip":
            if is_internal(value):
                result["internal_ips"].append(obs)
            else:
                result["external_ips"].append(obs)
        elif data_type in ("mail", "email"):
            result["emails"].append(obs)
        elif data_type == "hash":
            result["hashes"].append(obs)
        elif data_type == "url":
            result["urls"].append(obs)
        elif data_type in ("domain", "fqdn"):
            result["domains"].append(obs)
        else:
            result["other"].append(obs)

    return result


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        # Internal
        ("10.0.0.45",       True,  "internal — RFC1918 Class A"),
        ("10.0.0.15",       True,  "internal — RFC1918 Class A"),
        ("172.16.5.10",     True,  "internal — RFC1918 Class B"),
        ("192.168.1.1",     True,  "internal — RFC1918 Class C"),
        ("127.0.0.1",       True,  "internal — loopback"),
        ("41.226.10.5",     False, "external — Tunis office (public IP)"),
        # External / malicious
        ("185.220.101.45",  False, "external — Feodo Tracker C2"),
        ("91.92.128.33",    False, "external — Emotet C2"),
        ("203.0.113.55",    False, "external — brute force source"),
        ("8.8.8.8",         False, "external — Google DNS"),
        # Edge cases
        ("999.999.999.999", False, "invalid — should not crash"),
        ("not-an-ip",       False, "invalid — should not crash"),
    ]

    print("IP Classification Tests\n" + "=" * 50)
    all_passed = True
    for ip, expected, label in test_cases:
        result  = is_internal(ip)
        status  = "✅" if result == expected else "❌"
        if result != expected:
            all_passed = False
        print(f"  {status}  {ip:20} → {classify_ip(ip):10} — {label}")

    print()
    print("All tests passed ✅" if all_passed else "Some tests FAILED ❌")

    # Test observable partitioning
    print("\nObservable Partitioning Test\n" + "=" * 50)
    mock_observables = [
        {"dataType": "ip",   "data": "185.220.101.45", "tags": ["source", "external"]},
        {"dataType": "ip",   "data": "10.0.0.15",      "tags": ["destination", "internal"]},
        {"dataType": "mail", "data": "adele@example.com",  "tags": ["user"]},
        {"dataType": "hash", "data": "d41d8cd98f00b204e9800998ecf8427e", "tags": []},
        {"dataType": "url",  "data": "http://malicious.ru/payload", "tags": []},
    ]
    partitioned = extract_ips_from_observables(mock_observables)
    for key, items in partitioned.items():
        if items:
            print(f"  {key}: {[i['data'] for i in items]}")