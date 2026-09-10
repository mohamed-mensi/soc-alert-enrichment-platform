"""
enrichment/identity_lookup.py
==============================
Resolves internal IPs and user emails to corporate directory identity context
via the Microsoft Graph API.

Two modes:
  mock_mode=True  — returns hardcoded realistic mock data
                    (use when no directory tenant is available)
  mock_mode=False — calls real Microsoft Graph API
                    (requires DIRECTORY_TENANT_ID, DIRECTORY_CLIENT_ID,
                     DIRECTORY_CLIENT_SECRET in .env)

Switching to production:
    1. Register an app in identity provider admin center
    2. Grant these application permissions (read-only):
         User.Read.All
         GroupMember.Read.All
         AuditLog.Read.All          (requires P1 license)
         UserAuthenticationMethod.Read.All
         IdentityRiskyUser.Read.All
         Device.Read.All
    3. Add credentials to .env
    4. Set mock_mode=False in config.yaml

Usage:
    from enrichment.identity_lookup import IdentityLookup

    lookup = IdentityLookup(mock_mode=True)

    # Lookup by internal IP
    result = lookup.lookup_ip("10.0.0.15")

    # Lookup by email
    result = lookup.lookup_email("adele.vance@example-corp.com")

    # Returns:
    # {
    #     "found": True,
    #     "display_name": "Adele Vance",
    #     "department": "Finance",
    #     "job_title": "Senior Financial Analyst",
    #     "manager": "Alex Wilber",
    #     "employee_type": "Member",
    #     "account_enabled": True,
    #     "mfa_enabled": False,
    #     "risk_level": "high",
    #     "groups": ["Finance-Team", "ERP-Access"],
    #     "criticality": "HIGH",
    #     "mock": True   # present only in mock mode
    # }
"""

import logging
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── Mock data ─────────────────────────────────────────────────────────────────
# Simulates a realistic Example Corp environment.
# Maps internal IPs and emails to AD user profiles.
# Replace with real Graph API calls when tenant is available.

_MOCK_BY_IP = {
    "10.0.0.15": {
        "display_name":   "Adele Vance",
        "department":     "Finance",
        "job_title":      "Senior Financial Analyst",
        "manager":        "Alex Wilber",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    False,
        "risk_level":     "high",
        "groups":         ["Finance-Team", "ERP-Access"],
        "criticality":    "HIGH",
        "email":          "adele.vance@example-corp.com",
    },
    "10.0.0.20": {
        "display_name":   "Alex Wilber",
        "department":     "IT",
        "job_title":      "IT Manager",
        "manager":        "Walid KDOUS",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    True,
        "risk_level":     "none",
        "groups":         ["IT-Admins", "Domain-Admins"],
        "criticality":    "CRITICAL",
        "email":          "alex.wilber@example-corp.com",
    },
    "10.0.0.45": {
        "display_name":   "SRV-FINANCE-01",
        "department":     "IT",
        "job_title":      "Service Account",
        "manager":        "Alex Wilber",
        "employee_type":  "ServiceAccount",
        "account_enabled": True,
        "mfa_enabled":    False,
        "risk_level":     "none",
        "groups":         ["Servers", "Finance-Systems"],
        "criticality":    "CRITICAL",
        "email":          None,
    },
    "10.0.0.12": {
        "display_name":   "SRV-DC-01",
        "department":     "IT",
        "job_title":      "Service Account",
        "manager":        "Alex Wilber",
        "employee_type":  "ServiceAccount",
        "account_enabled": True,
        "mfa_enabled":    False,
        "risk_level":     "none",
        "groups":         ["Domain-Controllers", "IT-Admins"],
        "criticality":    "CRITICAL",
        "email":          None,
    },
    "10.0.0.10": {
        "display_name":   "Auth-Server-01",
        "department":     "IT",
        "job_title":      "Service Account",
        "manager":        "Alex Wilber",
        "employee_type":  "ServiceAccount",
        "account_enabled": True,
        "mfa_enabled":    False,
        "risk_level":     "none",
        "groups":         ["Servers"],
        "criticality":    "HIGH",
        "email":          None,
    },
}

_MOCK_BY_EMAIL = {
    "adele.vance@example-corp.com": {
        "display_name":   "Adele Vance",
        "department":     "Finance",
        "job_title":      "Senior Financial Analyst",
        "manager":        "Alex Wilber",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    False,
        "risk_level":     "high",
        "groups":         ["Finance-Team", "ERP-Access"],
        "criticality":    "HIGH",
        "email":          "adele.vance@example-corp.com",
    },
    "lee.grant@example-corp.com": {
        "display_name":   "Lee Grant",
        "department":     "Marketing",
        "job_title":      "Marketing Coordinator",
        "manager":        "Miriam Graham",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    True,
        "risk_level":     "none",
        "groups":         ["Marketing-Team"],
        "criticality":    "LOW",
        "email":          "lee.grant@example-corp.com",
    },
    "alex.wilber@example-corp.com": {
        "display_name":   "Alex Wilber",
        "department":     "IT",
        "job_title":      "IT Manager",
        "manager":        "Walid KDOUS",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    True,
        "risk_level":     "none",
        "groups":         ["IT-Admins", "Domain-Admins"],
        "criticality":    "CRITICAL",
        "email":          "alex.wilber@example-corp.com",
    },
    "miriam.graham@example-corp.com": {
        "display_name":   "Miriam Graham",
        "department":     "Marketing",
        "job_title":      "Marketing Director",
        "manager":        "Walid KDOUS",
        "employee_type":  "Member",
        "account_enabled": True,
        "mfa_enabled":    True,
        "risk_level":     "none",
        "groups":         ["Marketing-Team", "Directors"],
        "criticality":    "MEDIUM",
        "email":          "miriam.graham@example-corp.com",
    },
}

# Criticality rules — derived from department and group membership
# Used in real mode when criticality isn't explicitly set
_DEPT_CRITICALITY = {
    "IT":       "HIGH",
    "Finance":  "HIGH",
    "Legal":    "HIGH",
    "HR":       "MEDIUM",
    "Marketing":"LOW",
    "Sales":    "LOW",
}

_GROUP_CRITICALITY = {
    "Domain-Controllers": "CRITICAL",
    "Domain-Admins":      "CRITICAL",
    "IT-Admins":          "CRITICAL",
    "Global-Admins":      "CRITICAL",
    "Finance-Team":       "HIGH",
    "ERP-Access":         "HIGH",
    "Directors":          "HIGH",
    "Servers":            "HIGH",
}


# ── Main class ────────────────────────────────────────────────────────────────

class IdentityLookup:
    """
    Resolves internal IPs and emails to corporate directory identity context.

    Parameters
    ----------
    mock_mode : bool
        If True, returns hardcoded mock data without calling Graph API.
        Set to False when directory tenant credentials are available.
    tenant_id : str, optional
        corporate directory tenant ID (falls back to DIRECTORY_TENANT_ID env var)
    client_id : str, optional
        App registration client ID (falls back to DIRECTORY_CLIENT_ID env var)
    client_secret : str, optional
        App registration secret (falls back to DIRECTORY_CLIENT_SECRET env var)
    """

    def __init__(
        self,
        mock_mode: bool = True,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        self.mock_mode = mock_mode

        if not mock_mode:
            self.tenant_id     = tenant_id     or os.getenv("DIRECTORY_TENANT_ID")
            self.client_id     = client_id     or os.getenv("DIRECTORY_CLIENT_ID")
            self.client_secret = client_secret or os.getenv("DIRECTORY_CLIENT_SECRET")

            if not all([self.tenant_id, self.client_id, self.client_secret]):
                raise ValueError(
                    "Real mode requires DIRECTORY_TENANT_ID, DIRECTORY_CLIENT_ID, "
                    "and DIRECTORY_CLIENT_SECRET in .env"
                )
            self._token = None
            self._token_expiry = 0

        mode = "MOCK" if mock_mode else "REAL (Microsoft Graph API)"
        logger.info(f"IdentityLookup initialized — mode: {mode}")

    # ── Public API ────────────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict:
        """
        Resolve an internal IP address to its corporate directory owner.

        Parameters
        ----------
        ip : str — internal IP address (e.g. "10.0.0.15")

        Returns
        -------
        dict with identity fields, or not-found result
        """
        if self.mock_mode:
            return self._mock_lookup_ip(ip)
        return self._real_lookup_ip(ip)

    def lookup_email(self, email: str) -> dict:
        """
        Resolve a user email to their corporate directory profile.

        Parameters
        ----------
        email : str — user email address

        Returns
        -------
        dict with identity fields, or not-found result
        """
        if self.mock_mode:
            return self._mock_lookup_email(email)
        return self._real_lookup_email(email)

    def lookup_observable(self, obs_type: str, value: str) -> dict:
        """
        Convenience method — routes to lookup_ip or lookup_email
        based on observable type.

        Parameters
        ----------
        obs_type : str — "ip", "mail", "email"
        value    : str — the observable value

        Returns
        -------
        dict with identity fields, or not-found result
        """
        if obs_type == "ip":
            return self.lookup_ip(value)
        elif obs_type in ("mail", "email"):
            return self.lookup_email(value)
        else:
            return self._not_found(f"Observable type '{obs_type}' not supported for AD lookup")

    # ── Mock mode ─────────────────────────────────────────────────────────────

    def _mock_lookup_ip(self, ip: str) -> dict:
        """Return mock identity data for a known internal IP."""
        data = _MOCK_BY_IP.get(ip.strip())
        if not data:
            logger.debug(f"[MOCK] IP {ip} not in mock data — returning not found")
            return self._not_found(f"IP {ip} not found in mock AD data")

        result = dict(data)
        result["found"] = True
        result["mock"]  = True
        logger.info(
            f"[MOCK] IP {ip} → {result['display_name']} "
            f"({result['department']}) — criticality: {result['criticality']}"
        )
        return result

    def _mock_lookup_email(self, email: str) -> dict:
        """Return mock identity data for a known email address."""
        data = _MOCK_BY_EMAIL.get(email.strip().lower()) or \
               _MOCK_BY_EMAIL.get(email.strip())
        if not data:
            logger.debug(f"[MOCK] Email {email} not in mock data — returning not found")
            return self._not_found(f"Email {email} not found in mock AD data")

        result = dict(data)
        result["found"] = True
        result["mock"]  = True
        logger.info(
            f"[MOCK] Email {email} → {result['display_name']} "
            f"({result['department']}) — criticality: {result['criticality']}"
        )
        return result

    # ── Real mode (Microsoft Graph API) ──────────────────────────────────────

    def _real_lookup_ip(self, ip: str) -> dict:
        """
        Real Graph API lookup by IP.

        NOTE: corporate directory doesn't directly map IPs to users.
        Strategy:
          1. Query sign-in logs for recent logins from this IP
          2. Get the user who most recently authenticated from it
          3. Look up that user's full profile

        Requires: AuditLog.Read.All permission + P1 license
        """
        try:
            token = self._get_token()
            import requests

            # Query sign-in logs for this IP
            url = (
                "https://graph.microsoft.com/v1.0/auditLogs/signIns"
                f"?$filter=ipAddress eq '{ip}'"
                "&$orderby=createdDateTime desc"
                "&$top=1"
                "&$select=userId,userDisplayName,userPrincipalName,ipAddress,createdDateTime"
            )
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            sign_ins = data.get("value", [])
            if not sign_ins:
                return self._not_found(f"No sign-in logs found for IP {ip}")

            user_id = sign_ins[0].get("userId")
            if not user_id:
                return self._not_found(f"No user ID in sign-in logs for IP {ip}")

            return self._get_user_profile(user_id, token)

        except Exception as exc:
            logger.error(f"Graph API lookup failed for IP {ip}: {exc}")
            return self._not_found(str(exc))

    def _real_lookup_email(self, email: str) -> dict:
        """Real Graph API lookup by email / user principal name."""
        try:
            token = self._get_token()
            import requests

            url = (
                f"https://graph.microsoft.com/v1.0/users/{email}"
                "?$select=id,displayName,jobTitle,department,mail,"
                "accountEnabled,userType,createdDateTime"
            )
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            response.raise_for_status()
            user = response.json()
            user_id = user.get("id")

            return self._get_user_profile(user_id, token, base_user=user)

        except Exception as exc:
            logger.error(f"Graph API lookup failed for email {email}: {exc}")
            return self._not_found(str(exc))

    def _get_user_profile(
        self, user_id: str, token: str, base_user: Optional[dict] = None
    ) -> dict:
        """
        Fetch full user profile from Graph API.
        Combines: basic profile + manager + groups + MFA + risk level
        """
        import requests

        headers = {"Authorization": f"Bearer {token}"}
        profile = base_user or {}

        # Basic profile (if not already fetched)
        if not base_user:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}"
                "?$select=displayName,jobTitle,department,mail,"
                "accountEnabled,userType",
                headers=headers, timeout=10
            )
            if r.ok:
                profile = r.json()

        # Manager
        manager_name = None
        try:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/manager"
                "?$select=displayName",
                headers=headers, timeout=10
            )
            if r.ok:
                manager_name = r.json().get("displayName")
        except Exception:
            pass

        # Group memberships
        groups = []
        try:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
                "?$select=displayName",
                headers=headers, timeout=10
            )
            if r.ok:
                groups = [
                    g.get("displayName") for g in r.json().get("value", [])
                    if g.get("displayName")
                ]
        except Exception:
            pass

        # MFA methods
        mfa_enabled = False
        try:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id}"
                "/authentication/methods",
                headers=headers, timeout=10
            )
            if r.ok:
                methods = r.json().get("value", [])
                # Any method other than password = MFA registered
                mfa_enabled = any(
                    m.get("@odata.type", "") != "#microsoft.graph.passwordAuthenticationMethod"
                    for m in methods
                )
        except Exception:
            pass

        # Identity Protection risk level
        risk_level = "none"
        try:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/identityProtection"
                f"/riskyUsers/{user_id}",
                headers=headers, timeout=10
            )
            if r.ok:
                risk_level = r.json().get("riskLevel", "none")
        except Exception:
            pass

        # Derive criticality
        dept       = profile.get("department", "")
        criticality = self._derive_criticality(dept, groups)

        result = {
            "found":           True,
            "display_name":    profile.get("displayName"),
            "department":      dept,
            "job_title":       profile.get("jobTitle"),
            "manager":         manager_name,
            "employee_type":   profile.get("userType", "Member"),
            "account_enabled": profile.get("accountEnabled", True),
            "mfa_enabled":     mfa_enabled,
            "risk_level":      risk_level,
            "groups":          groups,
            "criticality":     criticality,
            "email":           profile.get("mail"),
            "mock":            False,
        }
        logger.info(
            f"Graph API: {result['display_name']} "
            f"({result['department']}) — criticality: {criticality}"
        )
        return result

    def _get_token(self) -> str:
        """
        Get a valid access token using client credentials flow.
        Caches the token until expiry.
        """
        import time
        import requests

        if self._token and time.time() < self._token_expiry - 60:
            return self._token

        url = (
            f"https://login.microsoftonline.com/{self.tenant_id}"
            "/oauth2/v2.0/token"
        )
        response = requests.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }, timeout=10)
        response.raise_for_status()
        data = response.json()

        self._token        = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600)
        logger.info("Graph API token acquired")
        return self._token

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_criticality(department: str, groups: list) -> str:
        """
        Derive asset criticality from department and group memberships.
        Group membership takes precedence over department.
        """
        # Check groups first — highest precedence
        for group in groups:
            if group in _GROUP_CRITICALITY:
                level = _GROUP_CRITICALITY[group]
                if level == "CRITICAL":
                    return "CRITICAL"

        for group in groups:
            if group in _GROUP_CRITICALITY:
                return _GROUP_CRITICALITY[group]

        # Fall back to department
        return _DEPT_CRITICALITY.get(department, "LOW")

    @staticmethod
    def _not_found(reason: str = "") -> dict:
        """Return a standard not-found result."""
        return {
            "found":           False,
            "display_name":    None,
            "department":      None,
            "job_title":       None,
            "manager":         None,
            "employee_type":   None,
            "account_enabled": None,
            "mfa_enabled":     None,
            "risk_level":      "none",
            "groups":          [],
            "criticality":     "LOW",
            "email":           None,
            "mock":            False,
            "reason":          reason,
        }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    lookup = IdentityLookup(mock_mode=True)

    test_cases = [
        # Internal IPs
        ("ip",   "10.0.0.15",                  "Finance user workstation"),
        ("ip",   "10.0.0.20",                  "IT Manager workstation"),
        ("ip",   "10.0.0.45",                  "Finance server"),
        ("ip",   "10.0.0.12",                  "Domain controller"),
        ("ip",   "10.0.0.99",                  "Unknown internal IP"),
        # Emails
        ("mail", "adele.vance@example-corp.com",    "Finance analyst"),
        ("mail", "lee.grant@example-corp.com",      "Marketing user"),
        ("mail", "alex.wilber@example-corp.com",    "IT admin"),
        ("mail", "unknown@example-corp.com",        "Unknown user"),
        # External IP — should not be passed here but handled gracefully
        ("ip",   "185.220.101.45",             "External IP — should return not found"),
    ]

    print("corporate directory Lookup Tests (Mock Mode)")
    print("=" * 60)

    for obs_type, value, label in test_cases:
        result = lookup.lookup_observable(obs_type, value)
        print(f"\n  [{obs_type}] {value} — {label}")
        if result["found"]:
            print(f"  ✅ Found   : {result['display_name']}")
            print(f"  Department : {result['department']}")
            print(f"  Job title  : {result['job_title']}")
            print(f"  Manager    : {result['manager']}")
            print(f"  Criticality: {result['criticality']}")
            print(f"  MFA        : {'Yes' if result['mfa_enabled'] else 'No ⚠️'}")
            print(f"  Risk level : {result['risk_level'].upper()}")
            print(f"  Groups     : {result['groups']}")
        else:
            print(f"  ❌ Not found — {result.get('reason', '')}")