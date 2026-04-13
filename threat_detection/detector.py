"""
detector.py - Threat Detection Engine
=======================================
Analyses parsed log entries and applies detection rules to identify
suspicious activity patterns relevant to SOC investigations:

  - Brute-force attacks       : >= threshold failed attempts from one IP
  - Credential spraying       : many different usernames tried from one IP
  - Suspicious post-fail login: successful login after multiple failures
  - Low-volume probing        : failed attempts below brute-force threshold
                                but still worth noting

Author: SOC Analyst Toolkit
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .parser import LogEntry


# ─────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────

@dataclass
class IPProfile:
    """
    Aggregated profile of all activity from a single IP address.
    Built incrementally as log entries are processed.
    """
    ip_address: str
    failed_count: int = 0
    success_count: int = 0
    invalid_user_count: int = 0
    usernames_tried: set = field(default_factory=set)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    raw_entries: list = field(default_factory=list)

    @property
    def total_attempts(self) -> int:
        return self.failed_count + self.success_count + self.invalid_user_count

    @property
    def unique_usernames(self) -> int:
        return len(self.usernames_tried)


@dataclass
class ThreatAlert:
    """Represents a detected threat with severity and context."""
    alert_type: str          # "BRUTE_FORCE" | "CREDENTIAL_SPRAY" | "SUSPICIOUS_LOGIN" | "PROBE"
    severity: str            # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    ip_address: str
    description: str
    failed_count: int
    success_count: int
    usernames: set
    first_seen: Optional[str]
    last_seen: Optional[str]

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.alert_type} | "
            f"IP: {self.ip_address} | "
            f"Failures: {self.failed_count} | "
            f"Desc: {self.description}"
        )


# ─────────────────────────────────────────────
#  Detection Engine
# ─────────────────────────────────────────────

class ThreatDetector:
    """
    Processes a list of LogEntry objects and produces IPProfile aggregates
    and ThreatAlert objects based on configurable detection thresholds.

    Detection Rules
    ---------------
    1. BRUTE_FORCE      – IP has >= `threshold` failed attempts, single account
    2. CREDENTIAL_SPRAY – IP tried >= `spray_threshold` distinct usernames
    3. SUSPICIOUS_LOGIN – IP had failures then achieved a successful login
    4. PROBE            – IP has < threshold failures (low-noise recon)
    """

    def __init__(
        self,
        threshold: int = 5,
        spray_threshold: int = 4,
    ):
        """
        Parameters
        ----------
        threshold       : Minimum failed attempts to trigger BRUTE_FORCE alert.
        spray_threshold : Minimum unique usernames to trigger CREDENTIAL_SPRAY.
        """
        self.threshold       = threshold
        self.spray_threshold = spray_threshold

        # Per-IP activity profiles built during analysis
        self.ip_profiles: dict[str, IPProfile] = {}

        # Final list of raised alerts
        self.alerts: list[ThreatAlert] = []

        # IPs that achieved login — used for suspicious login detection
        self._successful_ips: set[str] = set()

    # ── Public Interface ──────────────────────

    def analyse(self, entries: list[LogEntry]) -> list[ThreatAlert]:
        """
        Main entry point. Feed all log entries, get back threat alerts.

        Steps:
          1. Aggregate entries into per-IP profiles.
          2. Evaluate each profile against detection rules.
          3. Return sorted list of ThreatAlert objects.
        """
        self._build_profiles(entries)
        self._evaluate_profiles()
        # Sort alerts: CRITICAL → HIGH → MEDIUM → LOW, then by failed count desc
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 9), -a.failed_count)
        )
        return self.alerts

    def get_summary(self) -> dict:
        """Return a summary dict for report generation and terminal display."""
        total_failed  = sum(p.failed_count for p in self.ip_profiles.values())
        total_success = sum(p.success_count for p in self.ip_profiles.values())
        suspicious_ips = {
            a.ip_address for a in self.alerts
            if a.severity in ("CRITICAL", "HIGH")
        }
        return {
            "total_ips_seen":         len(self.ip_profiles),
            "total_failed_attempts":  total_failed,
            "total_success_attempts": total_success,
            "total_alerts":           len(self.alerts),
            "suspicious_ips":         len(suspicious_ips),
            "suspicious_ip_list":     sorted(suspicious_ips),
            "threshold_used":         self.threshold,
        }

    # ── Step 1 – Profile Building ─────────────

    def _build_profiles(self, entries: list[LogEntry]) -> None:
        """
        Iterate over all log entries and accumulate per-IP statistics.
        Tracks: failed count, success count, usernames tried, timestamps.
        """
        for entry in entries:
            ip = entry.ip_address
            if not ip:
                continue  # Skip entries without a resolvable IP

            # Create profile on first encounter
            if ip not in self.ip_profiles:
                self.ip_profiles[ip] = IPProfile(ip_address=ip)

            profile = self.ip_profiles[ip]
            profile.raw_entries.append(entry)

            # Update timestamp range
            if entry.timestamp:
                if profile.first_seen is None:
                    profile.first_seen = entry.timestamp
                profile.last_seen = entry.timestamp

            # Track username attempts
            if entry.username:
                profile.usernames_tried.add(entry.username)

            # Increment the appropriate counter
            if entry.status == "failed":
                profile.failed_count += 1
            elif entry.status == "success":
                profile.success_count += 1
                self._successful_ips.add(ip)
            elif entry.status == "invalid_user":
                profile.invalid_user_count += 1
                profile.failed_count += 1  # Count invalid user as a failure

    # ── Step 2 – Rule Evaluation ──────────────

    def _evaluate_profiles(self) -> None:
        """
        Apply each detection rule to every IP profile.
        A single IP can trigger multiple alert types.
        """
        for ip, profile in self.ip_profiles.items():
            # Rule 1 – Credential spraying (checked first; takes priority)
            if profile.unique_usernames >= self.spray_threshold and profile.failed_count >= self.threshold:
                self._raise_alert(
                    alert_type="CREDENTIAL_SPRAY",
                    severity="CRITICAL",
                    profile=profile,
                    description=(
                        f"Tried {profile.unique_usernames} different usernames "
                        f"with {profile.failed_count} total failures — "
                        "indicative of automated credential spraying."
                    ),
                )

            # Rule 2 – Brute force (high volume, likely single account)
            elif profile.failed_count >= self.threshold:
                severity = "CRITICAL" if profile.failed_count >= self.threshold * 3 else "HIGH"
                self._raise_alert(
                    alert_type="BRUTE_FORCE",
                    severity=severity,
                    profile=profile,
                    description=(
                        f"{profile.failed_count} failed login attempts detected "
                        f"(threshold: {self.threshold}). "
                        f"Target accounts: {', '.join(sorted(profile.usernames_tried)[:5])}"
                        f"{'...' if profile.unique_usernames > 5 else ''}."
                    ),
                )

            # Rule 3 – Low-volume probe (below threshold but still suspicious)
            elif 1 < profile.failed_count < self.threshold:
                self._raise_alert(
                    alert_type="PROBE",
                    severity="LOW",
                    profile=profile,
                    description=(
                        f"{profile.failed_count} failed attempts — "
                        "possible reconnaissance or misconfigured service."
                    ),
                )

            # Rule 4 – Successful login after failures (possible compromise)
            if ip in self._successful_ips and profile.failed_count > 0:
                self._raise_alert(
                    alert_type="SUSPICIOUS_LOGIN",
                    severity="MEDIUM",
                    profile=profile,
                    description=(
                        f"Successful login recorded after {profile.failed_count} failures. "
                        "Possible successful brute-force or credential reuse."
                    ),
                )

    def _raise_alert(
        self,
        alert_type: str,
        severity: str,
        profile: IPProfile,
        description: str,
    ) -> None:
        """Create and store a ThreatAlert from a profile match."""
        self.alerts.append(ThreatAlert(
            alert_type=alert_type,
            severity=severity,
            ip_address=profile.ip_address,
            description=description,
            failed_count=profile.failed_count,
            success_count=profile.success_count,
            usernames=profile.usernames_tried.copy(),
            first_seen=profile.first_seen,
            last_seen=profile.last_seen,
        ))
