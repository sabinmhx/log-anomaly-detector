"""
report.py - Report Generation Module
=====================================
Handles all output for the threat detection system:

  - Formatted terminal output with ANSI colour coding
  - CSV report file with per-IP breakdown
  - Plain-text summary report

Colour scheme follows SOC traffic-light conventions:
  RED     – CRITICAL threats
  YELLOW  – HIGH threats
  CYAN    – MEDIUM threats / informational
  WHITE   – LOW / normal
  GREEN   – Successful / safe activity

Author: SOC Analyst Toolkit
"""

import csv
import os
from datetime import datetime
from typing import Optional

from .detector import ThreatAlert, IPProfile


# ─────────────────────────────────────────────
#  ANSI Colour Helpers
# ─────────────────────────────────────────────

class Color:
    """ANSI escape codes for terminal colour output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;214m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    DIM     = "\033[2m"

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI codes (for plain-text file output)."""
        import re
        return re.sub(r"\033\[[0-9;]*m", "", text)


SEVERITY_COLORS = {
    "CRITICAL": Color.RED,
    "HIGH":     Color.ORANGE,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.CYAN,
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


# ─────────────────────────────────────────────
#  Report Generator
# ─────────────────────────────────────────────

class ReportGenerator:
    """
    Produces terminal output and report files from detection results.

    Usage
    -----
        rg = ReportGenerator(alerts, ip_profiles, summary, logfile)
        rg.print_terminal_report()
        rg.write_csv("report.csv")
        rg.write_txt("report.txt")
    """

    # Banner width for terminal display
    _WIDTH = 72

    def __init__(
        self,
        alerts: list[ThreatAlert],
        ip_profiles: dict[str, IPProfile],
        summary: dict,
        log_filepath: str,
        no_color: bool = False,
    ):
        self.alerts       = alerts
        self.ip_profiles  = ip_profiles
        self.summary      = summary
        self.log_filepath = log_filepath
        self.no_color     = no_color
        self._run_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Terminal Output ───────────────────────

    def print_terminal_report(self) -> None:
        """Print the full analysis report to stdout with colour formatting."""
        self._print_header()
        self._print_alerts()
        self._print_ip_table()
        self._print_summary()
        self._print_footer()

    # ── File Output ───────────────────────────

    def write_csv(self, output_path: str) -> None:
        """
        Write a CSV file with one row per observed IP address.
        Columns: IP, Failed, Success, Unique Usernames, Status, Alert Type,
                 Severity, First Seen, Last Seen.
        """
        suspicious_ips = {a.ip_address for a in self.alerts if a.severity in ("CRITICAL", "HIGH")}

        fieldnames = [
            "IP Address", "Failed Attempts", "Success Attempts",
            "Unique Usernames", "Status", "Alert Type", "Severity",
            "First Seen", "Last Seen", "Usernames Tried",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip, profile in sorted(self.ip_profiles.items()):
                # Find the highest-severity alert for this IP
                ip_alerts = [a for a in self.alerts if a.ip_address == ip]
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                ip_alerts.sort(key=lambda a: sev_order.get(a.severity, 9))

                top_alert  = ip_alerts[0] if ip_alerts else None
                alert_type = top_alert.alert_type if top_alert else "N/A"
                severity   = top_alert.severity   if top_alert else "N/A"
                status     = "Suspicious" if ip in suspicious_ips else "Normal"

                writer.writerow({
                    "IP Address":        ip,
                    "Failed Attempts":   profile.failed_count,
                    "Success Attempts":  profile.success_count,
                    "Unique Usernames":  profile.unique_usernames,
                    "Status":            status,
                    "Alert Type":        alert_type,
                    "Severity":          severity,
                    "First Seen":        profile.first_seen or "N/A",
                    "Last Seen":         profile.last_seen  or "N/A",
                    "Usernames Tried":   "|".join(sorted(profile.usernames_tried)),
                })

    def write_txt(self, output_path: str) -> None:
        """
        Write a plain-text version of the terminal report (no ANSI codes).
        Useful for emailing or archiving.
        """
        import io, sys

        # Capture terminal output then strip colour codes
        buffer = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buffer

        self.no_color = True
        self.print_terminal_report()
        self.no_color = False

        sys.stdout = old_stdout
        plain_text = Color.strip(buffer.getvalue())

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(plain_text)

    # ── Internal Helpers ─────────────────────

    def _c(self, color: str, text: str) -> str:
        """Apply colour if enabled; otherwise return plain text."""
        if self.no_color:
            return text
        return f"{color}{text}{Color.RESET}"

    def _print_header(self) -> None:
        w = self._WIDTH
        print()
        print(self._c(Color.BLUE, "╔" + "═" * (w - 2) + "╗"))
        print(self._c(Color.BLUE, "║") +
              self._c(Color.BOLD + Color.WHITE, " LOG-BASED THREAT DETECTION SYSTEM".center(w - 2)) +
              self._c(Color.BLUE, "║"))
        print(self._c(Color.BLUE, "║") +
              self._c(Color.GREY, " Security Operations Center — Authentication Log Analyser".center(w - 2)) +
              self._c(Color.BLUE, "║"))
        print(self._c(Color.BLUE, "╠" + "═" * (w - 2) + "╣"))
        print(self._c(Color.BLUE, "║") +
              self._c(Color.DIM, f"  Log File : {self.log_filepath}".ljust(w - 2)) +
              self._c(Color.BLUE, "║"))
        print(self._c(Color.BLUE, "║") +
              self._c(Color.DIM, f"  Run Time : {self._run_time}".ljust(w - 2)) +
              self._c(Color.BLUE, "║"))
        print(self._c(Color.BLUE, "╚" + "═" * (w - 2) + "╝"))
        print()

    def _print_alerts(self) -> None:
        print(self._c(Color.BOLD + Color.WHITE, "  ▶  THREAT ALERTS"))
        print(self._c(Color.GREY, "  " + "─" * (self._WIDTH - 4)))

        if not self.alerts:
            print(self._c(Color.GREEN, "  ✔  No threats detected. All activity appears normal."))
            print()
            return

        # Group alerts by severity for a clean grouped display
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        grouped = {s: [a for a in self.alerts if a.severity == s] for s in sev_order}

        for sev in sev_order:
            for alert in grouped[sev]:
                color = SEVERITY_COLORS.get(sev, Color.WHITE)
                icon  = SEVERITY_ICONS.get(sev, "●")

                print()
                print(
                    self._c(color, f"  {icon} [{alert.severity}]") +
                    self._c(Color.BOLD, f" {alert.alert_type}") +
                    self._c(Color.GREY, f"  ─  IP: ") +
                    self._c(Color.WHITE, alert.ip_address)
                )
                print(self._c(Color.DIM, f"     {alert.description}"))
                print(
                    self._c(Color.GREY, "     ├─ Failures : ") +
                    self._c(color, str(alert.failed_count)) +
                    self._c(Color.GREY, "   Successes : ") +
                    self._c(Color.GREEN, str(alert.success_count))
                )
                print(
                    self._c(Color.GREY, "     ├─ Usernames tried : ") +
                    self._c(Color.CYAN, ", ".join(sorted(alert.usernames)[:8]) +
                            ("..." if len(alert.usernames) > 8 else ""))
                )
                print(
                    self._c(Color.GREY, "     └─ Window : ") +
                    self._c(Color.DIM, f"{alert.first_seen}  →  {alert.last_seen}")
                )
        print()

    def _print_ip_table(self) -> None:
        print(self._c(Color.BOLD + Color.WHITE, "  ▶  IP ACTIVITY TABLE"))
        print(self._c(Color.GREY, "  " + "─" * (self._WIDTH - 4)))
        print()

        # Column widths
        suspicious_ips = {a.ip_address for a in self.alerts if a.severity in ("CRITICAL", "HIGH")}

        header = (
            f"  {'IP Address':<20} {'Failed':>8} {'Success':>8} "
            f"{'Usernames':>10} {'Status':<14} {'Severity'}"
        )
        print(self._c(Color.BOLD + Color.WHITE, header))
        print(self._c(Color.GREY, "  " + "─" * (self._WIDTH - 4)))

        for ip, profile in sorted(
            self.ip_profiles.items(),
            key=lambda kv: kv[1].failed_count,
            reverse=True,
        ):
            ip_alerts = [a for a in self.alerts if a.ip_address == ip]
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            ip_alerts.sort(key=lambda a: sev_order.get(a.severity, 9))
            top_alert = ip_alerts[0] if ip_alerts else None

            if ip in suspicious_ips:
                status = "⚠  Suspicious"
                status_color = Color.RED
            elif top_alert and top_alert.severity == "MEDIUM":
                status = "⚡ Watch"
                status_color = Color.YELLOW
            elif top_alert and top_alert.severity == "LOW":
                status = "🔵 Probe"
                status_color = Color.CYAN
            else:
                status = "✔  Normal"
                status_color = Color.GREEN

            sev_str = top_alert.severity if top_alert else "—"
            sev_color = SEVERITY_COLORS.get(sev_str, Color.GREY)

            print(
                f"  {self._c(Color.WHITE, ip):<20}"
                f" {self._c(Color.RED if profile.failed_count > 0 else Color.GREY, str(profile.failed_count)):>17}"
                f" {self._c(Color.GREEN, str(profile.success_count)):>17}"
                f" {self._c(Color.CYAN, str(profile.unique_usernames)):>19}"
                f"  {self._c(status_color, status):<23}"
                f"  {self._c(sev_color, sev_str)}"
            )
        print()

    def _print_summary(self) -> None:
        s = self.summary
        w = self._WIDTH
        print(self._c(Color.BOLD + Color.WHITE, "  ▶  ANALYSIS SUMMARY"))
        print(self._c(Color.GREY, "  " + "─" * (w - 4)))
        print()
        metrics = [
            ("Total IPs Observed",      str(s["total_ips_seen"]),         Color.WHITE),
            ("Total Failed Attempts",   str(s["total_failed_attempts"]),  Color.RED),
            ("Total Successful Logins", str(s["total_success_attempts"]), Color.GREEN),
            ("Alerts Raised",           str(s["total_alerts"]),           Color.ORANGE),
            ("Suspicious IPs",          str(s["suspicious_ips"]),         Color.RED),
            ("Detection Threshold",     str(s["threshold_used"]) + " failed attempts", Color.CYAN),
        ]
        for label, value, color in metrics:
            print(
                self._c(Color.GREY, f"    {label:<28}") +
                self._c(color, value)
            )

        if s["suspicious_ip_list"]:
            print()
            print(self._c(Color.GREY, f"    {'Flagged IPs':<28}") +
                  self._c(Color.RED, ", ".join(s["suspicious_ip_list"])))
        print()

    def _print_footer(self) -> None:
        w = self._WIDTH
        print(self._c(Color.GREY, "  " + "─" * (w - 4)))
        print(self._c(Color.DIM, "  End of Report  |  Generated by SOC Threat Detection System"))
        print()
