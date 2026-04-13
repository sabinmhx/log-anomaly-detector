"""
threat_detection — SOC Log Analysis Package
============================================
Core modules:
  parser   — auth.log parsing
  detector — threat detection engine
  report   — terminal + file output
"""

from .parser   import LogParser, LogEntry
from .detector import ThreatDetector, ThreatAlert, IPProfile
from .report   import ReportGenerator

__version__ = "1.0.0"
__all__ = [
    "LogParser", "LogEntry",
    "ThreatDetector", "ThreatAlert", "IPProfile",
    "ReportGenerator",
]
