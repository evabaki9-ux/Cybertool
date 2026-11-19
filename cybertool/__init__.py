"""Cybertool — port scanning and local vulnerability signature lookup."""

from . import scanner, vulns
from .scanner import scan_target

__version__ = "0.3.0"
__author__ = "evabaki9-ux"

__all__ = ["__version__", "__author__", "scan_target", "scanner", "vulns"]
