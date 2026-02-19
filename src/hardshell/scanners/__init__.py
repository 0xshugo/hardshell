"""Scanner registry — auto-discovers available scanners."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hardshell.scanners.grype import GrypeScanner
from hardshell.scanners.lynis import LynisScanner
from hardshell.scanners.nuclei import NucleiScanner
from hardshell.scanners.system import SystemScanner
from hardshell.scanners.trivy import TrivyScanner

if TYPE_CHECKING:
    from hardshell.scanners.base import Scanner

SCANNER_CLASSES: dict[str, type] = {
    "system": SystemScanner,
    "trivy": TrivyScanner,
    "grype": GrypeScanner,
    "lynis": LynisScanner,
    "nuclei": NucleiScanner,
}


def list_available_scanners() -> list[str]:
    return [name for name, cls in SCANNER_CLASSES.items() if cls.is_available()]


def get_scanner(name: str) -> Scanner:
    cls = SCANNER_CLASSES[name]
    return cls()
