"""Abstract scanner protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from hardshell.config import ScanConfig
from hardshell.models import Finding


@runtime_checkable
class Scanner(Protocol):
    name: str

    @staticmethod
    def is_available() -> bool:
        """Check if the scanner binary/prerequisites exist."""
        ...

    async def scan(self, config: ScanConfig) -> list[Finding]:
        """Run scan and return unified findings."""
        ...
