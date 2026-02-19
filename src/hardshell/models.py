"""Unified data models for scan findings and results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }[self]


class Finding(BaseModel):
    """A single security finding from any scanner."""

    id: str = Field(description="CVE-ID or scanner-specific identifier")
    scanner: str = Field(description="Scanner that produced this finding")
    severity: Severity
    title: str
    description: str = ""
    affected: str = Field(description="Affected package, image, config, etc.")
    current_version: str | None = None
    fixed_version: str | None = None
    remediation: str | None = None

    # CTI enrichment (populated by intel modules)
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_cisa_kev: bool = False
    has_public_exploit: bool = False

    # Scoring (populated by scorer)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)

    @property
    def is_cve(self) -> bool:
        return self.id.startswith("CVE-")


class ScanSummary(BaseModel):
    """Aggregate counts by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return cls(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            info=counts.get("info", 0),
            total=len(findings),
        )


class ScanResult(BaseModel):
    """Complete result of a hardshell scan run."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hostname: str = ""
    os_info: str = ""
    scanners_used: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    llm_analysis: str | None = None

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by risk_score descending."""
        return sorted(self.findings, key=lambda f: f.risk_score, reverse=True)
