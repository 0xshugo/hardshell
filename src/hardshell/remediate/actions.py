"""Remediation action definitions and tier classification."""

from __future__ import annotations

import fnmatch
from enum import StrEnum

from pydantic import BaseModel


class RemediationTier(StrEnum):
    AUTO = "auto"      # Execute immediately, notify after
    PROPOSE = "propose"  # Notify + execute after maintenance window
    ALERT = "alert"    # Notify only, human decision required


class RemediationAction(BaseModel):
    finding_id_pattern: str
    tier: RemediationTier
    title: str
    command: str | None = None
    description: str = ""
    requires_reboot: bool = False
    maintenance_window_only: bool = False

    def matches(self, finding_id: str) -> bool:
        return fnmatch.fnmatch(finding_id, self.finding_id_pattern)


# Ordered: first match wins
RULES: list[RemediationAction] = [
    # AUTO — safe, idempotent, no service interruption
    RemediationAction(
        finding_id_pattern="SSL-EXPIRY-*",
        tier=RemediationTier.AUTO,
        title="Renew SSL certificate",
        command="certbot renew --quiet --deploy-hook 'docker kill --signal=HUP factory-nginx'",
        description="Renew expired/expiring Let's Encrypt certificate and reload nginx.",
    ),
    RemediationAction(
        finding_id_pattern="SYS-F2B-DOWN",
        tier=RemediationTier.AUTO,
        title="Restart fail2ban",
        command="systemctl restart fail2ban",
        description="Restart fail2ban service to restore brute-force protection.",
    ),
    RemediationAction(
        finding_id_pattern="SYS-AUTOUPD-OFF",
        tier=RemediationTier.AUTO,
        title="Enable unattended-upgrades",
        command="systemctl enable --now unattended-upgrades",
        description="Ensure automatic security updates are running.",
    ),
    RemediationAction(
        finding_id_pattern="SYS-F2B-MISSING",
        tier=RemediationTier.PROPOSE,
        title="Install fail2ban",
        command="apt-get install -y fail2ban && systemctl enable --now fail2ban",
        description="Install fail2ban to protect against brute-force attacks.",
    ),
    # PROPOSE — service restart or package upgrade (maintenance window preferred)
    RemediationAction(
        finding_id_pattern="SYS-PKG-SEC",
        tier=RemediationTier.PROPOSE,
        title="Apply security package updates",
        command="DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
        description="Apply pending OS security updates.",
        maintenance_window_only=True,
    ),
    # ALERT — human judgment required, could cause lockout or data loss
    RemediationAction(
        finding_id_pattern="SYS-DOCKER-PRIV",
        tier=RemediationTier.ALERT,
        title="Privileged container detected",
        description="Remove --privileged flag and use specific capabilities instead.",
    ),
    RemediationAction(
        finding_id_pattern="SYS-SSH-*",
        tier=RemediationTier.ALERT,
        title="SSH configuration issue",
        description="SSH changes require careful review to avoid lockout.",
    ),
    RemediationAction(
        finding_id_pattern="SYS-FW-INACTIVE",
        tier=RemediationTier.ALERT,
        title="Firewall is inactive",
        description="Enable firewall after reviewing current open ports.",
    ),
]


def get_rule(finding_id: str) -> RemediationAction | None:
    for rule in RULES:
        if rule.matches(finding_id):
            return rule
    return None
