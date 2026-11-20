import json
from pathlib import Path

import pytest

from hardshell.reporters import discord


def actionable_report(case_id="abc123"):
    return {
        "status": "actionable",
        "cases": [
            {
                "case_id": case_id,
                "advisory_id": "CVE-2026-123007",
                "product": "nginx",
                "asset_id": "factory-nginx",
                "installed": "1.29.3",
                "fixed": "1.30.7",
                "status": "actionable",
                "priority": "P1",
                "exposure": "public",
                "public_summary": "Memory corruption in HTTP/2 flow control",
            }
        ],
    }


@pytest.mark.asyncio
async def test_actionable_early_warning_posts_once(tmp_path, monkeypatch):
    posts = []

    async def fake_send(url, content):
        posts.append((url, content))
        return True

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.test/webhook")
    monkeypatch.setattr(discord, "_send", fake_send)
    state = tmp_path / "alerts.json"

    assert await discord.notify_early_warning(actionable_report(), "host-a", state_path=state)
    assert await discord.notify_early_warning(actionable_report(), "host-a", state_path=state)
    assert len(posts) == 1
    assert "HIGH early-warning" in posts[0][1]
    assert "CVE-2026-123007" in posts[0][1]
    saved = json.loads(Path(state).read_text())
    assert saved["case_ids"] == ["abc123"]


@pytest.mark.asyncio
async def test_non_actionable_is_silent(monkeypatch):
    posts = []

    async def fake_send(url, content):
        posts.append(content)
        return True

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.test/webhook")
    monkeypatch.setattr(discord, "_send", fake_send)
    assert await discord.notify_early_warning({"status": "needs_review", "cases": []}, "host")
    assert not posts


@pytest.mark.asyncio
async def test_remediation_lifecycle_templates(monkeypatch):
    posts = []

    async def fake_send(url, content):
        posts.append(content)
        return True

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.test/webhook")
    monkeypatch.setattr(discord, "_send", fake_send)
    assert await discord.notify_remediation_lifecycle(
        phase="pending_approval",
        advisory_id="CVE-2026-123007",
        asset_id="factory-nginx",
        hostname="host",
    )
    assert "要承認" in posts[0]
    assert await discord.notify_remediation_lifecycle(
        phase="completed",
        advisory_id="CVE-2026-123007",
        asset_id="factory-nginx",
        hostname="host",
    )
    assert "完了" in posts[1]


@pytest.mark.asyncio
async def test_unconfigured_webhook_returns_false_and_records_status(tmp_path, monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("HARDSHELL_STATUS_WEBHOOK_URL", raising=False)
    state = tmp_path / "alerts.json"

    res = await discord.deliver_early_warning(actionable_report(), "host-a", state_path=state)
    assert res["ok"] is False
    assert res["status"] == "skipped_unconfigured"
    assert res["consecutive_failures"] == 1
    saved = json.loads(state.read_text())
    assert saved["last_delivery"]["status"] == "skipped_unconfigured"


@pytest.mark.asyncio
async def test_php_actionable_uses_php_playbook_and_tracks_failures(tmp_path, monkeypatch):
    posts = []

    async def fake_send_fail(url, content):
        posts.append(content)
        return False

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.test/webhook")
    monkeypatch.setattr(discord, "_send", fake_send_fail)
    state = tmp_path / "alerts.json"
    php_report = {
        "status": "actionable",
        "cases": [
            {
                "case_id": "php-1",
                "advisory_id": "CVE-2026-129496",
                "product": "php",
                "asset_id": "freshrss",
                "installed": "8.4.27",
                "fixed": "8.4.28",
                "status": "actionable",
                "priority": "P1",
                "exposure": "public",
                "public_summary": "Timezone cache UAF",
            }
        ],
    }

    failed = await discord.deliver_early_warning(php_report, "host-a", state_path=state)
    assert failed["ok"] is False
    assert failed["status"] == "failed"
    assert failed["consecutive_failures"] == 1
    assert "operations/playbooks/php-upgrade.md" in posts[0]
    assert json.loads(state.read_text())["case_ids"] == []

    async def fake_send_ok(url, content):
        posts.append(content)
        return True

    monkeypatch.setattr(discord, "_send", fake_send_ok)
    sent = await discord.deliver_early_warning(php_report, "host-a", state_path=state)
    assert sent["ok"] is True
    assert sent["status"] == "sent"
    assert sent["consecutive_failures"] == 0
    assert json.loads(state.read_text())["case_ids"] == ["php-1"]

