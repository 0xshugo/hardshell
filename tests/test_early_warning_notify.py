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
