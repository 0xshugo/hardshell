"""Shell-level tests for the orca-control read-only share and the actionable precheck."""

import getpass
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRECHECK = ROOT / "operations" / "automations" / "precheck-actionable.sh"
SHARE = ROOT / "operations" / "share" / "hardshell-share-report.sh"
GRANT = ROOT / "operations" / "grant-orca-readonly.sh"
DROPIN = ROOT / "operations" / "systemd" / "hardshell-watch.service.d" / "50-share-report.conf"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


def _report(path: Path, *, age: timedelta = timedelta(minutes=5), cases=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "generated_at": (datetime.now(UTC) - age).isoformat(),
                "status": "actionable" if cases else "no_action",
                "cases": cases or [],
            }
        )
    )
    return path


def _precheck(tmp_path: Path, **env: str) -> subprocess.CompletedProcess:
    base = {
        "PATH": os.environ["PATH"],
        "HARDSHELL_SHARED_DIR": str(tmp_path / "shared"),
        "HARDSHELL_PROD_HOME": str(tmp_path / "prod"),
    }
    base.update(env)
    return subprocess.run(
        ["bash", str(PRECHECK)], env=base, capture_output=True, text=True, timeout=30
    )


ACTIONABLE = [{"case_id": "nginx-1", "status": "actionable", "product": "nginx"}]


def test_precheck_runs_when_shared_report_is_actionable(tmp_path):
    _report(tmp_path / "shared" / "early-warning.json", cases=ACTIONABLE)
    res = _precheck(tmp_path)
    assert res.returncode == 0
    assert "decision=run reason=actionable" in res.stdout
    assert str(tmp_path / "shared" / "early-warning.json") in res.stdout


def test_precheck_skips_fresh_report_without_actionable_cases(tmp_path):
    _report(
        tmp_path / "shared" / "early-warning.json",
        cases=[{"case_id": "x", "status": "potentially_affected"}],
    )
    res = _precheck(tmp_path)
    assert res.returncode == 1
    assert "decision=skip reason=no_actionable" in res.stdout


def test_precheck_runs_when_report_is_stale(tmp_path):
    _report(tmp_path / "shared" / "early-warning.json", age=timedelta(hours=3))
    res = _precheck(tmp_path)
    assert res.returncode == 0
    assert "reason=stale" in res.stdout


def test_precheck_runs_when_nothing_is_readable(tmp_path):
    res = _precheck(tmp_path)
    assert res.returncode == 0
    assert "decision=run reason=unreadable" in res.stdout


def test_precheck_never_uses_workspace_placeholder(tmp_path):
    # The repo's own build/early-warning.json is a placeholder; even if it existed and
    # were actionable, the precheck must report "unreadable" instead of trusting it.
    res = _precheck(tmp_path)
    assert str(ROOT / "build") not in res.stdout
    assert "reason=unreadable" in res.stdout


def test_precheck_runs_on_unparseable_report(tmp_path):
    path = tmp_path / "shared" / "early-warning.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    res = _precheck(tmp_path)
    assert res.returncode == 0
    assert "reason=unparseable" in res.stdout


def test_precheck_order_env_then_shared_then_prod(tmp_path):
    _report(tmp_path / "prod" / "build" / "early-warning.json", cases=ACTIONABLE)
    _report(tmp_path / "shared" / "early-warning.json")
    # shared (no actionable) wins over prod (actionable)
    assert _precheck(tmp_path).returncode == 1
    override = _report(tmp_path / "override.json", cases=ACTIONABLE)
    res = _precheck(tmp_path, HARDSHELL_EARLY_WARNING=str(override))
    assert res.returncode == 0
    assert str(override) in res.stdout


def test_precheck_falls_back_to_prod_home(tmp_path):
    _report(tmp_path / "prod" / "build" / "early-warning.json", cases=ACTIONABLE)
    res = _precheck(tmp_path)
    assert res.returncode == 0
    assert "reason=actionable" in res.stdout


def _git(cwd: Path, *args: str) -> None:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(cwd),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(["git", "-C", str(cwd), *args], env=env, check=True, capture_output=True)


@pytest.fixture
def prod_tree(tmp_path):
    home = tmp_path / "prod"
    (home / "build" / "state").mkdir(parents=True)
    (home / "reports").mkdir()
    _report(home / "build" / "early-warning.json", cases=ACTIONABLE)
    (home / "build" / "state" / "discord.env").write_text("WEBHOOK=secret-webhook\n")
    (home / ".env").write_text("API_KEY=secret-key\n")
    (home / "reports" / "daily-2026-11-19.json").write_text('{"day": 19}')
    (home / "reports" / "daily-2026-11-20.json").write_text('{"day": 20}')
    (home / "reports" / "weekly-2026-11-16.json").write_text('{"week": 47}')
    (home / "reports" / "daily-latest-notes.json").write_text('{"ignored": true}')
    shared = tmp_path / "shared"
    shared.mkdir()
    return home, shared


def _share(home: Path, shared: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
    base = {
        "PATH": os.environ["PATH"],
        "HARDSHELL_HOME": str(home),
        "HARDSHELL_SHARED_DIR": str(shared),
        "HARDSHELL_OWNER": getpass.getuser(),
    }
    base.update(env)
    return subprocess.run(
        ["bash", str(SHARE), *args], env=base, capture_output=True, text=True, timeout=30
    )


def test_share_publish_copies_only_allowlisted_files(prod_tree):
    home, shared = prod_tree
    res = _share(home, shared, "publish")
    assert res.returncode == 0, res.stderr
    visible = sorted(p.name for p in shared.iterdir() if not p.name.startswith("."))
    assert visible == ["daily-latest.json", "early-warning.json", "weekly-latest.json"]
    assert json.loads((shared / "daily-latest.json").read_text()) == {"day": 20}
    assert (shared / ".daily-source").read_text().strip() == "daily-2026-11-20.json"
    assert (shared / "early-warning.json").read_bytes() == (
        home / "build" / "early-warning.json"
    ).read_bytes()
    for p in shared.iterdir():
        assert oct(p.stat().st_mode & 0o777) == "0o640", p
        assert "secret" not in p.read_text()


def test_share_publish_skips_symlinked_sources(prod_tree):
    home, shared = prod_tree
    secret = home / "build" / "state" / "discord.env"
    (home / "reports" / "daily-2026-11-21.json").symlink_to(secret)
    res = _share(home, shared, "publish")
    assert res.returncode == 0
    for p in shared.iterdir():
        assert "secret" not in p.read_text()


def test_share_status_writes_version_json(prod_tree):
    home, shared = prod_tree
    _git(home, "init", "-q")
    _git(home, "add", "reports")
    _git(home, "commit", "-q", "-m", "init")
    _share(home, shared, "publish")
    res = _share(
        home, shared, "status", SERVICE_RESULT="success", EXIT_CODE="exited", EXIT_STATUS="2"
    )
    assert res.returncode == 0, res.stderr
    version = json.loads((shared / "version.json").read_text())
    assert version["schema"] == "hardshell-shared-version/v1"
    assert len(version["git_commit"]) >= 40
    assert version["git_dirty"] is False
    assert version["watch"]["exit_status"] == 2
    assert version["watch"]["service_result"] == "success"
    assert version["shared_files"]["early-warning.json"]
    assert version["report_sources"]["daily"] == "daily-2026-11-20.json"
    assert oct((shared / "version.json").stat().st_mode & 0o777) == "0o640"

    (home / "reports" / "daily-2026-11-19.json").write_text('{"day": "changed"}')
    _share(home, shared, "status")
    assert json.loads((shared / "version.json").read_text())["git_dirty"] is True


def test_share_status_without_git_is_null(prod_tree):
    home, shared = prod_tree
    res = _share(home, shared, "status", EXIT_STATUS="1", SERVICE_RESULT="exit-code")
    assert res.returncode == 0
    version = json.loads((shared / "version.json").read_text())
    assert version["git_commit"] is None
    assert version["git_dirty"] is None
    assert version["watch"]["exit_status"] == 1


def test_share_is_noop_when_shared_dir_missing(prod_tree, tmp_path):
    home, _ = prod_tree
    res = _share(home, tmp_path / "missing", "publish")
    assert res.returncode == 0
    assert "grant-orca-readonly" in res.stderr


def test_dropin_uses_root_post_hooks_and_success_status():
    text = DROPIN.read_text()
    assert "SuccessExitStatus=2" in text
    assert "ExecStartPost=-+/usr/local/libexec/hardshell/share-report publish" in text
    assert "ExecStopPost=-+/usr/local/libexec/hardshell/share-report status" in text


def test_grant_dry_run_changes_nothing_and_prints_rollback(tmp_path):
    res = subprocess.run(
        ["bash", str(GRANT), "--dry-run", "--with-journal"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    out = res.stdout
    assert "[dry-run] install -d -m 0750 -o root -g orca-control /var/lib/hardshell-shared" in out
    assert "systemctl daemon-reload" in out
    assert "Rollback:" in out
    assert "gpasswd -d orca-control systemd-journal" in out
    assert "setfacl" not in GRANT.read_text().split("set -euo pipefail", 1)[1]


def test_grant_without_journal_flag_never_touches_groups():
    res = subprocess.run(
        ["bash", str(GRANT), "--dry-run"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    assert "usermod" not in res.stdout
    assert "systemd-journal" not in res.stdout
