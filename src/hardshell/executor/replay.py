"""Durable, atomic replay barrier. A claim is consumed BEFORE side effects."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

from hardshell.executor.contract import AuthorizedPlan
from hardshell.executor.verify import ExecutorDenied


class PersistentReplayStore:
    """SQLite on local durable storage, shared by executor processes on a node.

    Storage owner must provision a private 0700 parent directory. A restart does
    not clear claims; an unknown operation must be reconciled, never auto-retried.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        parent = self.path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ExecutorDenied("replay store parent must already exist")
        parent_info = parent.stat()
        if parent_info.st_mode & 0o077:
            raise ExecutorDenied("replay directory is accessible by other users")
        if self.path.is_symlink():
            raise ExecutorDenied("replay store symlinks are prohibited")
        if not self.path.exists():
            try:
                fd = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(fd)
            except FileExistsError:
                pass
        if not stat.S_ISREG(self.path.stat().st_mode) or self.path.stat().st_mode & 0o077:
            raise ExecutorDenied("replay database must be a private regular file")
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS claims ("
                " tenant TEXT NOT NULL, executor TEXT NOT NULL, nonce TEXT NOT NULL,"
                " plan_id TEXT NOT NULL, claimed_at TEXT NOT NULL,"
                " status TEXT NOT NULL DEFAULT 'claimed',"
                " provider_ids_json TEXT NOT NULL DEFAULT '[]',"
                " PRIMARY KEY (tenant, executor, nonce),"
                " UNIQUE (tenant, executor, plan_id))"
            )

    def claim(self, plan: AuthorizedPlan) -> None:
        try:
            with sqlite3.connect(self.path, timeout=5, isolation_level=None) as db:
                db.execute("PRAGMA busy_timeout=5000")
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO claims(tenant, executor, nonce, plan_id, claimed_at) "
                        "VALUES(?,?,?,?,datetime('now'))",
                        (plan.tenant_id, plan.executor_id, str(plan.nonce), str(plan.plan_id)),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        except sqlite3.IntegrityError as exc:
            raise ExecutorDenied("duplicate plan or nonce") from exc
        except sqlite3.Error as exc:
            raise ExecutorDenied("replay ledger unavailable") from exc

    def record_outcome(self, plan: AuthorizedPlan, status: str, provider_ids: list[str]) -> None:
        """Persist the bounded result; CLAIMED remains UNKNOWN after process crash."""
        if status not in {"accepted", "unknown"}:
            raise ValueError("an executor must not claim verified success")
        try:
            with sqlite3.connect(self.path, timeout=5, isolation_level=None) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    cursor = db.execute(
                        "UPDATE claims SET status=?, provider_ids_json=? "
                        "WHERE tenant=? AND executor=? AND plan_id=? AND status='claimed'",
                        (status, json.dumps(provider_ids), plan.tenant_id,
                         plan.executor_id, str(plan.plan_id)),
                    )
                    if cursor.rowcount != 1:
                        raise ExecutorDenied("execution receipt cannot be recorded")
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise ExecutorDenied("receipt ledger unavailable") from exc
