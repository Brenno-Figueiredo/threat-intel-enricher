"""Armazenamento local (SQLite): cache de resultados com validade (TTL) e contagem de uso diário.

Economiza a cota gratuita das APIs: o mesmo IP consultado de novo dentro do TTL não gasta requisição.
Nenhuma chave de API é gravada aqui.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Callable, Dict, Optional

from .models import ProviderResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS results(
  provider TEXT, kind TEXT, indicator TEXT, ts REAL, data TEXT,
  PRIMARY KEY(provider, kind, indicator));
CREATE TABLE IF NOT EXISTS usage(
  provider TEXT, day TEXT, n INTEGER, PRIMARY KEY(provider, day));
"""


class Store:
    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time):
        self.clock = clock
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        with self.lock, self.conn:
            self.conn.executescript(SCHEMA)

    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))  # as cotas resetam em UTC

    # ---- cache -------------------------------------------------------------
    def get(self, provider: str, kind: str, indicator: str, ttl: float) -> Optional[ProviderResult]:
        with self.lock:
            row = self.conn.execute(
                "SELECT ts, data FROM results WHERE provider=? AND kind=? AND indicator=?",
                (provider, kind, indicator)).fetchone()
        if not row or self.clock() - row[0] > ttl:
            return None
        result = ProviderResult.from_dict(json.loads(row[1]))
        result.cached = True
        return result

    def put(self, result: ProviderResult) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO results(provider,kind,indicator,ts,data) VALUES(?,?,?,?,?)",
                (result.provider, result.kind, result.indicator, self.clock(),
                 json.dumps(result.to_dict(), ensure_ascii=False)))

    # ---- uso diário ---------------------------------------------------------
    def used_today(self, provider: str) -> int:
        with self.lock:
            row = self.conn.execute("SELECT n FROM usage WHERE provider=? AND day=?",
                                    (provider, self._day())).fetchone()
        return row[0] if row else 0

    def add_use(self, provider: str) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO usage(provider,day,n) VALUES(?,?,1) "
                "ON CONFLICT(provider,day) DO UPDATE SET n=n+1", (provider, self._day()))

    # ---- manutenção ---------------------------------------------------------
    def stats(self) -> Dict:
        with self.lock:
            rows = self.conn.execute("SELECT provider, COUNT(*) FROM results GROUP BY provider").fetchall()
            usage = self.conn.execute("SELECT provider, n FROM usage WHERE day=?", (self._day(),)).fetchall()
        return {"entries": sum(n for _, n in rows), "by_provider": dict(rows), "used_today": dict(usage)}

    def clear(self) -> None:
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM results")

    def close(self) -> None:
        with self.lock:
            self.conn.close()
