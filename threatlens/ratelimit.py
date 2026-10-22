"""Controle de cota: limite por minuto (janela deslizante) e limite diário (persistido no banco)."""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from .cache import Store


class QuotaExceeded(Exception):
    """A cota diária do provedor acabou. Esperar não adianta: ela só volta no reset diário."""


class ProviderError(Exception):
    """Falha ao consultar um provedor (chave inválida, erro HTTP, resposta inesperada)."""


class RateLimiter:
    def __init__(self, name: str, store: Store, per_minute: Optional[int] = None,
                 per_day: Optional[int] = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 on_wait: Optional[Callable[[str, float], None]] = None):
        self.name, self.store = name, store
        self.per_minute, self.per_day = per_minute, per_day
        self.clock, self.sleep, self.on_wait = clock, sleep, on_wait
        self._times: List[float] = []

    def acquire(self) -> None:
        """Reserva uma requisição. Espera se o limite por minuto estourou; falha se a cota diária acabou."""
        if self.per_day is not None and self.store.used_today(self.name) >= self.per_day:
            raise QuotaExceeded(f"{self.name}: cota diária de {self.per_day} consultas esgotada")
        if self.per_minute:
            self._prune()
            if len(self._times) >= self.per_minute:
                wait = 60 - (self.clock() - self._times[0]) + 0.05
                if self.on_wait:
                    self.on_wait(self.name, wait)
                self.sleep(max(wait, 0))
                self._prune()
            self._times.append(self.clock())
        self.store.add_use(self.name)

    def _prune(self) -> None:
        now = self.clock()
        self._times = [t for t in self._times if now - t < 60]
