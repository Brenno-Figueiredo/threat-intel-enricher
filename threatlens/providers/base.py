"""Interface comum dos provedores de inteligência de ameaças."""
from __future__ import annotations

import time
from typing import Optional

from ..http import Transport, urllib_transport
from ..indicators import is_global_ip
from ..models import ProviderResult
from ..ratelimit import RateLimiter


class Provider:
    name = "base"
    external = True            # True = envia o indicador a um serviço de terceiros pela internet
    kinds = ()                 # tipos de indicador que sabe consultar

    def __init__(self, transport: Transport = urllib_transport, limiter: Optional[RateLimiter] = None):
        self.transport = transport
        self.limiter = limiter

    def supports(self, kind: str) -> bool:
        return kind in self.kinds

    def accepts_ip(self, ip: str) -> bool:
        """Provedores externos só recebem IPs públicos. Os locais (lista de bloqueio) aceitam qualquer um."""
        return (not self.external) or is_global_ip(ip)

    def lookup(self, indicator: str, kind: str) -> ProviderResult:
        raise NotImplementedError

    def _result(self, indicator: str, kind: str, verdict: str, score: int, summary: str, **details) -> ProviderResult:
        return ProviderResult(self.name, indicator, kind, verdict, int(score), summary,
                              details=details, queried_at=time.time())
