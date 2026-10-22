"""Orquestra o enriquecimento: valida, consulta o cache, respeita as cotas, chama os provedores e combina."""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Set, Union

from .cache import Store
from .indicators import classify
from .models import Enrichment, ProviderResult
from .ratelimit import ProviderError, QuotaExceeded
from .scoring import combine


class Enricher:
    def __init__(self, providers, store: Store, ttl_hours: float = 24, use_cache: bool = True,
                 progress: Optional[Callable[[str], None]] = None):
        self.providers = providers
        self.store = store
        self.ttl = ttl_hours * 3600
        self.use_cache = use_cache
        self.progress = progress or (lambda msg: None)
        self.disabled: Set[str] = set()   # provedores que estouraram a cota nesta execução
        self.stats = {"queries": 0, "cache_hits": 0, "errors": 0}

    def enrich(self, indicators: Union[Dict[str, int], Iterable[str]]) -> List[Enrichment]:
        counts = indicators if isinstance(indicators, dict) else {i: 1 for i in indicators}
        out = []
        for position, (raw, seen) in enumerate(counts.items(), 1):
            self.progress(f"[{position}/{len(counts)}] {raw}")
            out.append(self._enrich_one(raw, seen))
        return out

    def _enrich_one(self, raw: str, seen: int) -> Enrichment:
        parsed = classify(raw)
        if not parsed:
            return Enrichment(raw, "invalid", seen, verdict="invalid", reasons=["não é um IP, domínio ou hash válido"])
        kind, indicator = parsed
        item = Enrichment(indicator, kind, seen)

        for provider in self.providers:
            if not provider.supports(kind):
                continue
            if kind == "ip" and not provider.accepts_ip(indicator):
                item.skipped.append(f"{provider.name}: IP privado ou reservado, não consultado")
                continue
            if provider.name in self.disabled:
                item.skipped.append(f"{provider.name}: cota esgotada, consulta ignorada")
                continue
            result = self._query(provider, indicator, kind, item)
            if result:
                item.results.append(result)

        item.score, item.verdict, item.reasons = combine(item.results)
        if not item.results and item.skipped and item.verdict == "unknown":
            item.verdict = "ignored"
        return item

    def _query(self, provider, indicator: str, kind: str, item: Enrichment) -> Optional[ProviderResult]:
        if self.use_cache:
            cached = self.store.get(provider.name, kind, indicator, self.ttl)
            if cached:
                self.stats["cache_hits"] += 1
                return cached
        try:
            if provider.limiter:
                provider.limiter.acquire()
            result = provider.lookup(indicator, kind)
        except QuotaExceeded as exc:
            self.disabled.add(provider.name)
            item.skipped.append(str(exc))
            return None
        except (ProviderError, ConnectionError) as exc:
            self.stats["errors"] += 1
            return ProviderResult(provider.name, indicator, kind, "unknown", 0, "erro na consulta", error=str(exc))
        self.stats["queries"] += 1
        if provider.external:          # só vale guardar o que custou uma consulta externa
            self.store.put(result)
        return result
