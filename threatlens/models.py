"""Estruturas de dados: resultado de um provedor e enriquecimento final de um indicador."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List

VERDICTS = ("malicious", "suspicious", "clean", "unknown")
VERDICT_LABEL = {"malicious": "Malicioso", "suspicious": "Suspeito", "clean": "Limpo",
                 "unknown": "Sem dados", "ignored": "Ignorado", "invalid": "Inválido"}


@dataclass
class ProviderResult:
    provider: str
    indicator: str
    kind: str
    verdict: str               # malicious | suspicious | clean | unknown
    score: int                 # 0 a 100
    summary: str
    details: Dict = field(default_factory=dict)
    error: str = ""
    cached: bool = False
    queried_at: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "ProviderResult":
        return cls(**data)


@dataclass
class Enrichment:
    indicator: str
    kind: str
    seen: int = 1
    results: List[ProviderResult] = field(default_factory=list)
    score: int = 0
    verdict: str = "unknown"   # malicious | suspicious | clean | unknown | ignored | invalid
    reasons: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"indicator": self.indicator, "kind": self.kind, "seen": self.seen, "score": self.score,
                "verdict": self.verdict, "reasons": self.reasons, "skipped": self.skipped,
                "results": [r.to_dict() for r in self.results]}
