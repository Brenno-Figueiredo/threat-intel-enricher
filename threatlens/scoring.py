"""Combina os resultados de vários provedores em uma nota de risco única (0 a 100) com explicação."""
from __future__ import annotations

from typing import List, Tuple

from .models import ProviderResult

MALICIOUS_AT = 75
SUSPICIOUS_AT = 40
CONSENSUS_BONUS = 10


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_AT:
        return "malicious"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"


def combine(results: List[ProviderResult]) -> Tuple[int, str, List[str]]:
    """Regra: vale a nota mais alta entre os provedores, mais um bônus quando 2 ou mais concordam.

    Por que a mais alta e não a média: basta uma fonte confiável acusar para o indicador merecer atenção.
    Provedores sem dados ou com erro não puxam a nota para baixo.
    """
    reasons = [f"{r.provider}: {r.summary}" for r in results if not r.error]
    usable = [r for r in results if not r.error and r.verdict != "unknown"]
    if not usable:
        return 0, "unknown", reasons
    score = max(r.score for r in usable)
    flagged = [r for r in usable if r.verdict in ("malicious", "suspicious")]
    if len(flagged) >= 2:
        score = min(100, score + CONSENSUS_BONUS)
        reasons.append(f"Consenso: {len(flagged)} fontes sinalizam este indicador (+{CONSENSUS_BONUS})")
    return score, verdict_for(score), reasons
