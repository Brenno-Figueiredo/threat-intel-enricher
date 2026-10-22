"""AbuseIPDB: reputação de IPs com base em denúncias da comunidade (endpoint /api/v2/check).

Documentação: https://docs.abuseipdb.com/ . O plano gratuito permite 1.000 consultas por dia.
"""
from __future__ import annotations

from urllib.parse import urlencode

from ..http import get_json
from ..ratelimit import ProviderError, QuotaExceeded
from .base import Provider

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "abuseipdb"
    kinds = ("ip",)

    def __init__(self, api_key: str, max_age_days: int = 90, **kwargs):
        super().__init__(**kwargs)
        self._key = api_key              # nunca é impresso nem gravado
        self.max_age_days = max_age_days

    def lookup(self, indicator: str, kind: str):
        query = urlencode({"ipAddress": indicator, "maxAgeInDays": self.max_age_days})
        status, _, body = get_json(self.transport, f"{BASE_URL}?{query}", {"Key": self._key})
        if status == 429:
            raise QuotaExceeded("AbuseIPDB: limite diário de consultas excedido (HTTP 429)")
        if status in (401, 403):
            raise ProviderError("AbuseIPDB: chave de API inválida ou sem permissão")
        if status == 422:
            raise ProviderError("AbuseIPDB: IP rejeitado como inválido")
        if status != 200 or "data" not in body:
            raise ProviderError(f"AbuseIPDB: resposta inesperada (HTTP {status})")

        d = body["data"]
        score = int(d.get("abuseConfidenceScore", 0))
        reports = int(d.get("totalReports", 0))
        if d.get("isWhitelisted"):
            verdict = "clean"
        elif score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        else:
            verdict = "clean"
        summary = f"confiança de abuso {score}%, {reports} denúncia(s)"
        if d.get("isWhitelisted"):
            summary += ", IP em lista de confiança"
        return self._result(
            indicator, kind, verdict, score, summary,
            country=d.get("countryCode"), isp=d.get("isp"), usage_type=d.get("usageType"),
            domain=d.get("domain"), total_reports=reports, distinct_users=d.get("numDistinctUsers"),
            last_reported=d.get("lastReportedAt"), is_tor=d.get("isTor"))
