"""VirusTotal (API v3): reputação de IPs, domínios e hashes de arquivos, segundo dezenas de motores.

Documentação: https://docs.virustotal.com/ . A API pública é limitada a 4 requisições por minuto
e 500 por dia, e NÃO pode ser usada em produtos comerciais (use apenas para estudo e uso pessoal).
"""
from __future__ import annotations

from ..http import get_json
from ..ratelimit import ProviderError, QuotaExceeded
from .base import Provider

BASE_URL = "https://www.virustotal.com/api/v3"
ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files"}


class VirusTotal(Provider):
    name = "virustotal"
    kinds = tuple(ENDPOINTS)

    def __init__(self, api_key: str, **kwargs):
        super().__init__(**kwargs)
        self._key = api_key

    def lookup(self, indicator: str, kind: str):
        # o indicador já foi validado em indicators.classify, então é seguro usá-lo no caminho da URL
        url = f"{BASE_URL}/{ENDPOINTS[kind]}/{indicator}"
        status, _, body = get_json(self.transport, url, {"x-apikey": self._key})
        if status == 404:
            return self._result(indicator, kind, "unknown", 0, "não encontrado no VirusTotal")
        if status == 429:
            raise QuotaExceeded("VirusTotal: limite de requisições excedido (HTTP 429)")
        if status in (401, 403):
            raise ProviderError("VirusTotal: chave de API inválida ou sem permissão")
        if status != 200 or "data" not in body:
            raise ProviderError(f"VirusTotal: resposta inesperada (HTTP {status})")

        attrs = body["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        # 10 pontos por motor que acusa e 5 por motor que suspeita: 10 motores acusando já dá 100
        score = min(100, malicious * 10 + suspicious * 5)
        if malicious >= 5:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"
        summary = f"{malicious} motor(es) acusam e {suspicious} suspeitam, de {total} analisados"
        extra = {"malicious": malicious, "suspicious": suspicious, "engines": total,
                 "reputation": attrs.get("reputation")}
        if kind == "ip":
            extra.update(country=attrs.get("country"), as_owner=attrs.get("as_owner"))
        elif kind == "domain":
            extra.update(registrar=attrs.get("registrar"), categories=attrs.get("categories"))
        else:
            label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            extra.update(file_name=attrs.get("meaningful_name"), file_type=attrs.get("type_description"),
                         size=attrs.get("size"), threat_label=label)
            if label:
                summary += f", classificado como {label}"
        return self._result(indicator, kind, verdict, score, summary, **extra)
