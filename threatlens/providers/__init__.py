"""Montagem dos provedores a partir da configuração (chaves vindas do ambiente, nunca do código)."""
from __future__ import annotations

import os
from typing import Dict, List, Optional

from ..cache import Store
from ..http import urllib_transport
from ..ratelimit import RateLimiter
from .abuseipdb import AbuseIPDB
from .blocklist import Blocklist
from .demo import DemoProvider
from .virustotal import VirusTotal


class NoProvidersError(Exception):
    pass


def load_env_file(path: Optional[str]) -> Dict[str, str]:
    """Lê um arquivo .env simples (CHAVE=valor). As variáveis reais do sistema têm prioridade."""
    values: Dict[str, str] = {}
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip("\"'")
    values.update({k: v for k, v in os.environ.items()})
    return values


def _int(env: Dict[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, default))
    except (TypeError, ValueError):
        return default


def configured(env: Dict[str, str]) -> Dict[str, bool]:
    return {"abuseipdb": bool(env.get("ABUSEIPDB_API_KEY")),
            "virustotal": bool(env.get("VT_API_KEY") or env.get("VIRUSTOTAL_API_KEY"))}


def build_providers(env: Dict[str, str], store: Store, demo: bool = False, blocklist: Optional[str] = None,
                    only: Optional[List[str]] = None, transport=urllib_transport, on_wait=None):
    if demo:
        return [DemoProvider()]
    providers = []
    keys = configured(env)

    def wanted(name: str) -> bool:
        return only is None or name in only

    if keys["abuseipdb"] and wanted("abuseipdb"):
        limiter = RateLimiter("abuseipdb", store, per_day=_int(env, "ABUSEIPDB_DAILY_LIMIT", 1000), on_wait=on_wait)
        providers.append(AbuseIPDB(env["ABUSEIPDB_API_KEY"], transport=transport, limiter=limiter))
    if keys["virustotal"] and wanted("virustotal"):
        limiter = RateLimiter("virustotal", store, per_minute=_int(env, "VT_REQUESTS_PER_MINUTE", 4),
                              per_day=_int(env, "VT_REQUESTS_PER_DAY", 500), on_wait=on_wait)
        key = env.get("VT_API_KEY") or env.get("VIRUSTOTAL_API_KEY")
        providers.append(VirusTotal(key, transport=transport, limiter=limiter))
    if blocklist and wanted("blocklist"):
        providers.append(Blocklist(blocklist))
    if not providers:
        raise NoProvidersError(
            "Nenhum provedor configurado. Defina ABUSEIPDB_API_KEY e/ou VT_API_KEY (veja o .env.example), "
            "use --blocklist arquivo.txt, ou rode com --demo para dados simulados.")
    return providers
