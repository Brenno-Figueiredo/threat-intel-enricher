"""Transporte HTTP mínimo sobre urllib. É injetável: nos testes, troca-se por um falso (sem internet)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable, Dict, Tuple

MAX_BYTES = 2 * 1024 * 1024
USER_AGENT = "ThreatLens/1.0 (projeto educacional)"

# (método, url, headers, timeout) -> (status, headers em minúsculas, corpo em bytes)
Transport = Callable[[str, str, Dict[str, str], float], Tuple[int, Dict[str, str], bytes]]


def urllib_transport(method: str, url: str, headers: Dict[str, str], timeout: float):
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", **headers}
    req = urllib.request.Request(url, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # TLS verificado por padrão
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(MAX_BYTES)
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read(MAX_BYTES)
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise ConnectionError(f"falha de rede: {getattr(err, 'reason', err)}") from None


def get_json(transport: Transport, url: str, headers: Dict[str, str], timeout: float = 15.0):
    """Faz um GET e devolve (status, headers, dados). 'dados' é {} se o corpo não for JSON."""
    status, hdrs, body = transport("GET", url, headers, timeout)
    try:
        data = json.loads(body.decode("utf-8", "replace")) if body else {}
    except ValueError:
        data = {}
    return status, hdrs, data
