"""Lista de bloqueio local: um arquivo seu com indicadores conhecidos (um por linha). Funciona offline."""
from __future__ import annotations

import ipaddress

from ..indicators import classify
from .base import Provider


class Blocklist(Provider):
    name = "blocklist"
    external = False
    kinds = ("ip", "domain", "md5", "sha1", "sha256")

    def __init__(self, path: str, **kwargs):
        super().__init__(**kwargs)
        self.exact = set()
        self.networks = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                text = line.split("#", 1)[0].strip()
                if not text:
                    continue
                if "/" in text:
                    try:
                        self.networks.append(ipaddress.ip_network(text, strict=False))
                        continue
                    except ValueError:
                        pass
                c = classify(text)
                if c:
                    self.exact.add(c[1])

    def lookup(self, indicator: str, kind: str):
        hit = indicator in self.exact
        if not hit and kind == "ip":
            addr = ipaddress.ip_address(indicator)
            hit = any(addr in net for net in self.networks)
        if hit:
            return self._result(indicator, kind, "malicious", 100, "presente na sua lista de bloqueio", source="local")
        return self._result(indicator, kind, "unknown", 0, "não consta na sua lista de bloqueio")
