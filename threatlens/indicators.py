"""Identificação e validação de indicadores (IOCs): IP, domínio e hash.

Toda entrada passa por aqui antes de virar parte de uma URL ou de um pedido a um serviço externo.
Aceita indicadores "defanged" (1[.]2[.]3[.]4, hxxp://evil[.]com), como circulam em relatórios de segurança.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[a-f0-9]+$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def refang(value: str) -> str:
    """Desfaz as proteções de links: hxxp -> http, [.] -> ., etc."""
    v = value.strip().strip("<>\"'")
    v = re.sub(r"(?i)^hxxp", "http", v)
    for fake, real in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":")):
        v = v.replace(fake, real)
    return v


def classify(value: str) -> Optional[Tuple[str, str]]:
    """Devolve (tipo, valor normalizado) ou None se não for um indicador válido.

    Tipos: ip, domain, md5, sha1, sha256. Uma URL é reduzida ao seu host.
    """
    if not value or len(value) > 2048:
        return None
    v = refang(value)
    if "://" in v:
        host = urlparse(v).hostname
        if not host:
            return None
        v = host
    try:
        return "ip", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    low = v.lower()
    if len(low) in HASH_KINDS and HEX_RE.match(low):
        return HASH_KINDS[len(low)], low
    if DOMAIN_RE.match(low):
        return "domain", low
    return None


def is_global_ip(ip: str) -> bool:
    """True apenas para IPs públicos e roteáveis. Privados e reservados nunca saem da sua máquina."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def extract_from_line(line: str):
    """Extrai indicadores de uma linha de texto livre (apenas IPs e hashes, para evitar falsos domínios)."""
    found = []
    for m in IPV4_RE.finditer(line):
        c = classify(m.group(0))
        if c and c[0] == "ip":
            found.append(c)
    for m in HASH_RE.finditer(line):
        c = classify(m.group(0))
        if c:
            found.append(c)
    return found
