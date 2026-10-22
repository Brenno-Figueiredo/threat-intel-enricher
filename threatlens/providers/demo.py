"""Provedor de DEMONSTRAÇÃO: dados simulados e determinísticos. Não acessa a internet nem precisa de chave."""
from __future__ import annotations

import hashlib
import ipaddress

from ..indicators import is_global_ip
from .base import Provider

# Faixas reservadas para documentação (RFC 5737): nunca são IPs reais, então servem de exemplo seguro.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# Casos "plantados" que combinam com os projetos de exemplo da série (honeypot, LoginGuard, LogWatch).
KNOWN = {
    "203.0.113.50": (96, "malicious", "botnet de força bruta SSH, 1.480 denúncias", "CN", "Example Hosting"),
    "185.220.101.4": (100, "malicious", "nó de saída Tor com abuso recorrente", "DE", "Example Tor Relay"),
    "45.155.205.9": (88, "malicious", "scanner de vulnerabilidades web (Nikto)", "RU", "Example Cloud"),
    "91.240.118.172": (82, "malicious", "tentativas de SQL injection", "UA", "Example Networks"),
    "198.51.100.7": (55, "suspicious", "password spraying, 41 denúncias", "NL", "Example VPS"),
    "198.51.100.23": (48, "suspicious", "acessos SSH anômalos", "US", "Example Cloud"),
    "192.0.2.44": (45, "suspicious", "enumeração de usuários", "BR", "Example Telecom"),
    "8.8.8.8": (0, "clean", "DNS público do Google, em lista de confiança", "US", "Google LLC"),
    "1.1.1.1": (0, "clean", "DNS público da Cloudflare, em lista de confiança", "AU", "Cloudflare"),
    "evil.example": (94, "malicious", "domínio de comando e controle (C2)", None, None),
    "44d88612fea8a8f36de82e1278abb02f": (100, "malicious", "arquivo de teste EICAR (inofensivo, usado para testar antivírus)", None, None),
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": (100, "malicious", "arquivo de teste EICAR (inofensivo, usado para testar antivírus)", None, None),
}


class DemoProvider(Provider):
    name = "demo"
    external = False
    kinds = ("ip", "domain", "md5", "sha1", "sha256")

    def accepts_ip(self, ip: str) -> bool:
        # IPs internos (192.168.x.x, 10.x.x.x...) não têm reputação pública, nem simulada
        return is_global_ip(ip) or any(ipaddress.ip_address(ip) in net for net in DOC_NETS)

    def lookup(self, indicator: str, kind: str):
        if indicator in KNOWN:
            score, verdict, text, country, isp = KNOWN[indicator]
        else:
            # indicador desconhecido: resultado estável, calculado a partir do hash do próprio texto
            bucket = int(hashlib.sha256(indicator.encode()).hexdigest()[:8], 16) % 100
            if bucket < 70:
                score, verdict, text = bucket % 8, "clean", "sem relatos de abuso"
            elif bucket < 90:
                score, verdict, text = 40 + bucket % 20, "suspicious", "poucos relatos de abuso"
            else:
                score, verdict, text = 76 + bucket % 20, "malicious", "muitos relatos de abuso"
            country, isp = None, None
        return self._result(indicator, kind, verdict, score, f"[DEMO] {text}",
                            simulated=True, country=country, isp=isp)
