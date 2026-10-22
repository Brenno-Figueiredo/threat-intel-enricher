"""Leitura de indicadores a partir de arquivos: texto simples ou JSONL dos seus outros projetos."""
from __future__ import annotations

import json
from collections import Counter
from typing import Dict

from .indicators import classify, extract_from_line

IP_KEYS = ("ip", "source_ip", "src_ip", "ip_address", "remote_ip", "client_ip", "source")
HASH_KEYS = ("sha256", "sha1", "md5", "hash", "file_hash")
DOMAIN_KEYS = ("domain", "host", "hostname")


def collect(path: str) -> Dict[str, int]:
    """Devolve {indicador: quantas vezes apareceu}. Aceita .txt, .csv, .json e .jsonl."""
    counts: Counter = Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if path.lower().endswith((".jsonl", ".json")):
        _from_json(text, counts)
    else:
        _from_text(text, counts)
    return dict(counts.most_common())


def _from_text(text: str, counts: Counter) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        first = line.replace(",", " ").split()[0]
        parsed = classify(first)
        if parsed and len(line.split()) == 1:
            counts[parsed[1]] += 1          # a linha inteira é um indicador (inclui domínios)
            continue
        for _, value in extract_from_line(line):
            counts[value] += 1


def _from_json(text: str, counts: Counter) -> None:
    records = []
    stripped = text.strip()
    if stripped.startswith("["):
        records = json.loads(stripped)
    else:
        for line in text.splitlines():
            if line.strip():
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    for rec in records:
        if isinstance(rec, dict):
            _from_record(rec, counts)


def _from_record(rec: dict, counts: Counter) -> None:
    for key in IP_KEYS + HASH_KEYS + DOMAIN_KEYS:
        value = rec.get(key)
        if isinstance(value, str):
            parsed = classify(value.split(" ")[0])
            if parsed:
                counts[parsed[1]] += 1
