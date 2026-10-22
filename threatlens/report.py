"""Saídas: tabela no terminal, JSON, CSV, relatório HTML e feed de eventos para o Venator/CorrelAI."""
from __future__ import annotations

import csv
import html
import io
import json
import time
from datetime import datetime
from typing import List

from .models import VERDICT_LABEL, Enrichment

ANSI = {"malicious": "\033[1;97;41m", "suspicious": "\033[1;33m", "clean": "\033[32m",
        "unknown": "\033[2m", "ignored": "\033[2m", "invalid": "\033[2m", "reset": "\033[0m", "bold": "\033[1m"}


def _detail(item: Enrichment) -> str:
    """Junta o que há de mais útil dos provedores (país, provedor de internet, rótulo da ameaça)."""
    bits = []
    for r in item.results:
        d = r.details
        for key in ("country", "isp", "as_owner", "threat_label", "file_name"):
            if d.get(key) and str(d[key]) not in bits:
                bits.append(str(d[key]))
    if not bits and not item.results and item.skipped:
        return "privado/reservado: não consultado"
    return " | ".join(bits[:3])


def render_table(items: List[Enrichment], color: bool = True) -> str:
    def paint(text, key):
        return f"{ANSI[key]}{text}{ANSI['reset']}" if color else text

    lines = [f"{'INDICADOR':<44}{'TIPO':<8}{'NOTA':>5}  {'VEREDITO':<11}{'VISTO':>5}  DETALHES",
             "-" * 110]
    for it in items:
        label = f"{VERDICT_LABEL.get(it.verdict, it.verdict):<11}"
        lines.append(f"{it.indicator[:43]:<44}{it.kind:<8}{it.score:>5}  {paint(label, it.verdict)}"
                     f"{it.seen:>5}x  {_detail(it)}")
    return "\n".join(lines)


def print_explanations(items: List[Enrichment]) -> str:
    out = []
    for it in items:
        if it.verdict in ("malicious", "suspicious"):
            out.append(f"\n{it.indicator} ({VERDICT_LABEL[it.verdict].lower()}, nota {it.score})")
            out += [f"  - {r}" for r in it.reasons]
    return "\n".join(out)


def to_json(items: List[Enrichment]) -> str:
    return json.dumps({"generated_at": datetime.now().isoformat(timespec="seconds"),
                       "items": [i.to_dict() for i in items]}, ensure_ascii=False, indent=2)


def to_csv(items: List[Enrichment]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicador", "tipo", "nota", "veredito", "visto", "detalhes"])
    for it in items:
        # evita injeção de fórmula ao abrir no Excel
        safe = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in "=+-@" else v  # noqa: E731
        w.writerow([safe(it.indicator), it.kind, it.score, it.verdict, it.seen, safe(_detail(it))])
    return buf.getvalue()


def to_events(items: List[Enrichment], min_score: int = 40) -> List[dict]:
    """Eventos no formato genérico que o Venator e o CorrelAI já entendem (type, severity, ip, message)."""
    now = time.time()
    events = []
    for it in items:
        if it.score < min_score or it.verdict not in ("malicious", "suspicious"):
            continue
        events.append({
            "ts": now, "source": "threatlens", "type": "generic",
            "severity": "high" if it.verdict == "malicious" else "medium",
            "ip": it.indicator if it.kind == "ip" else "",
            "message": f"Inteligência de ameaças: {it.kind} {it.indicator} {VERDICT_LABEL[it.verdict].lower()} "
                       f"(nota {it.score}). {it.reasons[0] if it.reasons else ''}".strip(),
        })
    return events


CSS = """
:root{color-scheme:dark;--bg:#0c1219;--panel:#141e29;--line:#25364a;--text:#e5edf4;--muted:#8aa0b3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:30px 22px 70px}h1{margin:0;font-size:26px}.sub{color:var(--muted);margin:4px 0 0}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}.card{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:30px;line-height:1.1}.card span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th{text-align:left;color:var(--muted);font-weight:500;padding:10px;border-bottom:1px solid var(--line)}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;word-break:break-all}
.bar{height:6px;background:#0b141d;border-radius:3px;margin-top:5px;overflow:hidden}.bar b{display:block;height:100%}
.badge{font-size:11.5px;font-weight:700;border-radius:999px;padding:1px 10px;color:#08121a}.muted{color:var(--muted);font-size:12.5px}
.note{color:var(--muted);font-size:12.5px;margin-top:26px;border-top:1px solid var(--line);padding-top:14px}
"""
COLOR = {"malicious": "#ff5c7a", "suspicious": "#f2b13b", "clean": "#3ddc84", "unknown": "#8aa0b3",
         "ignored": "#8aa0b3", "invalid": "#8aa0b3"}


def to_html(items: List[Enrichment]) -> str:
    count = lambda v: sum(1 for i in items if i.verdict == v)  # noqa: E731
    rows = []
    for it in items:
        col = COLOR.get(it.verdict, "#8aa0b3")
        why = "<br>".join(html.escape(r) for r in (it.reasons or it.skipped)[:4])
        rows.append(
            f'<tr><td class="mono">{html.escape(it.indicator)}<div class="muted">{html.escape(it.kind)}</div></td>'
            f'<td><b>{it.score}</b><div class="bar"><b style="width:{it.score}%;background:{col}"></b></div></td>'
            f'<td><span class="badge" style="background:{col}">{html.escape(VERDICT_LABEL.get(it.verdict, it.verdict))}</span></td>'
            f'<td>{it.seen}x</td><td class="muted">{html.escape(_detail(it))}<br>{why}</td></tr>')
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ThreatLens - relatório</title>
<style>{CSS}</style></head><body><main>
<h1>ThreatLens</h1><p class="sub">Relatório de enriquecimento de indicadores · {datetime.now():%d/%m/%Y %H:%M}</p>
<div class="cards"><div class="card"><b>{len(items)}</b><span>Indicadores</span></div>
<div class="card"><b style="color:#ff5c7a">{count("malicious")}</b><span>Maliciosos</span></div>
<div class="card"><b style="color:#f2b13b">{count("suspicious")}</b><span>Suspeitos</span></div>
<div class="card"><b style="color:#3ddc84">{count("clean")}</b><span>Limpos</span></div></div>
<table><thead><tr><th>Indicador</th><th>Nota</th><th>Veredito</th><th>Visto</th><th>Detalhes</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<p class="note">Reputação não é prova: um IP pode ser compartilhado ou ter sido reaproveitado. Use a nota para priorizar a
investigação, não como veredito final. Dados de terceiros (AbuseIPDB, VirusTotal) conforme os termos de cada serviço.</p>
</main></body></html>"""
