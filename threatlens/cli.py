"""Linha de comando do ThreatLens."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, report
from .cache import Store
from .enricher import Enricher
from .indicators import classify
from .inputs import collect
from .providers import NoProvidersError, build_providers, configured, load_env_file

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--demo", action="store_true", help="usa dados SIMULADOS (não acessa a internet nem precisa de chave)")
    p.add_argument("--blocklist", metavar="ARQUIVO", help="lista de bloqueio local (um indicador por linha)")
    p.add_argument("--providers", metavar="LISTA", help="restringe os provedores, ex: abuseipdb,virustotal")
    p.add_argument("--no-cache", action="store_true", help="ignora o cache (gasta cota)")
    p.add_argument("--ttl", type=float, default=24, metavar="HORAS", help="validade do cache (padrão: 24)")
    p.add_argument("--min-score", type=int, default=0, metavar="N", help="mostra só indicadores com nota >= N")
    p.add_argument("--top", type=int, metavar="N", help="mostra só os N de maior nota")
    p.add_argument("--json", metavar="ARQ.json", help="salva o resultado em JSON")
    p.add_argument("--csv", metavar="ARQ.csv", help="salva o resultado em CSV")
    p.add_argument("--html", metavar="ARQ.html", help="gera um relatório HTML")
    p.add_argument("--feed", metavar="ARQ.jsonl", help="gera eventos para o Venator/CorrelAI (apenas suspeitos e maliciosos)")
    p.add_argument("--db", default=os.path.join(BASE, "threatlens-cache.db"), help="arquivo do cache")
    p.add_argument("--env", default=os.path.join(BASE, ".env"), help="arquivo .env com as chaves de API")
    p.add_argument("--quiet", action="store_true", help="não mostra o progresso")
    p.add_argument("--no-color", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="threatlens", description="Enriquece IPs, domínios e hashes com reputação de AbuseIPDB e VirusTotal.",
        epilog="As chaves de API vêm do ambiente (ABUSEIPDB_API_KEY, VT_API_KEY) ou do .env, nunca da linha de comando.")
    sub = ap.add_subparsers(dest="cmd")

    lk = sub.add_parser("lookup", help="consulta um ou mais indicadores")
    lk.add_argument("values", nargs="+", help="IP, domínio ou hash (aceita formato 1[.]2[.]3[.]4)")
    _common(lk)

    bt = sub.add_parser("batch", help="enriquece todos os indicadores de um arquivo (.txt, .csv, .json, .jsonl)")
    bt.add_argument("file")
    _common(bt)

    sub.add_parser("config", help="mostra quais provedores estão configurados (sem exibir chaves)").add_argument(
        "--env", default=os.path.join(BASE, ".env"))

    ch = sub.add_parser("cache", help="estatísticas do cache e da cota de hoje")
    ch.add_argument("--db", default=os.path.join(BASE, "threatlens-cache.db"))
    ch.add_argument("--clear", action="store_true", help="apaga o cache")

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def cmd_config(args) -> int:
    env = load_env_file(args.env)
    keys = configured(env)
    print("Provedores:")
    print(f"  AbuseIPDB   {'configurado' if keys['abuseipdb'] else 'sem chave (defina ABUSEIPDB_API_KEY)'}")
    print(f"  VirusTotal  {'configurado' if keys['virustotal'] else 'sem chave (defina VT_API_KEY)'}")
    print(f"\nArquivo .env: {'encontrado' if os.path.isfile(args.env) else 'não encontrado'} ({args.env})")
    print("As chaves nunca são exibidas nem gravadas no cache.")
    return 0


def cmd_cache(args) -> int:
    store = Store(args.db)
    if args.clear:
        store.clear()
        print("Cache apagado.")
    s = store.stats()
    print(f"Entradas no cache: {s['entries']}")
    for name, n in s["by_provider"].items():
        print(f"  {name}: {n}")
    print("Consultas gastas hoje (UTC): " + (", ".join(f"{k}={v}" for k, v in s["used_today"].items()) or "nenhuma"))
    return 0


def cmd_enrich(args) -> int:
    if args.cmd == "lookup":
        counts = {v: 1 for v in args.values}
        bad = [v for v in args.values if not classify(v)]
        if len(bad) == len(args.values):
            print("Nenhum indicador válido. Use um IP, um domínio ou um hash (MD5, SHA-1 ou SHA-256).", file=sys.stderr)
            return 2
    else:
        try:
            counts = collect(args.file)
        except OSError as exc:
            print(f"Erro ao ler {args.file}: {exc}", file=sys.stderr)
            return 2
        if not counts:
            print("Nenhum indicador encontrado no arquivo.", file=sys.stderr)
            return 2

    store = Store(args.db)
    log = (lambda m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))
    wait = lambda name, secs: log(f"aguardando {secs:.0f}s: limite por minuto do {name}")  # noqa: E731
    env = load_env_file(args.env)
    try:
        only = args.providers.split(",") if args.providers else None
        providers = build_providers(env, store, args.demo, args.blocklist, only, on_wait=wait)
    except NoProvidersError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    if args.demo:
        print("MODO DEMONSTRAÇÃO: os dados abaixo são simulados.\n")
    external = [p.name for p in providers if p.external]
    if external:
        print(f"Consultando {', '.join(external)}. Apenas IPs públicos, domínios e hashes são enviados.\n")

    enricher = Enricher(providers, store, args.ttl, not args.no_cache, log)
    try:
        items = enricher.enrich(counts)
    except KeyboardInterrupt:
        print("\nInterrompido.", file=sys.stderr)
        return 130
    items.sort(key=lambda i: (-i.score, -i.seen))
    shown = [i for i in items if i.score >= args.min_score]
    if args.top:
        shown = shown[:args.top]

    print(report.render_table(shown, color=not args.no_color and sys.stdout.isatty()))
    detail = report.print_explanations(shown)
    if detail:
        print(detail)
    s = enricher.stats
    print(f"\n{len(items)} indicador(es): {s['queries']} consulta(s) feita(s), {s['cache_hits']} do cache, {s['errors']} erro(s).")
    if enricher.disabled:
        print(f"Cota esgotada em: {', '.join(sorted(enricher.disabled))}. Rode de novo amanhã (UTC) ou use o cache.")
    for it in items:
        for r in it.results:
            if r.error:
                print(f"Aviso ({r.provider}, {it.indicator}): {r.error}", file=sys.stderr)
                break

    _write(args, items)
    return 1 if any(i.verdict == "malicious" for i in items) else 0


def _write(args, items) -> None:
    import json
    outputs = ((args.json, report.to_json), (args.csv, report.to_csv), (args.html, report.to_html))
    for path, fn in outputs:
        if path:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(fn(items))
            print(f"Salvo em: {path}")
    if args.feed:
        events = report.to_events(items, max(args.min_score, 40))
        with open(args.feed, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"{len(events)} evento(s) para o Venator/CorrelAI salvos em: {args.feed}")


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return {"config": cmd_config, "cache": cmd_cache, "lookup": cmd_enrich, "batch": cmd_enrich}[args.cmd](args)
