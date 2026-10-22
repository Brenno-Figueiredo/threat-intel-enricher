#!/usr/bin/env python3
"""ThreatLens - enriquecimento de indicadores de ameaça.
Exemplos:
    python app.py lookup 203.0.113.50 --demo
    python app.py batch samples/sshoney-sessions.jsonl --demo --html relatorio.html
    python app.py lookup 8.8.8.8 evil[.]com        (com chaves no .env)
"""
import sys

from threatlens.cli import main

if __name__ == "__main__":
    sys.exit(main())
