# ThreatLens

Enriquecimento de **indicadores de ameaça** (IPs, domínios e hashes de arquivos) em Python, **sem dependências
externas**. Você entrega uma lista de indicadores, e o ThreatLens consulta serviços de reputação
([AbuseIPDB](https://www.abuseipdb.com) e [VirusTotal](https://www.virustotal.com)), combina as respostas em uma
**nota de risco de 0 a 100** e explica por quê.

Quando um honeypot ou um detector de login captura o IP `203.0.113.50`, a pergunta seguinte é sempre a mesma:
*esse endereço já é conhecido por atacar alguém?* Esse passo é o **enriquecimento**, e é o que este projeto automatiza.

```
 indicadores            ThreatLens                                     saídas
┌───────────┐   ┌──────────────────────────────────────────┐   ┌────────────────────┐
│ .txt .csv │   │ validar → cache → cota → provedores → nota│   │ tabela no terminal │
│ .json(l)  │──▶│  (IPs privados nunca saem da sua máquina) │──▶│ JSON · CSV · HTML  │
│ honeypot  │   │  AbuseIPDB · VirusTotal · lista local     │   │ feed p/ Venator    │
└───────────┘   └──────────────────────────────────────────┘   └────────────────────┘
```

## Como rodar

Requisito: Python 3.9+. Nada para instalar.

### 1. Modo demonstração (não precisa de chave nem de internet)
```bash
python app.py lookup 203.0.113.50 8.8.8.8 evil[.]example --demo
python app.py batch samples/sshoney-sessions.jsonl --demo --html relatorio.html
```
Os dados do modo `--demo` são **simulados** e vêm marcados com `[DEMO]`. Servem para conhecer a ferramenta.

### 2. Com dados reais
Crie chaves gratuitas (conta Community/Free) e copie o modelo de configuração:

- AbuseIPDB: https://www.abuseipdb.com/account/api
- VirusTotal: https://www.virustotal.com/gui/my-apikey

```bash
copy .env.example .env        # no Windows (no Linux/macOS: cp)
```
Abra o `.env` e cole as chaves. Depois:
```bash
python app.py config                                  # confere o que está configurado (sem mostrar chaves)
python app.py lookup 8.8.8.8 evil[.]com
python app.py batch /caminho/sessions.jsonl --html relatorio.html --feed feed.jsonl
```

### Com a lista de bloqueio local (funciona offline)
```bash
python app.py lookup 203.0.113.77 --blocklist samples/blocklist.txt
```

## Entradas aceitas

| Formato | Exemplo |
|---|---|
| texto (`.txt`, `.csv`) | um indicador por linha, com `# comentários`; também acha IPs e hashes no meio do texto |
| `.jsonl` / `.json` | os arquivos dos seus outros projetos: `ip`, `source_ip`, `source`, `sha256`, `md5`, `domain`... |
| formato "defanged" | `1[.]2[.]3[.]4`, `evil[.]com`, `hxxp://evil[.]com/x` (como aparece em relatórios de segurança) |

Cada indicador é contado: o IP que atacou 10 vezes aparece como `10x` e sobe no ranking.

## Opções

| Opção | Descrição |
|---|---|
| `--demo` | dados simulados, sem internet |
| `--blocklist ARQ` | lista local de bloqueio (aceita faixas CIDR) |
| `--providers a,b` | limita os provedores (`abuseipdb`, `virustotal`, `blocklist`) |
| `--no-cache` | ignora o cache (gasta cota) |
| `--ttl HORAS` | validade do cache (padrão 24) |
| `--min-score N` / `--top N` | filtra a saída |
| `--json` `--csv` `--html` | salva o resultado |
| `--feed ARQ.jsonl` | gera eventos para o **Venator** e o **CorrelAI** (só suspeitos e maliciosos) |

Comandos extras: `python app.py cache` mostra o cache e as consultas gastas hoje; `cache --clear` apaga.
O programa termina com código `1` se achar algo malicioso, o que permite usá-lo em scripts.

## Como a nota é calculada

1. Cada provedor devolve uma nota de 0 a 100:
   - **AbuseIPDB**: a própria "confiança de abuso" (≥ 75 malicioso, ≥ 25 suspeito); IPs em lista de confiança saem como limpos.
   - **VirusTotal**: 10 pontos por motor antivírus que acusa e 5 por motor que suspeita (10 motores acusando = 100).
   - **Lista local**: presença = 100.
2. A nota final é a **mais alta** entre os provedores. Basta uma fonte confiável acusar para o indicador merecer atenção.
3. **Consenso**: se 2 ou mais fontes sinalizam, soma-se 10 pontos.
4. Provedores sem dados ou com erro **não puxam** a nota para baixo.
5. Veredito: ≥ 75 malicioso · ≥ 40 suspeito · abaixo disso, limpo.

## Cotas e cache

As APIs gratuitas têm limites, e o ThreatLens os respeita sozinho:

| Serviço | Limite gratuito (confira nos sites oficiais, eles mudam) |
|---|---|
| AbuseIPDB | 1.000 consultas por dia |
| VirusTotal (API pública) | 4 por minuto e 500 por dia; **proibido em uso comercial** |

- **Cache em SQLite** (24 h por padrão): o mesmo indicador não gasta consulta duas vezes.
- **Limite por minuto**: no VirusTotal ele espera sozinho (e avisa) em vez de tomar erro.
- **Cota diária**: a contagem fica salva no banco e sobrevive entre execuções. Se acabar ou se a API
  responder 429, aquele provedor é pausado, e os outros continuam.

## Segurança e privacidade

- **Chaves só no ambiente** (`.env` ou variáveis do sistema). Nunca vão na linha de comando, no cache, em mensagens
  de erro ou no GitHub: o `.gitignore` bloqueia o `.env` (só o `.env.example`, sem segredos, é versionado).
  Há testes que garantem que a chave não vaza nas mensagens de erro nem no comando `config`.
- **IPs privados e reservados** (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`...) **nunca são enviados** a serviços de
  terceiros. Eles revelariam a estrutura da sua rede e não têm reputação pública.
- **Toda entrada é validada** antes de virar parte de uma URL, o que impede injeção de caminho ou parâmetros.
- Os relatórios HTML escapam todo dado de terceiros, e o CSV neutraliza fórmulas (`=`, `+`, `-`, `@`).
- Ao consultar um serviço externo, você **informa a ele** qual indicador está investigando. Não consulte
  indicadores que sejam sensíveis para a sua organização.
- **Reputação não é prova.** Um IP pode ser compartilhado, reaproveitado ou ter sido denunciado por engano. Use a
  nota para priorizar a investigação, não como veredito final.
- Respeite os termos de uso de cada serviço. O ThreatLens é um projeto de estudo e uso pessoal.

## Integração com o resto da série

O `--feed` gera eventos no formato genérico que os outros projetos já entendem:
```bash
python app.py batch /caminho/sessions.jsonl --feed feed.jsonl
python app.py import feed.jsonl                       # no Venator
python app.py run feed.jsonl sessions.jsonl           # no CorrelAI
```
Assim, o IP que o honeypot capturou aparece nos outros painéis já com a nota de reputação.

## Estrutura

```
app.py                    ponto de entrada
.env.example              modelo de configuração (sem segredos)
threatlens/
  indicators.py           identifica e valida IP/domínio/hash; refang; IPs públicos
  providers/              abuseipdb · virustotal · blocklist · demo
  enricher.py             orquestra: valida → cache → cota → consulta → combina
  cache.py                SQLite: cache com validade + contagem de uso diário
  ratelimit.py            limite por minuto (janela deslizante) e diário
  scoring.py              combina os provedores em uma nota e um veredito
  inputs.py               lê .txt/.csv/.json/.jsonl
  report.py               tabela, JSON, CSV, HTML e feed
  http.py                 transporte HTTP (substituível nos testes)
  cli.py                  linha de comando
samples/                  indicadores, sessões de honeypot e lista de bloqueio de exemplo
tests/                    35 testes automatizados (sem internet)
```

## Testes

```bash
python -m unittest discover -s tests -v
```
Os testes usam um **transporte HTTP falso**: exercitam os provedores, o cache, as cotas e os erros (401, 404,
429, 500) sem acessar a internet e sem gastar nenhuma consulta.

## Limitações

- Os leitores das respostas do AbuseIPDB e do VirusTotal foram escritos a partir da documentação oficial e
  testados com respostas de exemplo. Na primeira execução real, confira com um IP que você conhece (como `8.8.8.8`).
- Só consulta o que cada serviço oferece de graça: não envia arquivos nem URLs completas, só reputação.
- Um IP novo, que ninguém denunciou ainda, aparece como "limpo". Ausência de denúncias não é garantia.

## Ideias para evoluir

- Mais fontes (AlienVault OTX, GreyNoise), consultando-as em paralelo
- Um conector nativo no Venator, em vez de passar por arquivo
- Painel web (por exemplo, em Angular) consumindo uma API do ThreatLens

## Projetos da série

[network-scanner](https://github.com/Brenno-Figueiredo/network-scanner) ·
[logwatch](https://github.com/Brenno-Figueiredo/logwatch) ·
[loginguard](https://github.com/Brenno-Figueiredo/loginguard) ·
[web-vuln-scanner](https://github.com/Brenno-Figueiredo/web-vuln-scanner) ·
[ssh-honeypot](https://github.com/Brenno-Figueiredo/ssh-honeypot) ·
[security-event-correlator](https://github.com/Brenno-Figueiredo/security-event-correlator) ·
[malware-static-analyzer](https://github.com/Brenno-Figueiredo/malware-static-analyzer) ·
[phishguard](https://github.com/Brenno-Figueiredo/phishguard) ·
[phishguard-ui](https://github.com/Brenno-Figueiredo/phishguard-ui)
