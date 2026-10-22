import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatlens import report  # noqa: E402
from threatlens.cache import Store  # noqa: E402
from threatlens.cli import main  # noqa: E402
from threatlens.enricher import Enricher  # noqa: E402
from threatlens.indicators import classify, extract_from_line, is_global_ip  # noqa: E402
from threatlens.inputs import collect  # noqa: E402
from threatlens.models import ProviderResult  # noqa: E402
from threatlens.providers.abuseipdb import AbuseIPDB  # noqa: E402
from threatlens.providers.blocklist import Blocklist  # noqa: E402
from threatlens.providers.demo import DemoProvider  # noqa: E402
from threatlens.providers.virustotal import VirusTotal  # noqa: E402
from threatlens.ratelimit import ProviderError, QuotaExceeded, RateLimiter  # noqa: E402
from threatlens.scoring import combine  # noqa: E402

ABUSE_OK = {"data": {"ipAddress": "118.25.6.39", "isPublic": True, "isWhitelisted": False,
                     "abuseConfidenceScore": 100, "countryCode": "CN", "isp": "Example ISP",
                     "usageType": "Data Center", "domain": "example.com", "totalReports": 1,
                     "numDistinctUsers": 1, "lastReportedAt": "2026-10-01T10:00:00+00:00"}}


class FakeTransport:
    """Troca a internet: devolve respostas prontas e registra cada chamada."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers, timeout):
        self.calls.append((url, headers))
        for fragment, (status, body) in self.routes.items():
            if fragment in url:
                return status, {}, json.dumps(body).encode()
        return 404, {}, b"{}"


def vt_body(malicious=0, suspicious=0, harmless=60, **attrs):
    stats = {"harmless": harmless, "malicious": malicious, "suspicious": suspicious, "undetected": 10, "timeout": 0}
    return {"data": {"attributes": {"last_analysis_stats": stats, **attrs}}}


class FakeClock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class IndicatorTests(unittest.TestCase):
    def test_classify_kinds(self):
        self.assertEqual(classify("8.8.8.8"), ("ip", "8.8.8.8"))
        self.assertEqual(classify("2001:4860:4860::8888")[0], "ip")
        self.assertEqual(classify("Example.COM"), ("domain", "example.com"))
        self.assertEqual(classify("44D88612FEA8A8F36DE82E1278ABB02F")[0], "md5")
        self.assertEqual(classify("a" * 40)[0], "sha1")
        self.assertEqual(classify("b" * 64)[0], "sha256")

    def test_defanged_and_url(self):
        self.assertEqual(classify("1[.]2[.]3[.]4"), ("ip", "1.2.3.4"))
        self.assertEqual(classify("hxxp://evil[.]com/payload.exe"), ("domain", "evil.com"))
        self.assertEqual(classify("https://203.0.113.9:8080/x"), ("ip", "203.0.113.9"))

    def test_rejects_garbage_and_injection(self):
        for bad in ("", "não é nada", "../../etc/passwd", "evil.com/../x?y=1;rm", "999.1.1.1", "x" * 3000):
            self.assertIsNone(classify(bad), bad)

    def test_global_ip(self):
        self.assertTrue(is_global_ip("8.8.8.8"))
        for ip in ("192.168.0.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "203.0.113.5"):
            self.assertFalse(is_global_ip(ip), ip)

    def test_extract_from_line_ignores_fake_domains(self):
        found = extract_from_line("falha de login de 1.2.3.4 abrindo relatorio.pdf hash " + "c" * 32)
        self.assertEqual({k for k, _ in found}, {"ip", "md5"})


class StoreAndLimiterTests(unittest.TestCase):
    def test_cache_respects_ttl(self):
        clock = FakeClock()
        store = Store(":memory:", clock)
        store.put(ProviderResult("abuseipdb", "1.2.3.4", "ip", "clean", 0, "ok"))
        hit = store.get("abuseipdb", "ip", "1.2.3.4", ttl=3600)
        self.assertTrue(hit and hit.cached)
        clock.t += 7200
        self.assertIsNone(store.get("abuseipdb", "ip", "1.2.3.4", ttl=3600))

    def test_daily_quota_persists_and_resets(self):
        clock = FakeClock()
        store = Store(":memory:", clock)
        limiter = RateLimiter("vt", store, per_day=2, clock=clock, sleep=clock.sleep)
        limiter.acquire()
        limiter.acquire()
        with self.assertRaises(QuotaExceeded):
            limiter.acquire()
        clock.t += 86400  # no dia seguinte (UTC) a cota volta
        limiter.acquire()
        self.assertEqual(store.used_today("vt"), 1)

    def test_per_minute_limit_waits(self):
        clock = FakeClock()
        waits = []
        limiter = RateLimiter("vt", Store(":memory:", clock), per_minute=2, clock=clock, sleep=clock.sleep,
                              on_wait=lambda name, s: waits.append(s))
        for _ in range(3):
            limiter.acquire()
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 50)


class ProviderTests(unittest.TestCase):
    def test_abuseipdb_malicious(self):
        t = FakeTransport({"abuseipdb": (200, ABUSE_OK)})
        r = AbuseIPDB("SEGREDO", transport=t).lookup("118.25.6.39", "ip")
        self.assertEqual((r.verdict, r.score), ("malicious", 100))
        self.assertEqual(r.details["country"], "CN")
        url, headers = t.calls[0]
        self.assertIn("ipAddress=118.25.6.39", url)
        self.assertEqual(headers["Key"], "SEGREDO")

    def test_abuseipdb_thresholds_and_whitelist(self):
        def check(score, white=False):
            body = {"data": {**ABUSE_OK["data"], "abuseConfidenceScore": score, "isWhitelisted": white}}
            return AbuseIPDB("k", transport=FakeTransport({"abuseipdb": (200, body)})).lookup("8.8.8.8", "ip").verdict
        self.assertEqual(check(30), "suspicious")
        self.assertEqual(check(5), "clean")
        self.assertEqual(check(90, white=True), "clean")

    def test_abuseipdb_errors_never_leak_the_key(self):
        key = "CHAVE-ULTRA-SECRETA"
        with self.assertRaises(QuotaExceeded):
            AbuseIPDB(key, transport=FakeTransport({"abuseipdb": (429, {})})).lookup("8.8.8.8", "ip")
        with self.assertRaises(ProviderError) as ctx:
            AbuseIPDB(key, transport=FakeTransport({"abuseipdb": (401, {})})).lookup("8.8.8.8", "ip")
        self.assertNotIn(key, str(ctx.exception))

    def test_virustotal_ip_domain_and_file(self):
        t = FakeTransport({
            "ip_addresses": (200, vt_body(malicious=7, suspicious=2, country="CN", as_owner="AS Example")),
            "domains": (200, vt_body(malicious=0)),
            "files/44d88612": (200, vt_body(malicious=60, meaningful_name="eicar.com", type_description="text",
                                            popular_threat_classification={"suggested_threat_label": "virus.eicar"})),
        })
        vt = VirusTotal("k", transport=t)
        ip = vt.lookup("203.0.113.9", "ip")
        self.assertEqual((ip.verdict, ip.score), ("malicious", 80))
        self.assertEqual(vt.lookup("example.com", "domain").verdict, "clean")
        f = vt.lookup("44d88612fea8a8f36de82e1278abb02f", "md5")
        self.assertEqual((f.verdict, f.score, f.details["threat_label"]), ("malicious", 100, "virus.eicar"))
        self.assertTrue(all(h["x-apikey"] == "k" for _, h in t.calls))

    def test_virustotal_not_found_and_quota(self):
        vt = VirusTotal("k", transport=FakeTransport({}))
        self.assertEqual(vt.lookup("a" * 64, "sha256").verdict, "unknown")
        with self.assertRaises(QuotaExceeded):
            VirusTotal("k", transport=FakeTransport({"files": (429, {})})).lookup("a" * 64, "sha256")

    def test_blocklist_exact_cidr_and_comments(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bl.txt")
            with open(path, "w") as f:
                f.write("# lista\n203.0.113.0/24\nevil.example  # c2\n" + "d" * 32 + "\n\n")
            bl = Blocklist(path)
            self.assertEqual(bl.lookup("203.0.113.77", "ip").verdict, "malicious")
            self.assertEqual(bl.lookup("evil.example", "domain").verdict, "malicious")
            self.assertEqual(bl.lookup("d" * 32, "md5").verdict, "malicious")
            self.assertEqual(bl.lookup("8.8.8.8", "ip").verdict, "unknown")

    def test_demo_is_deterministic_and_marked(self):
        demo = DemoProvider()
        a, b = demo.lookup("9.9.9.9", "ip"), demo.lookup("9.9.9.9", "ip")
        self.assertEqual((a.verdict, a.score), (b.verdict, b.score))
        self.assertTrue(a.details["simulated"] and a.summary.startswith("[DEMO]"))


class ScoringTests(unittest.TestCase):
    def r(self, provider, verdict, score, error=""):
        return ProviderResult(provider, "x", "ip", verdict, score, "resumo", error=error)

    def test_takes_highest_and_adds_consensus(self):
        score, verdict, reasons = combine([self.r("a", "suspicious", 55), self.r("b", "malicious", 80)])
        self.assertEqual((score, verdict), (90, "malicious"))
        self.assertTrue(any("Consenso" in x for x in reasons))

    def test_errors_and_unknown_do_not_lower_the_score(self):
        score, verdict, _ = combine([self.r("a", "malicious", 80), self.r("b", "unknown", 0),
                                     self.r("c", "unknown", 0, error="falha")])
        self.assertEqual((score, verdict), (80, "malicious"))

    def test_only_unknown_means_unknown(self):
        self.assertEqual(combine([self.r("a", "unknown", 0)])[:2], (0, "unknown"))


class EnricherTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def abuse(self, routes=None, limiter=None):
        t = FakeTransport(routes or {"abuseipdb": (200, ABUSE_OK)})
        return AbuseIPDB("k", transport=t, limiter=limiter), t

    def test_private_ip_is_never_sent_to_external_services(self):
        provider, transport = self.abuse()
        item = Enricher([provider], self.store).enrich(["192.168.0.10", "127.0.0.1"])
        self.assertEqual(transport.calls, [])
        self.assertTrue(all(i.verdict == "ignored" for i in item))

    def test_cache_avoids_a_second_query(self):
        provider, transport = self.abuse()
        enricher = Enricher([provider], self.store)
        enricher.enrich(["118.25.6.39"])
        enricher.enrich(["118.25.6.39"])
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(enricher.stats["cache_hits"], 1)

    def test_no_cache_flag_queries_again(self):
        provider, transport = self.abuse()
        enricher = Enricher([provider], self.store, use_cache=False)
        enricher.enrich(["118.25.6.39"])
        enricher.enrich(["118.25.6.39"])
        self.assertEqual(len(transport.calls), 2)

    def test_quota_exhaustion_stops_that_provider_only(self):
        provider, transport = self.abuse({"abuseipdb": (429, {})})
        blocklist = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        blocklist.write("8.8.4.4\n")
        blocklist.close()
        self.addCleanup(os.unlink, blocklist.name)
        enricher = Enricher([provider, Blocklist(blocklist.name)], self.store)
        items = enricher.enrich(["1.1.1.1", "8.8.4.4", "9.9.9.9"])
        self.assertEqual(len(transport.calls), 1)             # parou de gastar depois do primeiro 429
        self.assertIn("abuseipdb", enricher.disabled)
        self.assertEqual(items[1].verdict, "malicious")       # a lista local continuou funcionando

    def test_provider_error_does_not_crash_the_batch(self):
        provider, _ = self.abuse({"abuseipdb": (500, {})})
        items = Enricher([provider], self.store).enrich(["1.1.1.1", "8.8.8.8"])
        self.assertEqual(len(items), 2)
        self.assertTrue(items[0].results[0].error)
        self.assertEqual(items[0].verdict, "unknown")

    def test_invalid_indicator_is_reported(self):
        item = Enricher([DemoProvider()], self.store).enrich(["isso não é um ioc"])[0]
        self.assertEqual((item.kind, item.verdict), ("invalid", "invalid"))

    def test_limiter_is_used_before_each_query(self):
        limiter = RateLimiter("abuseipdb", self.store, per_day=1)
        provider, transport = self.abuse(limiter=limiter)
        items = Enricher([provider], self.store).enrich(["1.1.1.1", "8.8.8.8"])
        self.assertEqual(len(transport.calls), 1)
        self.assertTrue(any("esgotada" in s for s in items[0].skipped + items[1].skipped))


class InputsTests(unittest.TestCase):
    def write(self, name, text):
        d = tempfile.mkdtemp()
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_text_file_with_comments_and_defanged(self):
        path = self.write("a.txt", "# c\n1.2.3.4\n1[.]2[.]3[.]4  # repetido\nevil[.]com\nlog: falha de 5.6.7.8 em relatorio.pdf\n")
        counts = collect(path)
        self.assertEqual(counts["1.2.3.4"], 2)
        self.assertEqual(counts["evil.com"], 1)
        self.assertEqual(counts["5.6.7.8"], 1)
        self.assertNotIn("relatorio.pdf", counts)

    def test_jsonl_counts_events_per_ip(self):
        rows = [{"event": "login", "ip": "9.9.9.9"}] * 3 + [{"source": "8.8.8.8 (RDP)"}, {"sha256": "e" * 64}, {"x": 1}]
        counts = collect(self.write("s.jsonl", "\n".join(json.dumps(r) for r in rows) + "\nlinha quebrada\n"))
        self.assertEqual(counts["9.9.9.9"], 3)
        self.assertEqual(counts["8.8.8.8"], 1)
        self.assertEqual(counts["e" * 64], 1)


class ReportTests(unittest.TestCase):
    def item(self, isp="Example"):
        enricher = Enricher([DemoProvider()], Store(":memory:"))
        it = enricher.enrich({"203.0.113.50": 3})[0]
        it.results[0].details.update(country=None, isp=isp)   # o primeiro detalhe decide como a célula começa
        return it

    def test_html_escapes_third_party_data(self):
        doc = report.to_html([self.item("<script>alert(1)</script>")])
        self.assertNotIn("<script>alert", doc)
        self.assertIn("&lt;script&gt;", doc)

    def test_csv_neutralizes_formulas(self):
        row = report.to_csv([self.item("=HYPERLINK(\"http://x\")")]).splitlines()[1]
        self.assertIn("'=", row)

    def test_events_for_venator_only_include_threats(self):
        items = Enricher([DemoProvider()], Store(":memory:")).enrich(["203.0.113.50", "8.8.8.8", "198.51.100.7"])
        events = report.to_events(items)
        self.assertEqual({e["ip"] for e in events}, {"203.0.113.50", "198.51.100.7"})
        for e in events:
            self.assertEqual((e["source"], e["type"]), ("threatlens", "generic"))
            self.assertIn(e["severity"], ("high", "medium"))


class CLITests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(argv))
        return code, out.getvalue()

    def test_demo_lookup_exit_code_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = self.run_cli("lookup", "203.0.113.50", "8.8.8.8", "--demo", "--quiet", "--no-color",
                                     "--db", os.path.join(d, "c.db"))
        self.assertEqual(code, 1)  # achou algo malicioso
        self.assertIn("DEMONSTRAÇÃO", out)
        self.assertIn("Malicioso", out)

    def test_invalid_input_returns_2(self):
        self.assertEqual(self.run_cli("lookup", "isso-nao-vale!!")[0], 2)

    def test_no_provider_gives_friendly_error(self):
        with mock.patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as d:
            code, _ = self.run_cli("lookup", "8.8.8.8", "--db", os.path.join(d, "c.db"),
                                   "--env", os.path.join(d, "nao-existe.env"))
        self.assertEqual(code, 2)

    def test_config_never_prints_keys(self):
        with mock.patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "VALOR-SECRETO-123"}, clear=True):
            code, out = self.run_cli("config", "--env", "/nao/existe")
        self.assertEqual(code, 0)
        self.assertIn("configurado", out)
        self.assertNotIn("VALOR-SECRETO-123", out)

    def test_batch_writes_all_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            paths = {k: os.path.join(d, f"o.{k}") for k in ("json", "csv", "html")}
            feed = os.path.join(d, "feed.jsonl")
            code, _ = self.run_cli("batch", os.path.join(base, "samples", "sshoney-sessions.jsonl"), "--demo",
                                   "--quiet", "--db", os.path.join(d, "c.db"), "--json", paths["json"],
                                   "--csv", paths["csv"], "--html", paths["html"], "--feed", feed)
            self.assertEqual(code, 1)
            for p in list(paths.values()) + [feed]:
                self.assertGreater(os.path.getsize(p), 50, p)
            with open(paths["json"], encoding="utf-8") as f:
                self.assertTrue(json.load(f)["items"])


if __name__ == "__main__":
    unittest.main()
