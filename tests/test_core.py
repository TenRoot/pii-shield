"""Core engine tests:  python -m unittest discover -s tests -v"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402
try:
    from PyQt6 import sip  # noqa: E402
except ImportError:  # pragma: no cover
    sip = None

TEMPLATE_RULES = HERE.parent / "github-repo-template" / "rules"

SAMPLE = (
    "Ticket SEC-10442: John Smith (CORP\\jsmith) reported that SRV-DC01 at 10.20.30.40 "
    "can't reach fs01.contoso.local. Tenant id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301. "
    "AWS key AKIAIOSFODNN7EXAMPLE leaked in C:\\Users\\jsmith\\Desktop\\notes.txt; "
    "password=Sup3rS3cret! Call 054-123-4567. Teudat zehut 123456782. "
    "Again: SRV-DC01 and srv-dc01 talk to localhost. Customer Contoso is affected. "
    "Hash 5d41402abc4b2a76b9719d911017c592 is a file hash."
)


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        rules = cls.tmp / "rules"
        shutil.copytree(TEMPLATE_RULES, rules / "remote")
        (rules / "local").mkdir()
        cls.cfg = ps.AppConfig(cls.tmp / "config.json")
        cls.engine = ps.DetectionEngine(cls.cfg, rules)
        cls.engine.initialize()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def analyze(self, text, manual=(), vault=None):
        vault = vault or ps.SessionVault()
        return self.engine.analyze(text, list(manual), vault), vault

    def by_text(self, findings):
        return {f.text: f for f in findings}

    def test_detections(self):
        fs, _ = self.analyze(SAMPLE)
        d = self.by_text(fs)
        expect = {
            "John Smith": "PERSON", "CORP\\jsmith": "USERNAME", "SRV-DC01": "HOSTNAME",
            "10.20.30.40": "INTERNAL_IP", "fs01.contoso.local": "HOSTNAME",
            "3f2504e0-4f89-11d3-9a0c-0305e82c3301": "TENANT_ID", "AKIAIOSFODNN7EXAMPLE": "SECRET",
            "SEC-10442": "TICKET_ID", "123456782": "IL_ID", "Contoso": "CUSTOMER",
        }
        for text, ent in expect.items():
            self.assertIn(text, d, f"missing {text}")
            self.assertEqual(d[text].entity, ent, text)
        self.assertNotIn("localhost", d, "allow-list must suppress localhost")
        self.assertNotIn("5d41402abc4b2a76b9719d911017c592", d, "plain MD5 must not be flagged")
        self.assertEqual(d["Sup3rS3cret!"].entity, "SECRET", "only the value after password= is masked")
        self.assertTrue(any("054-123-4567" in f.text for f in fs))
        self.assertEqual(d["jsmith"].entity, "USERNAME", "only the user name in C:\\Users\\jsmith is masked")

    def test_skip_ner_argument_drops_ner_findings(self):
        if self.engine.mode != "presidio+spacy":
            self.skipTest("needs a spaCy model")
        fs = self.engine.analyze(SAMPLE, [], ps.SessionVault(), skip_ner=True)
        self.assertFalse([f for f in fs if f.recognizer in ps.NER_RECOGNIZERS])
        self.assertFalse([f for f in fs if f.text == "John Smith"], "no propagated copy of a dropped NER value")
        self.assertTrue([f for f in fs if f.text == "AKIAIOSFODNN7EXAMPLE"], "rules still run")

    def test_propagated_copy_inherits_source_score(self):
        fs, _ = self.analyze(SAMPLE)
        best = {}
        for f in fs:
            if f.source != "propagated":
                k = f.text.casefold()
                best[k] = max(best.get(k, 0.0), f.score)
        props = [f for f in fs if f.source == "propagated"]
        self.assertTrue(props, "SAMPLE has a lower-case srv-dc01 copy")
        for f in props:
            self.assertEqual(f.score, best[f.text.casefold()], f.text)

    def test_consistent_tokens_and_case_insensitive(self):
        fs, _ = self.analyze(SAMPLE)
        toks = {f.token for f in fs if f.text.casefold() == "srv-dc01"}
        self.assertEqual(len(toks), 1)
        self.assertGreaterEqual(sum(1 for f in fs if f.text.casefold() == "srv-dc01"), 3)

    def test_round_trip(self):
        fs, v = self.analyze(SAMPLE)
        out, used = ps.sanitize(SAMPLE, fs, v)
        self.assertNotIn("SRV-DC01", out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertEqual(ps.leak_check(out, v), [])
        self.assertEqual(out, ps.splice(SAMPLE, used))
        restored, n, unknown = v.restore(out)
        # case-insensitive mode restores "srv-dc01" with first-seen casing
        self.assertEqual(restored.replace("SRV-DC01", "srv-dc01").casefold(), SAMPLE.casefold())
        self.assertEqual(n, len(used))
        self.assertEqual(unknown, [])

    def test_disable_creates_leak_warning(self):
        fs, v = self.analyze(SAMPLE)
        target = next(f for f in fs if f.text == "AKIAIOSFODNN7EXAMPLE")
        target.enabled = False
        out, _ = ps.sanitize(SAMPLE, fs, v)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", out)
        # value never committed -> leak_check only sees committed values; pass it explicitly
        self.assertIn("AKIAIOSFODNN7EXAMPLE", ps.leak_check(out, v, [target.text]))

    def test_session_carry_over(self):
        fs, v = self.analyze("Host SRV-WEB01 is down")
        ps.sanitize("Host SRV-WEB01 is down", fs, v)
        fs2, _ = self.analyze("restart srv-web01 now, then SRV-APP02", vault=v)
        d = self.by_text(fs2)
        self.assertEqual(d["srv-web01"].token, v.lookup("SRV-WEB01"))
        self.assertNotEqual(d["SRV-APP02"].token, d["srv-web01"].token)

    def test_manual_rules(self):
        text = "nodes SRV-X1.corp.example and db.prod.acme plus acme-prod and ACME-PROD"
        rules = [ps.ManualRule("wildcard", "*.acme", "HOSTNAME"),
                 ps.ManualRule("exact", "acme-prod", "PROJECT", True),
                 ps.ManualRule("regex", r"SRV-X\d\.corp\.example", "HOSTNAME")]
        fs, v = self.analyze(text, rules)
        d = self.by_text(fs)
        self.assertEqual(d["db.prod.acme"].source, "manual")
        self.assertEqual(d["acme-prod"].entity, "PROJECT")
        self.assertEqual(d["acme-prod"].token, d["ACME-PROD"].token)
        self.assertIn("SRV-X1.corp.example", d)

    def test_merge_manual_rule_into_staged(self):
        text = "user bob logged into SRV-DC01 and SRV-DC01.lab"
        fs, v = self.analyze(text)
        merged, n = ps.merge_manual_rule(text, fs, ps.ManualRule("wildcard", "SRV-*", "HOSTNAME"), v)
        self.assertEqual(n, 2)
        self.assertIn("SRV-DC01.lab", {f.text for f in merged})
        spans = sorted((f.start, f.end) for f in merged)
        for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
            self.assertLessEqual(e1, s2, "merged findings must not overlap")

    def test_token_edit_and_collision(self):
        text = "SRV-AAA1 and SRV-BBB2"
        fs, v = self.analyze(text)
        a, b = fs[0], fs[1]
        a.token, a.token_edited = "<DC_PRIMARY>", True
        ps.repropose_tokens(fs, v)
        out, _ = ps.sanitize(text, fs, v)
        self.assertIn("<DC_PRIMARY>", out)
        b.token = "<DC_PRIMARY>"
        with self.assertRaises(ps.TokenCollision):
            ps.sanitize(text, fs, v)

    def test_lenient_restore(self):
        v = ps.SessionVault()
        v.commit("SRV-DC01", "<HOSTNAME_1>", "HOSTNAME")
        v.commit("10.0.0.5", "<INTERNAL_IP_10>", "INTERNAL_IP")
        v.commit("10.0.0.6", "<INTERNAL_IP_1>", "INTERNAL_IP")
        txt = "<HOSTNAME_1>, HOSTNAME_1, [HOSTNAME_1], &lt;HOSTNAME_1&gt;, \\<HOSTNAME_1\\>, INTERNAL_IP_10 vs <INTERNAL_IP_1> <X_9>"
        out, n, unknown = v.restore(txt, lenient=True)
        self.assertEqual(out, "SRV-DC01, SRV-DC01, SRV-DC01, SRV-DC01, SRV-DC01, 10.0.0.5 vs 10.0.0.6 <X_9>")
        self.assertEqual(unknown, ["<X_9>"])
        strict, n2, _ = v.restore(txt, lenient=False)
        self.assertIn("HOSTNAME_1,", strict)

    def test_hot_reload(self):
        before = len(self.engine.ruleset.rules)
        f = self.engine.rules_root / "local" / "extra.yaml"
        f.write_text("recognizers:\n  - name: Codename\n    entity: CODENAME\n    deny_list: [Bluebird]\n", "utf-8")
        try:
            rs = self.engine.reload_rules()
            self.assertEqual(len(rs.rules), before + 1)
            fs, _ = self.analyze("Operation Bluebird starts")
            self.assertIn("CODENAME", {x.entity for x in fs})
        finally:
            f.unlink()
            self.engine.reload_rules()

    def test_bad_rule_file_is_isolated(self):
        f = self.engine.rules_root / "local" / "broken.yaml"
        f.write_text("recognizers:\n  - name: Bad\n    entity: 1bad\n    patterns: ['([a-z']\n", "utf-8")
        try:
            rs = self.engine.reload_rules()
            self.assertEqual(len(rs.errors), 1)
            self.assertIn("invalid 'entity'", rs.errors[0])
            self.assertIn("invalid regex", rs.errors[0])
            self.assertGreater(len(rs.rules), 10, "good files must still load")
        finally:
            f.unlink()
            self.engine.reload_rules()

    def test_user_report_hosts_org_address(self):
        text = ("DC01 File-SRV acme.local (My name is Daniel Mizrahi. I'm working at Tenroot Cybersecurity. "
                "I live in Springfield, Rothschild 1. My wife's name is Noa. from DC01 and File-SRV on acme.local)")
        fs, v = self.analyze(text)
        out, _ = ps.sanitize(text, fs, v)
        for raw in ("DC01", "File-SRV", "acme.local", "Daniel", "Mizrahi", "Tenroot", "Springfield",
                    "Rothschild", "Noa"):
            self.assertNotIn(raw, out, raw)

    def test_machine_account(self):
        fs, _ = self.analyze("my computer name is dmizrahi$ and WS54$ joined the domain")
        d = self.by_text(fs)
        self.assertEqual(d["dmizrahi$"].entity, "HOSTNAME")
        self.assertEqual(d["WS54$"].entity, "HOSTNAME")
        fs, _ = self.analyze("Use the ADMIN$ and IPC$ shares. It costs 5$.")
        self.assertEqual([f.text for f in fs], [], "well-known shares and prices are not machine accounts")

    def test_lowercase_and_appliance_hosts(self):
        fs, _ = self.analyze("i have host223, ws54, srv01, sql03 and dc02a behind fortigate40d, "
                             "FGT-60F, asa5506 and synology918")
        d = self.by_text(fs)
        for raw in ("host223", "ws54", "srv01", "sql03", "dc02a", "fortigate40d", "FGT-60F", "asa5506",
                    "synology918"):
            self.assertIn(raw, d, raw)
            self.assertEqual(d[raw].entity, "HOSTNAME", raw)

    def test_product_names_are_not_hosts(self):
        fs, _ = self.analyze("We bought a FortiGate 40D and run SQL Server 2019 and sql2019 on Windows 11. "
                             "Use node 18, web3 tools, Server 2022, pc1 and ws2.")
        self.assertEqual([f.text for f in fs if f.entity == "HOSTNAME"], [])

    def test_benign_text_untouched(self):
        text = ("Upgrade Windows 10 to Windows Server 2019 and Python 3.12. Open port 443. Event ID 4624. "
                "Chapter 3 explains it. We use mongo-db and the file-server role.")
        fs, _ = self.analyze(text)
        self.assertEqual([f.text for f in fs], [])

    # Log lines adapted from the socprime/logtotal-sanitizer test suite (Apache-2.0)
    LOG_CASES = [
        ("Authorization: Bearer abcDEF1234567890xyzQWERTY", "abcDEF1234567890xyzQWERTY", "SECRET"),
        ("curl https://admin:Sup3rS3cret@git.acme.com/repo", "admin:Sup3rS3cret", "SECRET"),
        ("mysql --password=Winter2026! -h db", "Winter2026!", "SECRET"),
        ("Set-Cookie: JSESSIONID=8F3A9C2B1D4E5F60718293A4; Path=/", "8F3A9C2B1D4E5F60718293A4", "SECRET"),
        ("key sk-proj-abcdEFGH1234ijklMNOP5678 leaked", "sk-proj-abcdEFGH1234ijklMNOP5678", "SECRET"),
        ("key AIzaSyA1234567890abcdefghijklmnopqrstuv leaked", "AIzaSyA1234567890abcdefghijklmnopqrstuv", "SECRET"),
        ("token npm_abcdefghijklmnopqrstuvwxyz0123456789AB", "npm_abcdefghijklmnopqrstuvwxyz0123456789AB", "SECRET"),
        ("Oct 12 10:01:02 webgw01 sshd[311]: Failed password for invalid user jsmith from 203.0.113.9",
         "webgw01", "HOSTNAME"),
        ("Oct 12 10:01:02 webgw01 sshd[311]: Failed password for invalid user jsmith from 203.0.113.9",
         "jsmith", "USERNAME"),
        ("Oct 12 10:01:02 mailhub sudo:   kcohen : TTY=pts/0 ; COMMAND=/bin/ls", "kcohen", "USERNAME"),
        ("2024-11-15T09:19:41.123Z srv-app-07 sshd[4970]: session opened", "srv-app-07", "HOSTNAME"),
        ("probe srv-app-07 before failover", "srv-app-07", "HOSTNAME"),
        ("logon by S-1-5-21-3623811015-3361044348-30300820-1013", "S-1-5-21-3623811015-3361044348-30300820-1013", "SID"),
        ("arn:aws:iam::123456789012:user/dlevi", "dlevi", "USERNAME"),
        ("subject system:serviceaccount:prod:billing-api", "billing-api", "USERNAME"),
        ("uid=dlevi,ou=People,dc=acme,dc=local", "dlevi", "USERNAME"),
        ("host=fileshare.acme.com user=dlevi", "fileshare.acme.com", "HOSTNAME"),
        ("host=fileshare.acme.com user=dlevi", "dlevi", "USERNAME"),
        ("WIN-4F7K2LQ9PZ1 and DESKTOP-8HD2KQ1 joined", "WIN-4F7K2LQ9PZ1", "HOSTNAME"),
        ("WIN-4F7K2LQ9PZ1 and DESKTOP-8HD2KQ1 joined", "DESKTOP-8HD2KQ1", "HOSTNAME"),
        ("kerberos HTTP/intranet01.acme.com@ACME.LOCAL", "intranet01.acme.com", "HOSTNAME"),
        ("path=/home/alice/app.log", "alice", "USERNAME"),
        ('"CurrentDirectory": "C:\\\\Users\\\\xodih\\\\AppData\\\\Local"', "xodih", "USERNAME"),
    ]

    def test_log_lines(self):
        for text, value, entity in self.LOG_CASES:
            with self.subTest(text=text, value=value):
                d = self.by_text(self.analyze(text)[0])
                self.assertIn(value, d)
                self.assertEqual(d[value].entity, entity)

    def test_value_group_masks_only_value(self):
        text = "Authorization: Bearer abcDEF1234567890xyzQWERTY and password=Sup3rS3cret!"
        fs, v = self.analyze(text)
        out, _ = ps.sanitize(text, fs, v)
        self.assertRegex(out, r"^Authorization: Bearer <SECRET_\d+> and password=<SECRET_\d+>$")
        self.assertEqual(v.restore(out)[0], text)

    def test_json_fields(self):
        text = ('{"hostName": "BRANCH7", "user_name": "dlevi", "apiKey": "x9Fq2LmZ", "enabled": true, '
                '"note": "", "owner": "-", "uid": 0, "employeeId": 48213, "firstName": "Dana"}')
        fs, v = self.analyze(text)
        d = self.by_text(fs)
        expect = {"BRANCH7": "HOSTNAME", "dlevi": "USERNAME", "x9Fq2LmZ": "SECRET", "48213": "USERNAME",
                  "Dana": "PERSON"}
        for value, entity in expect.items():
            self.assertEqual(d[value].entity, entity, value)
        self.assertNotIn("0", d, "numbers under 3 digits are kept")
        out, _ = ps.sanitize(text, fs, v)
        self.assertIn('"enabled": true', out)
        self.assertIn('"hostName": "<HOSTNAME_', out)
        for text in ("{'user_name': 'maria', 'Password': 'hunter2pass'}",
                     'INFO body="{\\"password\\":\\"hunter2pass\\",\\"user\\":\\"maria\\"}"'):
            d = self.by_text(self.analyze(text)[0])
            self.assertEqual(d["maria"].entity, "USERNAME", text)
            self.assertEqual(d["hunter2pass"].entity, "SECRET", text)

    def test_log_lines_benign(self):
        """No rule match on log and prose text that only looks like the new patterns (spaCy is ignored)."""
        for text in ("Nov 15 09:19:41 kernel: CPU0: temperature above threshold",
                     "2026-10-12 10:01:02 INFO main: started",
                     "We use Bearer authentication and Basic authentication for the API.",
                     "GET /users/12345 returned 404; uses actions/checkout@v4",
                     "I bought this for user experience. Host: please check the server.",
                     "Accepted publickey for root from 203.0.113.9 as S-1-5-18 in C:\\Users\\Public\\x",
                     "cn=Users,dc=acme owner=root user=SYSTEM"):
            with self.subTest(text=text):
                fs, _ = self.analyze(text)
                self.assertEqual([f.text for f in fs if f.source == "custom" and f.entity != "DOMAIN"], [])

    LOG_TEXT = (
        "Oct 12 10:01:02 mailhub sudo:   kcohen : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls\n"
        "2024-11-15T09:19:42Z eventName=GetObject arn arn:aws:s3:::acme-backups/db.sql "
        "principal=arn:aws:iam::123456789012:user/dlevi\n"
        '{"userIdentity": {"arn": "arn:aws:iam::123456789012:user/dlevi"}, "eventName": "ConsoleLogin"}\n'
        "Nov 15 09:19:41 web01 CRON[1234]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)\n"
    )

    def test_looks_like_log(self):
        for text in (self.LOG_TEXT,
                     "Oct 12 10:01:02 webgw01 sshd[311]: Failed password for jsmith from 203.0.113.9",
                     "<34>2024-11-15T09:19:41Z host app: started",
                     "[ERROR] connection refused\n[INFO] retrying",
                     '203.0.113.9 - - [10/Oct/2024:13:55:36 +0000] "GET / HTTP/1.1" 200 512',
                     "1731662381 src=10.1.1.1 dst=10.2.2.2",
                     "user=dlevi host=fs01 action=logon"):
            with self.subTest(text=text):
                self.assertTrue(ps.looks_like_log(text))
        for text in (SAMPLE, "", "   \n", "Hi John,\nplease reset the password for Dana Levi.\nThanks",
                     "Oct 12 10:01:02 web01 sshd[1]: started\nThe log above shows that John Smith\n"
                     "logged in from the Berlin office before\nthe outage."):
            with self.subTest(text=text):
                self.assertFalse(ps.looks_like_log(text))

    def test_skip_ner_on_logs(self):
        if self.engine.mode != "presidio+spacy":
            self.skipTest("needs a spaCy model")
        ecfg = self.cfg["engine"]
        self.assertFalse(ecfg["skip_ner_on_logs"], "off by default")

        def ner(text):
            return {f.text for f in self.analyze(text)[0] if f.recognizer in ps.NER_RECOGNIZERS}
        self.assertTrue(ner(self.LOG_TEXT), "spaCy tags log fields when the option is off")
        self.assertFalse(self.engine.last_ner_skipped)
        ecfg["skip_ner_on_logs"] = True
        try:
            fs, _ = self.analyze(self.LOG_TEXT)
            self.assertTrue(self.engine.last_ner_skipped)
            d = self.by_text(fs)
            self.assertEqual({t for t, f in d.items() if f.recognizer in ps.NER_RECOGNIZERS}, set())
            for value in ("arn", "PWD=/tmp", "COMMAND=/bin/ls", "-v debian-sa1"):
                self.assertNotIn(value, d)
            for value, entity in (("kcohen", "USERNAME"), ("mailhub", "HOSTNAME"), ("dlevi", "USERNAME")):
                self.assertEqual(d[value].entity, entity, value)
            # prose keeps NER
            self.assertEqual(self.by_text(self.analyze(SAMPLE)[0])["John Smith"].entity, "PERSON")
            self.assertFalse(self.engine.last_ner_skipped)
        finally:
            ecfg["skip_ner_on_logs"] = False

    def test_user_kv_skips_arn(self):
        fs, _ = self.analyze("principal=arn:aws:iam::123456789012:role/Backup owner=dlevi")
        d = self.by_text(fs)
        self.assertNotIn("arn", d)
        self.assertEqual(d["dlevi"].entity, "USERNAME")

    def test_pwd_path_is_not_secret(self):
        text = "sudo: kcohen : TTY=pts/0 ; PWD=/home/kcohen ; USER=root ; COMMAND=/bin/ls"
        for fs in (self.analyze(text)[0], self.engine._lite_detect(text, self.engine.ruleset)):
            self.assertEqual([f.text for f in fs if f.entity == "SECRET"], [])
        for text, value in (("pwd=Winter2026!", "Winter2026!"), ("db_pwd: 'Winter2026!'", "Winter2026!"),
                            ("password=/Winter2026!", "/Winter2026!")):
            with self.subTest(text=text):
                self.assertEqual(self.by_text(self.analyze(text)[0])[value].entity, "SECRET")

    def test_lite_mode_value_group(self):
        text = "Oct 12 10:01:02 webgw01 sshd[1]: Accepted password for root from 10.1.1.1 password=Sup3rS3cret!"
        found = {(f.text, f.entity) for f in self.engine._lite_detect(text, self.engine.ruleset)}
        self.assertIn(("Sup3rS3cret!", "SECRET"), found)
        self.assertIn(("webgw01", "HOSTNAME"), found)
        self.assertNotIn("root", {t for t, _ in found}, "not_well_known must drop root in lite mode too")

    def test_manual_rule_value_group(self):
        rule = ps.ManualRule("regex", r"case=(?P<value>\d+)", "CASE_ID")
        fs, _ = self.analyze("see case=48213 now", [rule])
        self.assertEqual([(f.text, f.entity) for f in fs if f.source == "manual"], [("48213", "CASE_ID")])

    def test_high_entropy_rule_is_opt_in(self):
        blob = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A0NQ=="
        self.assertNotIn(blob, self.by_text(self.analyze(f"blob {blob} end")[0]))
        f = self.engine.rules_root / "local" / "entropy.yaml"
        f.write_text("recognizers:\n  - name: HighEntropyBlobs\n    entity: SECRET\n    validator: high_entropy\n"
                     "    patterns: ['(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])']\n", "utf-8")
        try:
            self.assertEqual(self.engine.reload_rules().errors, [])
            self.assertEqual(self.by_text(self.analyze(f"blob {blob} end")[0])[blob].entity, "SECRET")
        finally:
            f.unlink()
            self.engine.reload_rules()

    def test_bad_json_key_is_rejected(self):
        doc = {"recognizers": [{"name": "J", "entity": "X", "json_keys": ["ok", "bad\"key"]}]}
        with self.assertRaises(ps.RuleError) as cm:
            ps.parse_rule_document(doc, self.engine.rules_root / "j.yaml", self.engine.rules_root)
        self.assertIn("invalid JSON key names", str(cm.exception))

    def test_validators(self):
        self.assertTrue(ps._v_israeli_id("123456782"))
        self.assertFalse(ps._v_israeli_id("123456789"))
        self.assertTrue(ps._v_luhn("4111 1111 1111 1111"))
        self.assertFalse(ps._v_luhn("4111 1111 1111 1112"))
        self.assertTrue(ps._v_private_ipv4("172.20.1.1"))
        self.assertFalse(ps._v_private_ipv4("172.32.1.1"))
        self.assertFalse(ps._v_ipv4("10.0.0.300"))
        self.assertTrue(ps._v_high_entropy("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"))
        self.assertFalse(ps._v_high_entropy("0" * 40), "a repeated character is not random")
        self.assertFalse(ps._v_high_entropy("short"))
        self.assertIsNone(ps._v_not_well_known("dlevi"))
        for name in ("root", "SYSTEM", "Public", "S-1-5-18", "S-1-5-32-544", "S-1-1-0"):
            self.assertFalse(ps._v_not_well_known(name), name)
        self.assertIsNone(ps._v_not_well_known("S-1-5-21-1-2-3-500"), "a domain SID is sensitive")

    def test_wildcards(self):
        import re
        rx = re.compile(ps.wildcard_to_regex("SRV-*"), re.I)
        self.assertEqual(rx.findall("a SRV-DC01.corp.local. and srv-x"), ["SRV-DC01.corp.local", "srv-x"])
        rx = re.compile(ps.wildcard_to_regex("*.corp"), re.I)
        self.assertEqual(rx.findall("x.corp a.b.corp y.corporate"), ["x.corp", "a.b.corp"])
        self.assertEqual(rx.findall("see .corp here"), [], "'*.' needs a label before the dot")

    def test_default_threshold_keeps_core_entities(self):
        self.assertEqual(ps.DEFAULT_CONFIG["engine"]["score_threshold"], 0.85)
        text = ("Call +1 (212) 555-0199 or 054-123-4567 from 203.0.113.9, see https://intranet.example.org/x "
                "and report.py. I live at Rothschild 1.")
        d = {f.text: f.entity for f in self.analyze(text)[0]}
        self.assertEqual(d.get("+1 (212) 555-0199"), "PHONE_NUMBER")
        self.assertEqual(d.get("054-123-4567"), "PHONE_NUMBER")
        self.assertEqual(d.get("203.0.113.9"), "IP_ADDRESS")
        self.assertIn("URL", {e for t, e in d.items() if t.startswith("https://intranet.example.org")})
        self.assertNotIn("report.py", d, "a bare file name is not a URL")
        self.assertIn("STREET_ADDRESS", {e for t, e in d.items() if "Rothschild 1" in t})
        d = {f.text for f in self.analyze("id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 ok")[0]}
        self.assertNotIn("3f2504e0-4f89-11d3-9a0c-0305e82c3301", d, "a GUID needs tenant context")

    def test_environment_suffix_names(self):
        hits = ["acme-prod", "acme-dev", "acme-test", "ACME-PROD", "billing-api-staging", "shop-uat-02",
                "acme-qa", "acme-production", "acme-preprod", "acme-sandbox", "acme-stg"]
        fs, _ = self.analyze("deploy " + ", ".join(hits) + " today")
        d = self.by_text(fs)
        for h in hits:
            self.assertIn(h, d, h)
            self.assertEqual(d[h].entity, "HOSTNAME", h)
        skips = ["unit-test", "load-test", "smoke-test", "e2e-test", "pen-test", "a-b-test", "pre-prod",
                 "non-prod", "pre-production", "web-dev", "self-test", "unit-test-01"]
        fs, _ = self.analyze("we ran " + ", ".join(skips) + " today")
        self.assertEqual([f.text for f in fs if f.recognizer == "EnvironmentNames"], [])
        fs, _ = self.analyze("prod dev test production acme-production-line acme.prod acme_prod")
        self.assertEqual([f.text for f in fs if f.recognizer == "EnvironmentNames"], [])

    def test_wildcard_glob_crosses_dots(self):
        import re
        rx = re.compile(ps.wildcard_to_regex("*acme-labs*"), re.I)
        line = '"db.int.prod.acme-labs.com","1","112","7"'
        self.assertEqual(rx.findall(line), ["db.int.prod.acme-labs.com"])
        self.assertEqual(rx.findall("acme-labs.com and x-acme-labs-01 end."),
                         ["acme-labs.com", "x-acme-labs-01"])
        self.assertEqual(rx.findall("cme-labs.com notacme-lab"), [])
        self.assertEqual(rx.findall(" .acme-labs. "), ["acme-labs"], "never starts or ends on a dot")
        rx = re.compile(ps.wildcard_to_regex("db*com"), re.I)
        self.assertEqual(rx.findall("db.int.prod.acme-labs.com db..com dbcom"),
                         ["db.int.prod.acme-labs.com", "dbcom"])
        rx = re.compile(ps.wildcard_to_regex("SRV-*"), re.I)
        self.assertEqual(rx.findall("SRV- and SRV-DC01"), ["SRV-", "SRV-DC01"])
        rx = re.compile(ps.wildcard_to_regex("*"), re.I)
        self.assertNotIn("", rx.findall("a b, c"), "a bare '*' must not match empty text")
        self.assertEqual(ps.wildcard_to_regex("**x**"), ps.wildcard_to_regex("*x*"))

    def test_tldextract_is_offline(self):
        ps.install_network_guard()
        before = ps.NETWORK_GUARD["blocked"]
        self.analyze("mail me at someone@company.co.il")
        self.assertEqual(ps.NETWORK_GUARD["blocked"], before, "email recognizer must not attempt network access")

    def test_network_guard(self):
        import socket
        ps.install_network_guard()
        with self.assertRaises(PermissionError):
            socket.create_connection(("192.0.2.1", 443), timeout=1)


class BundledRulesTests(unittest.TestCase):
    """The default rules are embedded in the script, so a fresh install works with an empty rules/."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.rules = cls.tmp / "rules"
        (cls.rules / "local").mkdir(parents=True)
        cls.engine = ps.DetectionEngine(ps.AppConfig(cls.tmp / "config.json"), cls.rules)
        cls.engine.initialize()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_bundled_rules_match_template(self):
        on_disk = {p.relative_to(TEMPLATE_RULES).as_posix(): p.read_text("utf-8")
                   for p in TEMPLATE_RULES.rglob("*") if p.is_file()
                   and p.suffix.lower() in ps.RULE_EXTENSIONS | ps.WORDLIST_EXTENSIONS}
        self.assertEqual(ps.BUNDLED_RULES, on_disk,
                         "BUNDLED_RULES is out of date with github-repo-template/rules/")

    def test_user_report_with_empty_rules_dir(self):
        text = ("My name is Daniel Mizrahi. I'm working at Tenroot Cybersecurity. I live in Springfield, "
                "Rothschild 1. My wife's name is Noa. Please create me a network diagram of my network. "
                "i have DC01, File-SRV, host223, ws54, fortigate40d, my computer name is dmizrahi$")
        self.assertEqual(self.engine.ruleset.errors, [])
        fs = self.engine.analyze(text, [], ps.SessionVault())
        d = {f.text: f.entity for f in fs}
        for raw in ("DC01", "File-SRV", "host223", "ws54", "fortigate40d", "dmizrahi$"):
            self.assertEqual(d.get(raw), "HOSTNAME", raw)

    def test_local_rule_overrides_bundled(self):
        f = self.rules / "local" / "override.yaml"
        f.write_text("recognizers:\n  - name: HostRoleSuffix\n    entity: SERVER\n    deny_list: [Mail-Box]\n", "utf-8")
        try:
            rs = self.engine.reload_rules()
            self.assertEqual([r.entity for r in rs.rules if r.name == "HostRoleSuffix"], ["SERVER"])
            self.assertEqual(rs.warnings, [], "overriding a bundled rule is expected, not a warning")
        finally:
            f.unlink()
            self.engine.reload_rules()

    def test_self_test(self):
        ok, lines = ps.self_test(self.engine)
        self.assertTrue(ok, "\n".join(lines))
        self.assertIn("PASS", lines[-1])


class FrozenAndCliTests(unittest.TestCase):
    """Behaviour of the PyInstaller build (sys.frozen) and of the CLI without a console."""

    def test_app_dir(self):
        from unittest import mock
        exe = Path("/opt/PII-Shield/PII-Shield.exe")
        env = {k: v for k, v in os.environ.items() if k != "PII_SHIELD_HOME"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(sys, "executable", str(exe)):
                self.assertEqual(ps.default_app_dir(), exe.resolve().parent)
            with mock.patch.object(sys, "frozen", False, create=True):
                self.assertEqual(ps.default_app_dir(), Path(ps.__file__).resolve().parent)
        with mock.patch.dict(os.environ, {"PII_SHIELD_HOME": "/data/pii"}):
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(sys, "executable", str(exe)):
                self.assertEqual(ps.default_app_dir(), Path("/data/pii"))

    def test_default_rules_repo(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            want = "https://api.github.com/repos/TenRoot/pii-shield/contents/github-repo-template/rules"
            self.assertEqual(ps.AppConfig(tmp / "new.json")["github"]["repo_url"], want)
            (tmp / "empty.json").write_text('{"github": {"repo_url": ""}}', "utf-8")
            self.assertEqual(ps.AppConfig(tmp / "empty.json")["github"]["repo_url"], want,
                             "an empty URL saved by an older version falls back to the default")
            (tmp / "own.json").write_text('{"github": {"repo_url": "https://ghe.corp/api/v3/repos/o/r/contents/x", '
                                          '"version_path": "app/version.json"}}', "utf-8")
            own = ps.AppConfig(tmp / "own.json")["github"]
            self.assertEqual(own["repo_url"], "https://ghe.corp/api/v3/repos/o/r/contents/x")
            self.assertEqual(own["version_path"], "app/version.json", "a separate rules repo keeps its layout")
            # the release workflow keeps version.json at the root of the PII Shield repo
            self.assertEqual(ps.AppConfig(tmp / "new.json")["github"]["version_path"], "version.json")
            (tmp / "old.json").write_text('{"github": {"repo_url": "", "version_path": "app/version.json"}}', "utf-8")
            self.assertEqual(ps.AppConfig(tmp / "old.json")["github"]["version_path"], "version.json")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_presidio_hint(self):
        newer = [{"package": "presidio-analyzer", "installed": "2.2.364", "latest": "2.3.0"}]
        hint = ps.presidio_update_hint(newer, frozen=False)
        self.assertIn("pip install -U presidio-analyzer", hint)
        hint = ps.presidio_update_hint(newer, frozen=True)
        self.assertNotIn("pip", hint)
        self.assertIn("presidio-analyzer 2.3.0", hint)
        self.assertIn("new PII Shield release", hint)

    def test_cli_without_console(self):
        """A windowed (GUI-subsystem) build has sys.stdout/sys.stderr = None; the CLI must still work."""
        from unittest import mock
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None):
            self.assertEqual(ps.main(["--version"]), 0)
            self.assertEqual(ps.main(["--validate-rules", str(TEMPLATE_RULES)]), 0)

    def test_gui_start_path(self):
        """main() with no CLI flag builds the QApplication and the main window (Qt itself is mocked)."""
        from unittest import mock
        if not ps.QT_OK:
            self.skipTest("PyQt6 not installed")
        with mock.patch.object(ps.QtWidgets, "QApplication") as app, mock.patch.object(ps, "MainWindow") as win, \
                mock.patch.object(ps, "_ensure_dirs"):
            app.return_value.exec.return_value = 0
            self.assertEqual(ps.main([]), 0)
            win.return_value.show.assert_called_once()

    def test_log_file(self):
        from unittest import mock
        out = Path(tempfile.mkdtemp()) / "cli.log"
        try:
            with mock.patch.object(sys, "stdout", sys.stdout), mock.patch.object(sys, "stderr", sys.stderr):
                self.assertEqual(ps.main(["--validate-rules", str(TEMPLATE_RULES), "--log-file", str(out)]), 0)
            text = out.read_text("utf-8")
            self.assertIn("0 error(s)", text)
        finally:
            shutil.rmtree(out.parent, ignore_errors=True)


@unittest.skipUnless(ps.QT_OK, "PyQt6 not installed")
class MainWindowGuiTests(unittest.TestCase):
    """Main window, offscreen: tab 1 Send to Sanitize button and the session map menu."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            self.win = ps.MainWindow(ps.AppConfig(self.tmp / "config.json"))
        self.addCleanup(self.win.deleteLater)

    def test_button_follows_analysis_state(self):
        w = self.win
        self.assertEqual(w.btn_send.text(), "Send to Sanitize (Ctrl+G)")
        self.assertEqual(w.btn_send.objectName(), w.btn_analyze.objectName(), "same style as Analyze")
        self.assertFalse(w.btn_send.isEnabled(), "off before any analysis")
        w.input.setPlainText("host SRV-DC01")
        w.analyzed_text = "host SRV-DC01"
        w._update_send_button()
        self.assertTrue(w.btn_send.isEnabled(), "on after analysis")
        w.input.setPlainText("host SRV-DC02")
        self.assertFalse(w.btn_send.isEnabled(), "off once the input changes")
        w.input.setPlainText("host SRV-DC01")
        self.assertTrue(w.btn_send.isEnabled(), "on again when the input matches")

    def test_button_generates_and_opens_tab_2(self):
        w = self.win
        w.input.setPlainText("host SRV-DC01")
        w.analyzed_text = "host SRV-DC01"
        w.findings = [ps.Finding(5, 13, "SRV-DC01", "HOSTNAME", 0.9, "custom", token="<HOSTNAME_1>")]
        w._update_send_button()
        w.btn_send.click()
        self.assertEqual(w.tabs.currentIndex(), 1)
        self.assertNotIn("SRV-DC01", w.output.toPlainText())
        self.assertEqual(w.output.toPlainText(), "host <HOSTNAME_1>")


    def test_clear_and_load_file_clear_the_review(self):
        w = self.win
        w.vault.commit("SRV-DC01", "<HOSTNAME_1>", "HOSTNAME")

        def stage():
            w.input.setPlainText("host SRV-DC01")
            w.analyzed_text = "host SRV-DC01"
            w.findings = [ps.Finding(5, 13, "SRV-DC01", "HOSTNAME", 0.9, "custom", token="<HOSTNAME_1>")]
            w.populate_table()
            w._update_send_button()
            self.assertEqual(w.table.rowCount(), 1)

        SB = ps.QtWidgets.QMessageBox.StandardButton
        stage()
        with mock.patch.object(ps.QtWidgets.QMessageBox, "exec", return_value=SB.Cancel):
            w.clear_input_and_review()
        self.assertEqual((w.input.toPlainText(), w.table.rowCount()), ("host SRV-DC01", 1), "Cancel keeps all")

        with mock.patch.object(ps.QtWidgets.QMessageBox, "exec", return_value=SB.No) as asked:
            w.clear_input_and_review()
        asked.assert_called_once()
        self.assertEqual((w.input.toPlainText(), w.table.rowCount(), w.findings), ("", 0, []))
        self.assertIsNone(w.analyzed_text)
        self.assertFalse(w.btn_send.isEnabled())
        self.assertEqual(len(w.vault), 1, "'Keep session map' keeps it")

        stage()
        with mock.patch.object(ps.QtWidgets.QMessageBox, "exec", return_value=SB.Yes):
            w.clear_input_and_review()
        self.assertEqual((w.input.toPlainText(), w.table.rowCount(), len(w.vault)), ("", 0, 0),
                         "'Reset session too' empties the session map")

        w.input.setPlainText("text")
        with mock.patch.object(ps.QtWidgets.QMessageBox, "exec") as asked:
            w.clear_input_and_review()
        asked.assert_not_called()
        self.assertEqual(w.input.toPlainText(), "", "an empty session clears without asking")

        w.vault.commit("SRV-DC01", "<HOSTNAME_1>", "HOSTNAME")

        stage()
        log = self.tmp / "new.log"
        log.write_text("a fresh log line", "utf-8")
        with mock.patch.object(ps.QtWidgets.QFileDialog, "getOpenFileName", return_value=(str(log), "")):
            w.load_file()
        self.assertEqual((w.input.toPlainText(), w.table.rowCount()), ("a fresh log line", 0))
        self.assertIsNone(w.analyzed_text)

    def test_review_table_columns_resize_by_drag(self):
        from PyQt6.QtTest import QTest
        from PyQt6.QtCore import QPoint, Qt
        w = self.win
        w.show()
        self.app.processEvents()
        hh = w.table.horizontalHeader()
        for c in range(len(ps.COLS) - 1):           # the last column fills the free space
            before = hh.sectionSize(c)
            x, y = hh.sectionViewportPosition(c) + before - 1, hh.height() // 2
            QTest.mousePress(hh.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x, y))
            QTest.mouseMove(hh.viewport(), QPoint(x + 20, y))
            QTest.mouseMove(hh.viewport(), QPoint(x + 40, y))
            QTest.mouseRelease(hh.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                               QPoint(x + 40, y))
            self.assertGreater(hh.sectionSize(c), before, f"column {ps.COLS[c]} must resize by drag")

    def test_session_map_right_click_copies_raw_value(self):
        w = self.win
        w.vault.commit("SRV-DC01", "<HOSTNAME_1>", "HOSTNAME")
        w.vault.commit("10.20.30.40", "<INTERNAL_IP_1>", "INTERNAL_IP")
        w.chk_reveal.setChecked(False)
        w.refresh_map()
        row = next(r for r in range(w.map_table.rowCount()) if w.map_table.item(r, 0).text() == "<HOSTNAME_1>")
        self.assertNotEqual(w.map_table.item(row, 1).text(), "SRV-DC01", "the table shows a masked value")
        pos = w.map_table.visualItemRect(w.map_table.item(row, 1)).center()
        clip = ps.QtWidgets.QApplication.clipboard()
        for pick, expect in ((0, "SRV-DC01"), (1, "<HOSTNAME_1>")):
            w.map_table.clearSelection()
            with mock.patch.object(ps.QtWidgets.QMenu, "exec", lambda m, *a, i=pick: m.actions()[i]):
                w._map_menu(pos)
            self.assertEqual(clip.text(), expect)
        w.map_table.selectAll()
        with mock.patch.object(ps.QtWidgets.QMenu, "exec", lambda m, *a: m.actions()[0]):
            w._map_menu(pos)
        self.assertEqual(sorted(clip.text().split("\n")), ["10.20.30.40", "SRV-DC01"])


class RuleDetailsTests(unittest.TestCase):
    def test_promoted_rule_keeps_original_pattern(self):
        rule = ps.ManualRule("wildcard", "*contoso*", "PERSON").to_rule_yaml()
        self.assertEqual(rule["description"], "Promoted from manual wildcard rule: *contoso*")

    def test_details_show_description_regex_and_values(self):
        r = ps.RuleDef(name="n", entity="E", description="d",
                       patterns=[ps.PatternDef("p", r"\bx\b", 0.9)],
                       deny_list=["a", "b", "c"], json_keys=["pw"], json_key_contains=["token"])
        self.assertEqual(ps.rule_details(r, max_values=2),
                         ["d", "values: a, b (+1 more)", r"regex: \bx\b", "json keys: pw, *token*"])

    def _saved_rule(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        root = tmp / "rules"
        (root / "local").mkdir(parents=True)
        ps.append_rule_to_file(root / "local" / "promoted_rules.yaml",
                               ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml())
        rs = ps.load_rules_dir(root, bundled=False)
        return rs, rs.rules[0]

    def test_saved_rule_metadata_round_trip(self):
        y = ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml()
        self.assertEqual(y["metadata"], {"manual": {"match_type": "wildcard", "pattern": "*contoso*"}})
        self.assertEqual(y["name"], ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").rule_name)
        rs, r = self._saved_rule()
        self.assertEqual(ps.manual_source(r), ("wildcard", "*contoso*"))
        self.assertEqual(rs.warnings, [])

    def test_manual_source_from_old_description(self):
        r = ps.RuleDef("n", "E", description="Promoted from manual exact rule: contoso", raw={})
        self.assertEqual(ps.manual_source(r), ("exact", "contoso"))
        r = ps.RuleDef("n", "E", description="Promoted from manual regex rule: a b+", raw={})
        self.assertEqual(ps.manual_source(r), ("regex", "a b+"))
        self.assertIsNone(ps.manual_source(ps.RuleDef("n", "E", description="other", raw={})))

    def test_details_prefer_the_original_pattern(self):
        _, r = self._saved_rule()
        self.assertEqual(ps.rule_details(r)[0:2], [r.description, "wildcard: *contoso*"])
        self.assertEqual(len(ps.rule_details(r)), 2)


class RuleOverrideLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "rules"
        (self.root / "remote").mkdir(parents=True)
        (self.root / "local").mkdir()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, rel, text):
        (self.root / rel).write_text(text, "utf-8")

    def _load(self):
        return ps.load_rules_dir(self.root, bundled=False)

    HOSTS = """recognizers:
  - name: Contoso Hosts.v2
    entity: HOSTNAME
    patterns: ['\\bcontoso-\\w+\\b']
"""

    def test_marker_switches_off_remote_rule(self):
        self._write("remote/r.yaml", self.HOSTS)
        self._write("local/overrides.yaml", "recognizers:\n  - {name: Contoso Hosts.v2, enabled: false}\n")
        rs = self._load()
        self.assertNotIn("Contoso Hosts.v2", [r.name for r in rs.rules])
        r = next(r for r in rs.all_rules if r.name == "Contoso Hosts.v2")
        self.assertEqual((r.enabled, r.is_marker, r.entity), (False, True, "HOSTNAME"))
        self.assertEqual(r.overrides.source_file, "remote/r.yaml")
        self.assertTrue(r.patterns, "marker keeps the original's patterns")

    def test_marker_switches_on_rule_that_is_off_in_its_file(self):
        self._write("remote/r.yaml", self.HOSTS.replace("    entity", "    enabled: false\n    entity"))
        self.assertNotIn("Contoso Hosts.v2", [r.name for r in self._load().rules])
        self._write("local/overrides.yaml", "recognizers:\n  - {name: Contoso Hosts.v2, enabled: true}\n")
        self.assertIn("Contoso Hosts.v2", [r.name for r in self._load().rules])

    def test_marker_without_original_warns(self):
        self._write("local/overrides.yaml", "recognizers:\n  - {name: nothing_here, enabled: false}\n")
        rs = self._load()
        self.assertIn("marker 'nothing_here' in local/overrides.yaml has no rule to change", rs.warnings)
        self.assertNotIn("nothing_here", [r.name for r in rs.all_rules])

    def test_disabled_rule_with_broken_regex_is_not_a_file_error(self):
        self._write("local/a.yaml", """recognizers:
  - {name: valid_one, entity: HOSTNAME, patterns: ['\\bcontoso\\b']}
  - {name: 'off', entity: X, enabled: false, patterns: ['(']}
""")
        rs = self._load()
        self.assertEqual(rs.errors, [])
        self.assertTrue(next(r for r in rs.all_rules if r.name == "off").broken)
        self.assertTrue(any("disabled rule 'off' in" in w for w in rs.warnings))
        self.assertIn("valid_one", [r.name for r in rs.rules])

    def test_marker_cannot_switch_on_broken_rule(self):
        self._write("remote/r.yaml", "recognizers:\n  - {name: 'off', entity: X, enabled: false, patterns: ['(']}\n")
        self._write("local/overrides.yaml", "recognizers:\n  - {name: 'off', enabled: true}\n")
        rs = self._load()
        self.assertIn("cannot switch on 'off': the rule has errors", rs.warnings)
        self.assertNotIn("off", [r.name for r in rs.rules])

    def test_enabled_rule_without_patterns_is_still_an_error(self):
        self._write("local/a.yaml", "recognizers:\n  - {name: n, entity: HOSTNAME}\n")
        self.assertTrue(self._load().errors)

    def test_overrides_file_loads_after_other_local_files(self):
        self._write("local/zz_hand.yaml", "recognizers:\n  - {name: dup, entity: AAA, patterns: ['\\bone\\b']}\n")
        self._write("local/overrides.yaml", "recognizers:\n  - {name: dup, entity: BBB, patterns: ['\\btwo\\b']}\n")
        rs = self._load()
        self.assertEqual(next(r for r in rs.rules if r.name == "dup").source_file, "local/overrides.yaml")

    def test_disabled_full_local_rule_switches_off_bundled_and_remote_rule(self):
        bundled = {"b.yaml": "recognizers:\n  - {name: from_bundled, entity: HOSTNAME, patterns: ['\\bexample-\\w+\\b']}\n"}
        self._write("remote/r.yaml", self.HOSTS)
        self._write("local/mine.yaml", """recognizers:
  - {name: from_bundled, entity: HOSTNAME, enabled: false, patterns: ['\\bfabrikam-\\w+\\b']}
  - {name: Contoso Hosts.v2, entity: HOSTNAME, enabled: false, patterns: ['\\bfabrikam-\\w+\\b']}
""")
        with mock.patch.object(ps, "BUNDLED_RULES", bundled):
            rs = ps.load_rules_dir(self.root, bundled=True)
        active = [r.name for r in rs.rules]
        for name, was in (("from_bundled", "bundled/b.yaml"), ("Contoso Hosts.v2", "remote/r.yaml")):
            self.assertNotIn(name, active)
            r = next(r for r in rs.all_rules if r.name == name)
            self.assertFalse(r.enabled)
            self.assertFalse(r.is_marker)
            self.assertIsNotNone(r.overrides)
            self.assertEqual(r.overrides.source_file, was)

    def test_disabled_entry_with_invalid_name_is_skipped_with_warning(self):
        self._write("local/h.yaml", """recognizers:
  - {name: 'bad/name!', enabled: false}
  - {name: 'bad/full!', entity: HOSTNAME, enabled: false, patterns: ['\\bfabrikam\\b']}
  - {name: ok, entity: HOSTNAME, patterns: ['\\bcontoso\\b']}
""")
        rs = self._load()
        self.assertEqual(rs.errors, [])
        self.assertIn("ok", [r.name for r in rs.rules])
        self.assertEqual([r.name for r in rs.all_rules], ["ok"])
        self.assertTrue(any("bad/name!" in w for w in rs.warnings))
        self.assertTrue(any("bad/full!" in w for w in rs.warnings))
        self.assertEqual(ps.load_rules_dir(self.root, strict=True).errors, [], "strict sync dry run passes")

    def test_enabled_marker_with_invalid_name_is_still_an_error(self):
        self._write("local/h.yaml", "recognizers:\n  - {name: 'bad/name!', enabled: true}\n")
        self.assertTrue(self._load().errors)

    def test_full_copy_records_what_it_replaced(self):
        self._write("remote/c.yaml", self.HOSTS.replace("Contoso Hosts.v2", "c"))
        self._write("local/overrides.yaml", self.HOSTS.replace("Contoso Hosts.v2", "c").replace("HOSTNAME", "ORG"))
        r = next(r for r in self._load().rules if r.name == "c")
        self.assertEqual(r.overrides.source_file, "remote/c.yaml")
        self.assertFalse(r.is_marker)


class RuleWriteTests(unittest.TestCase):
    REMOTE = """recognizers:
  - name: remote_one
    entity: HOSTNAME
    patterns: ['\\bcontoso-\\w+\\b']
  - name: Contoso Hosts.v2
    entity: HOSTNAME
    patterns: ['\\bexample-\\w+\\b']
  - name: remote_wordlist
    entity: ORG
    wordlist: ../wl.txt
  - name: remote_json
    entity: SECRET
    json_keys: [password]
"""
    SAVED = """version: 1
allow_list: [keepme]
recognizers:
  - name: manual_hostname_x
    entity: HOSTNAME
    patterns: ['\\bcontoso\\b']
  - name: manual_org_y
    entity: ORG
    deny_list: [example]
"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "rules"
        (self.root / "remote").mkdir(parents=True)
        (self.root / "local").mkdir()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.root / "wl.txt").write_text("contoso\nexample\n", "utf-8")
        (self.root / "remote/x.yaml").write_text(self.REMOTE, "utf-8")
        self.saved = self.root / "local/promoted_rules.yaml"
        self.saved.write_text(self.SAVED, "utf-8")
        self.ov = self.root / "local/overrides.yaml"

    def rule(self, name):
        return next(r for r in ps.load_rules_dir(self.root).all_rules if r.name == name)

    def recs(self, path):
        return ps.yaml.safe_load(path.read_text("utf-8"))["recognizers"]

    def test_kinds(self):
        self.assertEqual(ps.rule_kind(self.rule("remote_one")), "remote")
        self.assertEqual(ps.rule_kind(self.rule("manual_org_y")), "saved")
        self.assertEqual(ps.rule_kind(ps.RuleDef("a", "B", source_file="bundled/hosts.yaml")), "bundled")
        self.assertEqual(ps.rule_kind(ps.RuleDef("a", "B", source_file="local/zz.yaml")), "hand-edited")

    def test_disable_and_enable_remote_rule_writes_then_removes_marker(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        self.assertEqual(self.recs(self.ov), [{"name": "remote_one", "enabled": False}])
        ps.set_rule_enabled(self.root, self.rule("remote_one"), True)
        self.assertEqual(self.recs(self.ov), [])

    def test_disable_saved_rule_sets_flag_in_place(self):
        ps.set_rule_enabled(self.root, self.rule("manual_org_y"), False)
        recs = self.recs(self.saved)
        self.assertEqual([r.get("enabled", True) for r in recs], [True, False])
        self.assertEqual(ps.yaml.safe_load(self.saved.read_text("utf-8"))["allow_list"], ["keepme"])

    def test_hand_edited_rule_refused(self):
        (self.root / "local/zz.yaml").write_text(
            "recognizers:\n  - {name: hand, entity: ORG, deny_list: [example]}\n", "utf-8")
        with self.assertRaises(ps.RuleError):
            ps.set_rule_enabled(self.root, self.rule("hand"), False)

    def test_delete_last_saved_rule_keeps_valid_empty_file(self):
        ps.delete_rule(self.root, self.rule("manual_hostname_x"))
        ps.delete_rule(self.root, self.rule("manual_org_y"))
        self.assertEqual(self.recs(self.saved), [])
        self.assertEqual(ps.load_rules_dir(self.root).errors, [])

    def test_invalid_edit_leaves_file_unchanged(self):
        r = self.rule("manual_hostname_x")
        before = self.saved.read_bytes()
        with self.assertRaises(ps.RuleError):
            ps.save_rule(self.root, r, {**r.raw, "patterns": ["("]})
        self.assertEqual(self.saved.read_bytes(), before)
        self.assertFalse(self.saved.with_suffix(".tmp").exists())

    def test_broken_yaml_file_is_not_overwritten(self):
        self.ov.write_text("recognizers: [", "utf-8")
        with self.assertRaises(ps.RuleError):
            ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        self.assertEqual(self.ov.read_text("utf-8"), "recognizers: [")

    def test_refuses_files_the_app_does_not_own(self):
        with self.assertRaises(ps.RuleError):
            ps.update_rule_file(self.root / "remote/x.yaml", self.root, lambda r: r)
        with self.assertRaises(ps.RuleError):
            ps.update_rule_file(self.root / "local/zz.yaml", self.root, lambda r: r)

    def test_override_copy_inlines_wordlist(self):
        c = ps.override_copy(self.rule("remote_wordlist"))
        self.assertNotIn("wordlist", c)
        self.assertEqual(sorted(c["deny_list"]), ["contoso", "example"])

    def test_override_copy_keeps_json_keys_without_generated_patterns(self):
        c = ps.override_copy(self.rule("remote_json"))
        self.assertEqual((c["json_keys"], c.get("patterns")), (["password"], None))

    def test_override_status_changed_and_removed(self):
        orig = self.rule("remote_one")
        c = ps.override_copy(orig)
        c["entity"] = "ORG"
        ps.save_rule(self.root, orig, c)
        r = self.rule("remote_one")
        self.assertEqual(ps.rule_kind(r), "override")
        self.assertIsNone(ps.override_status(r))
        (self.root / "remote/x.yaml").write_text(self.REMOTE.replace("contoso-", "fabrikam-"), "utf-8")
        self.assertEqual(ps.override_status(self.rule("remote_one")), "changed")
        (self.root / "remote/x.yaml").write_text(self.REMOTE.replace("name: remote_one", "name: gone"), "utf-8")
        self.assertEqual(ps.override_status(self.rule("remote_one")), "removed")

    def test_override_status_none_for_marker(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        self.assertIsNone(ps.override_status(self.rule("remote_one")))

    def test_restore_original_removes_copy(self):
        orig = self.rule("remote_one")
        c = ps.override_copy(orig)
        c["entity"] = "ORG"
        ps.save_rule(self.root, orig, c)
        ps.restore_original(self.root, self.rule("remote_one"))
        self.assertEqual(self.recs(self.ov), [])
        self.assertEqual(self.rule("remote_one").entity, "HOSTNAME")

    def test_save_edit_of_saved_rule_in_place_and_rename(self):
        r = self.rule("manual_hostname_x")
        ps.save_rule(self.root, r, {**r.raw, "name": "renamed", "entity": "ORG"})
        self.assertEqual([x["name"] for x in self.recs(self.saved)], ["renamed", "manual_org_y"])

    def test_saved_rule_rename_collision_refused(self):
        r = self.rule("manual_hostname_x")
        before = self.saved.read_bytes()
        with self.assertRaises(ps.RuleError):
            ps.save_rule(self.root, r, {**r.raw, "name": "manual_org_y"})
        self.assertEqual(self.saved.read_bytes(), before)

    def test_edit_of_marker_rule_replaces_marker_with_full_copy(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        m = self.rule("remote_one")
        c = ps.override_copy(m)
        self.assertFalse(c["enabled"])
        ps.save_rule(self.root, m, c)
        recs = self.recs(self.ov)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["patterns"], ["\\bcontoso-\\w+\\b"])

    def test_marker_matches_name_with_spaces_and_dots(self):
        ps.set_rule_enabled(self.root, self.rule("Contoso Hosts.v2"), False)
        self.assertNotIn("Contoso Hosts.v2", [r.name for r in ps.load_rules_dir(self.root).rules])

    def test_append_rule_to_file_still_works(self):
        ps.append_rule_to_file(self.saved, {"name": "manual_new", "entity": "ORG", "deny_list": ["example"]})
        self.assertEqual([x["name"] for x in self.recs(self.saved)][-1], "manual_new")

    # ---- toggles decide from the file entry, not from a stale RuleDef
    def test_stale_remote_ruledef_toggle_keeps_edited_copy(self):
        stale = self.rule("remote_one")
        c = ps.override_copy(stale)
        c["patterns"] = ["\\bfabrikam-\\w+\\b"]
        ps.save_rule(self.root, stale, c)
        ps.set_rule_enabled(self.root, stale, False)
        recs = self.recs(self.ov)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["patterns"], ["\\bfabrikam-\\w+\\b"])
        self.assertIs(recs[0]["enabled"], False)

    def test_stale_marker_ruledef_toggle_back_keeps_edited_copy(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        marker = self.rule("remote_one")
        ps.save_rule(self.root, marker, {**ps.override_copy(marker), "patterns": ["\\bfabrikam-\\w+\\b"]})
        ps.set_rule_enabled(self.root, marker, True)
        recs = self.recs(self.ov)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["patterns"], ["\\bfabrikam-\\w+\\b"])
        self.assertIs(recs[0]["enabled"], True)

    def test_toggle_to_original_state_writes_no_marker(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), True)
        self.assertEqual(self.recs(self.ov) if self.ov.exists() else [], [])

    def test_stale_override_ruledef_after_restore_writes_marker(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        marker = self.rule("remote_one")
        ps.restore_original(self.root, marker)
        ps.set_rule_enabled(self.root, marker, False)
        self.assertEqual(self.recs(self.ov), [{"name": "remote_one", "enabled": False}])

    def test_remote_rule_over_disabled_bundled_rule_gets_marker(self):
        bundled = {"b.yaml": "recognizers:\n  - {name: remote_one, entity: HOSTNAME, enabled: false, "
                             "patterns: ['\\bexample-\\w+\\b']}\n"}
        with mock.patch.object(ps, "BUNDLED_RULES", bundled):
            r = next(r for r in ps.load_rules_dir(self.root, bundled=True).all_rules if r.name == "remote_one")
            self.assertEqual(ps.rule_kind(r), "remote")
            ps.set_rule_enabled(self.root, r, False)
            self.assertNotIn("remote_one", [x.name for x in ps.load_rules_dir(self.root, bundled=True).rules])
        self.assertEqual(self.recs(self.ov), [{"name": "remote_one", "enabled": False}])

    # ---- a bad edit of a disabled rule is refused
    def test_save_disabled_rule_with_bad_regex_refused(self):
        ps.set_rule_enabled(self.root, self.rule("manual_hostname_x"), False)
        r = self.rule("manual_hostname_x")
        before = self.saved.read_bytes()
        with self.assertRaises(ps.RuleError):
            ps.save_rule(self.root, r, {**r.raw, "patterns": ["("]})
        self.assertEqual(self.saved.read_bytes(), before)

    def test_save_disabled_marker_copy_with_bad_regex_refused(self):
        ps.set_rule_enabled(self.root, self.rule("remote_one"), False)
        m = self.rule("remote_one")
        before = self.ov.read_bytes()
        with self.assertRaises(ps.RuleError):
            ps.save_rule(self.root, m, {**ps.override_copy(m), "patterns": ["("]})
        self.assertEqual(self.ov.read_bytes(), before)

    def test_toggle_still_accepts_disabled_broken_entry(self):
        self.saved.write_text(self.SAVED + "  - {name: broken_off, entity: ORG, enabled: false, patterns: ['(']}\n",
                              "utf-8")
        ps.set_rule_enabled(self.root, self.rule("manual_org_y"), False)
        self.assertEqual([r["name"] for r in self.recs(self.saved)][-1], "broken_off")

    # ---- write failures
    def test_os_error_on_replace_raises_rule_error_and_keeps_file(self):
        before = self.saved.read_bytes()
        with mock.patch.object(ps.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(ps.RuleError) as cm:
                ps.set_rule_enabled(self.root, self.rule("manual_org_y"), False)
        self.assertIn("cannot write", str(cm.exception))
        self.assertEqual(self.saved.read_bytes(), before)
        self.assertFalse(self.saved.with_suffix(".tmp").exists())


class ReloadLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "rules" / "local").mkdir(parents=True)
        self.engine = ps.DetectionEngine(ps.AppConfig(self.tmp / "config.json"), self.tmp / "rules")

    def _blocking_loader(self, gate, started):
        results = []

        def fake(root, strict=False, bundled=False):
            rs = ps.RuleSet()
            results.append(rs)
            started.set()
            if len(results) == 1:
                gate.wait(5)
            return rs
        return fake, results

    def test_concurrent_reloads_run_one_at_a_time(self):
        import threading
        gate, started = threading.Event(), threading.Event()
        fake, results = self._blocking_loader(gate, started)
        with mock.patch.object(ps, "load_rules_dir", side_effect=fake), mock.patch.object(ps, "PRESIDIO_OK", False):
            a = threading.Thread(target=self.engine.reload_rules, daemon=True)
            a.start()
            self.assertTrue(started.wait(5))
            b = threading.Thread(target=self.engine.reload_rules, daemon=True)
            b.start()
            b.join(0.3)
            self.assertEqual(len(results), 1, "second reload waits for the first")
            gate.set()
            a.join(5)
            b.join(5)
        self.assertEqual(len(results), 2)
        self.assertIs(self.engine.ruleset, results[1], "the newest ruleset is assigned last")

    def test_initialize_during_reload_does_not_deadlock(self):
        import threading
        gate, started = threading.Event(), threading.Event()
        fake, results = self._blocking_loader(gate, started)
        with mock.patch.object(ps, "load_rules_dir", side_effect=fake), mock.patch.object(ps, "PRESIDIO_OK", False):
            a = threading.Thread(target=self.engine.reload_rules, daemon=True)
            a.start()
            self.assertTrue(started.wait(5))
            b = threading.Thread(target=self.engine.initialize, daemon=True)
            b.start()
            b.join(0.3)
            gate.set()
            a.join(5)
            b.join(5)
            self.assertFalse(a.is_alive() or b.is_alive(), "deadlock")
        self.assertEqual(self.engine.mode, "lite")
        self.assertIs(self.engine.ruleset, results[-1])


class RuleEditTests(unittest.TestCase):
    def test_build_edited_raw_manual_renames(self):
        base = ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml()
        new = ps.build_edited_raw(base, entity="ORGANIZATION", score=0.95, case_sensitive=False,
                                  manual=("wildcard", "*contoso-labs*"))
        self.assertEqual(new["name"], ps.ManualRule("wildcard", "*contoso-labs*", "ORGANIZATION").rule_name)

    def test_build_edited_raw_manual_score_applies_to_patterns(self):
        base = ps.ManualRule("wildcard", "*contoso*", "ORGANIZATION").to_rule_yaml()
        new = ps.build_edited_raw(base, entity="ORGANIZATION", score=0.5, case_sensitive=False,
                                  manual=("wildcard", "*contoso*"))
        self.assertEqual(new["score"], 0.5)
        self.assertEqual(new["patterns"][0]["score"], 0.5)

    def test_build_edited_raw_manual_keeps_enabled(self):
        base = dict(ps.ManualRule("exact", "contoso", "ORGANIZATION").to_rule_yaml(), enabled=False)
        new = ps.build_edited_raw(base, entity="ORGANIZATION", score=0.8, case_sensitive=True,
                                  manual=("exact", "contoso"))
        self.assertIs(new["enabled"], False)
        self.assertEqual(new["score"], 0.8)
        self.assertTrue(new["case_sensitive"])

    def test_build_edited_raw_keeps_unshown_fields(self):
        base = {"name": "n", "entity": "HOSTNAME", "context": ["host"], "validator": "luhn",
                "patterns": [{"name": "p1", "regex": r"\bcontoso\b", "score": 0.7}]}
        new = ps.build_edited_raw(base, entity="HOSTNAME", score=0.9, case_sensitive=False,
                                  patterns=[r"\bcontoso\b", r"\bexample\b"])
        self.assertEqual(new["context"], ["host"])
        self.assertEqual(new["validator"], "luhn")
        self.assertEqual(new["patterns"][0], {"name": "p1", "regex": r"\bcontoso\b", "score": 0.7})
        self.assertEqual(new["patterns"][1], r"\bexample\b")
        self.assertNotIn("deny_list", new)

    def test_build_edited_raw_values_and_input_untouched(self):
        base = {"name": "n", "entity": "ORG", "deny_list": ["old"]}
        new = ps.build_edited_raw(base, entity="ORG", score=0.9, case_sensitive=False,
                                  values=["contoso", "example"])
        self.assertEqual(new["deny_list"], ["contoso", "example"])
        self.assertEqual(base["deny_list"], ["old"])
        gone = ps.build_edited_raw(base, entity="ORG", score=0.9, case_sensitive=False)
        self.assertNotIn("deny_list", gone)

    def test_build_edited_raw_scalar_pattern_mapping_is_kept(self):
        base = {"name": "n", "entity": "HOSTNAME", "patterns": {"name": "p1", "regex": r"\bcontoso\b", "score": 0.7}}
        new = ps.build_edited_raw(base, entity="HOSTNAME", score=0.9, case_sensitive=False,
                                  patterns=[r"\bcontoso\b"])
        self.assertEqual(new["patterns"], [{"name": "p1", "regex": r"\bcontoso\b", "score": 0.7}])


@unittest.skipUnless(ps.QT_OK, "PyQt6 not available")
class RulesManagerGuiTests(unittest.TestCase):
    REMOTE = "recognizers:\n  - name: remote_one\n    entity: HOSTNAME\n    patterns: ['\\bcontoso-\\w+\\b']\n" \
             "  - name: remote_wl\n    entity: ORG\n    wordlist: ../wl.txt\n"

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = ps.QtWidgets.QApplication.instance() or ps.QtWidgets.QApplication([])

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "rules"
        (self.root / "remote").mkdir(parents=True)
        (self.root / "local").mkdir()
        (self.root / "wl.txt").write_text("contoso\nexample\n", "utf-8")
        (self.root / "remote/x.yaml").write_text(self.REMOTE, "utf-8")
        self.saved = self.root / "local/promoted_rules.yaml"
        ps.append_rule_to_file(self.saved, ps.ManualRule("wildcard", "*contoso*", "HOSTNAME").to_rule_yaml())
        ps.append_rule_to_file(self.saved, {"name": "plain", "entity": "HOSTNAME",
                                            "patterns": [r"\bcontoso-\d+\b"]})
        self.ov = self.root / "local/overrides.yaml"

    def rule(self, name):
        return next(r for r in ps.load_rules_dir(self.root).all_rules if r.name == name)

    def dialog(self, name):
        dlg = ps.RuleEditDialog(None, self.rule(name), self.root, ["HOSTNAME", "ORGANIZATION"])
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_edit_dialog_shows_read_only_name(self):
        self.assertEqual(self.dialog("plain").ed_name.text(), "plain")
        manual = next(r.name for r in ps.load_rules_dir(self.root).all_rules if r.name != "plain"
                      and ps.rule_kind(r) == "saved")
        dlg = self.dialog(manual)
        self.assertEqual(dlg.ed_name.text(), manual)
        self.assertTrue(dlg.name_hint.text())

    def test_edit_dialog_invalid_regex_stays_open(self):
        dlg = self.dialog("plain")
        finished = []
        dlg.finished.connect(finished.append)
        before = self.saved.read_bytes()
        dlg.ed_patterns.setPlainText("(")
        with mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            dlg.btn_save.click()
        warn.assert_called_once()
        self.assertEqual(finished, [], "dialog stays open")
        self.assertEqual(self.saved.read_bytes(), before)

    def test_edit_dialog_test_box_shows_matches(self):
        dlg = self.dialog("plain")
        dlg.ed_patterns.setPlainText(r"\bcontoso-\d+\b")
        dlg.ed_sample.setPlainText("host contoso-01")
        self.assertIn("contoso-01", dlg.ed_result.text())
        dlg.ed_sample.setPlainText("nothing here")
        self.assertEqual(dlg.ed_result.text(), "No match")
        dlg.ed_patterns.setPlainText("(")
        dlg.ed_sample.setPlainText("x")
        self.assertNotEqual(dlg.ed_result.text(), "No match")

    def test_cancel_edit_copy_writes_nothing(self):
        dlg = self.dialog("remote_one")
        dlg.reject()
        self.assertFalse(self.ov.exists())

    def test_manual_rule_form_saves_with_new_name(self):
        r = self.rule(ps.ManualRule("wildcard", "*contoso*", "HOSTNAME").rule_name)
        dlg = self.dialog(r.name)
        self.assertEqual(dlg.ed_pattern.text(), "*contoso*")
        dlg.ed_pattern.setText("*contoso-labs*")
        dlg.btn_save.click()
        self.assertEqual(dlg.result(), ps.QtWidgets.QDialog.DialogCode.Accepted)
        names = [x["name"] for x in ps.yaml.safe_load(self.saved.read_text("utf-8"))["recognizers"]]
        self.assertIn(ps.ManualRule("wildcard", "*contoso-labs*", "HOSTNAME").rule_name, names)

    def test_save_remote_copy_writes_override(self):
        dlg = self.dialog("remote_one")
        dlg.ed_patterns.setPlainText(r"\bexample-\w+\b")
        dlg.btn_save.click()
        self.assertEqual(dlg.result(), ps.QtWidgets.QDialog.DialogCode.Accepted)
        self.assertTrue(self.ov.exists())

    def test_edit_dialog_scalar_patterns_and_values(self):
        ps.append_rule_to_file(self.saved, {"name": "scalar_one", "entity": "HOSTNAME",
                                            "patterns": r"\bcontoso-\d+\b", "deny_list": "fabrikam"})
        dlg = self.dialog("scalar_one")
        self.assertEqual(dlg.ed_patterns.toPlainText(), r"\bcontoso-\d+\b")
        self.assertEqual(dlg.ed_values.toPlainText(), "fabrikam")

    def test_wordlist_warning_shown(self):
        dlg = self.dialog("remote_wl")
        self.assertEqual(dlg.ed_values.toPlainText().splitlines(), ["contoso", "example"])
        self.assertIn("This copy no longer follows changes to the original word list.",
                      dlg.warning_label.text())
        self.assertEqual(self.dialog("remote_one").warning_label.text(), "")

    # ---- rules manager window
    BUNDLED = {"b.yaml": "version: 1\nrecognizers:\n  - name: bundled_one\n    entity: HOSTNAME\n"
                         "    patterns: ['\\bexample-\\w+\\b']\n"}

    def window(self, ready=True):
        patcher = mock.patch.object(ps, "BUNDLED_RULES", self.BUNDLED)
        patcher.start()
        self.addCleanup(patcher.stop)
        with mock.patch.object(ps.MainWindow, "_start_engine"):
            w = ps.MainWindow(ps.AppConfig(self.tmp / "config.json"))
        self.addCleanup(w.deleteLater)
        w.engine.rules_root = self.root
        if ready:
            w.engine.mode = "lite"      # as after initialize(); _start_engine is patched out
        return w

    def manager(self, w):
        with mock.patch.object(ps.QtWidgets.QDialog, "exec", return_value=0) as ex:
            w.show_rule_report()
        ex.assert_called_once()
        dlg = w._rules_manager
        self.addCleanup(lambda: None if sip.isdeleted(dlg) else dlg.deleteLater())
        return dlg

    def row_of(self, dlg, name):
        for r in range(dlg.table.rowCount()):
            if dlg.table.item(r, 2).text() == name:
                return r
        self.fail(f"no row {name}")

    def act(self, dlg, name, button):
        dlg.table.cellWidget(self.row_of(dlg, name), 5).findChild(ps.QtWidgets.QPushButton, button).click()

    def test_chip_opens_manager(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        self.assertIsInstance(dlg, ps.RulesManagerDialog)
        self.assertEqual(dlg.table.rowCount(), len(w.engine.ruleset.all_rules))
        self.assertEqual([dlg.table.horizontalHeaderItem(i).text() for i in range(6)],
                         ["On", "Entity", "Name", "Source", "Matches", "Actions"])

    def test_uncheck_bundled_rule_drops_active_count(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        before = len(w.engine.ruleset.rules)
        row = self.row_of(dlg, "bundled_one")
        self.assertEqual(dlg.table.item(row, 3).text(), "bundled")
        dlg.table.item(row, 0).setCheckState(ps.Qt.CheckState.Unchecked)
        self.assertEqual(len(w.engine.ruleset.rules), before - 1)
        self.assertIn("Re-analyze", w.statusBar().currentMessage())
        self.assertTrue(self.ov.exists())

    def test_hand_edited_row_is_read_only(self):
        (self.root / "local/mine.yaml").write_text(
            "recognizers:\n  - name: hand_one\n    entity: ORG\n    patterns: ['\\bfabrikam\\b']\n", "utf-8")
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        row = self.row_of(dlg, "hand_one")
        item = dlg.table.item(row, 0)
        self.assertFalse(item.flags() & ps.Qt.ItemFlag.ItemIsEnabled)
        self.assertIn("Edit this file by hand", item.toolTip())
        self.assertIsNone(dlg.table.cellWidget(row, 5))

    def test_delete_saved_rule_after_confirm(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        yes = ps.QtWidgets.QMessageBox.StandardButton.Yes
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question", return_value=yes):
            self.act(dlg, "plain", "act_delete")
        self.assertNotIn("plain", [r.name for r in w.engine.ruleset.all_rules])
        self.assertNotIn("plain", [dlg.table.item(r, 2).text() for r in range(dlg.table.rowCount())])
        self.assertIn("Re-analyze", w.statusBar().currentMessage())

    def test_delete_declined_changes_nothing(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        before = self.saved.read_bytes()
        no = ps.QtWidgets.QMessageBox.StandardButton.No
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question", return_value=no):
            self.act(dlg, "plain", "act_delete")
        self.assertEqual(self.saved.read_bytes(), before)

    def test_delete_last_saved_rule_leaves_empty_list(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        yes = ps.QtWidgets.QMessageBox.StandardButton.Yes
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question", return_value=yes):
            for name in [r.name for r in w.engine.ruleset.all_rules if ps.rule_kind(r) == "saved"]:
                self.act(dlg, name, "act_delete")
        self.assertIn("recognizers: []", self.saved.read_text("utf-8"))

    def test_filter_by_source(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        dlg.filter_source.setCurrentText("saved")
        saved = [r for r in w.engine.ruleset.all_rules if ps.rule_kind(r) == "saved"]
        self.assertEqual(dlg.table.rowCount(), len(saved))
        dlg.filter_source.setCurrentText("All")
        dlg.filter_text.setText("remote_one")
        self.assertEqual(dlg.table.rowCount(), 1)

    def test_edit_copy_opens_dialog(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        with mock.patch.object(ps.RuleEditDialog, "exec",
                               return_value=ps.QtWidgets.QDialog.DialogCode.Rejected) as ex:
            self.act(dlg, "remote_one", "act_edit")
        ex.assert_called_once()
        self.assertFalse(self.ov.exists())

    def test_restore_original_after_confirm(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        dlg.table.item(self.row_of(dlg, "bundled_one"), 0).setCheckState(ps.Qt.CheckState.Unchecked)
        self.assertEqual(dlg.table.item(self.row_of(dlg, "bundled_one"), 3).text(), "override of bundled")
        yes = ps.QtWidgets.QMessageBox.StandardButton.Yes
        with mock.patch.object(ps.QtWidgets.QMessageBox, "question", return_value=yes) as q:
            self.act(dlg, "bundled_one", "act_restore")
        self.assertEqual(q.call_args[0][2], "Delete your copy and use the original rule?")
        self.assertEqual(dlg.table.item(self.row_of(dlg, "bundled_one"), 3).text(), "bundled")
        self.assertIn("recognizers: []", self.ov.read_text("utf-8"))

    def test_rule_error_shows_warning_and_changes_nothing(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        row = self.row_of(dlg, "plain")
        with mock.patch.object(ps, "set_rule_enabled", side_effect=ps.RuleError("boom")), \
                mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            dlg.table.item(row, 0).setCheckState(ps.Qt.CheckState.Unchecked)
        warn.assert_called_once()
        self.assertEqual(dlg.table.item(self.row_of(dlg, "plain"), 0).checkState(), ps.Qt.CheckState.Checked)

    def test_open_before_engine_load(self):
        w = self.window(ready=False)
        self.assertEqual(w.engine.ruleset.all_rules, [])
        with mock.patch.object(w.engine, "reload_rules") as reload:
            dlg = self.manager(w)
            self.assertGreater(dlg.table.rowCount(), 0)
            row = self.row_of(dlg, "bundled_one")
            dlg.table.item(row, 0).setCheckState(ps.Qt.CheckState.Unchecked)
        reload.assert_not_called()
        self.assertEqual(dlg.table.item(self.row_of(dlg, "bundled_one"), 0).checkState(),
                         ps.Qt.CheckState.Unchecked)
        self.assertNotIn("bundled_one", [r.name for r in dlg.ruleset.rules])
        self.assertEqual(ps.yaml.safe_load(self.ov.read_text("utf-8"))["recognizers"],
                         [{"name": "bundled_one", "enabled": False}])
        self.assertIn("Re-analyze", w.statusBar().currentMessage())

    def test_accepted_edit_updates_row(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)

        def fake_exec(edit):
            edit.ed_patterns.setPlainText(r"\bfabrikam-\d+\b")
            edit.btn_save.click()
            return edit.result()
        with mock.patch.object(ps.RuleEditDialog, "exec", fake_exec):
            self.act(dlg, "plain", "act_edit")
        self.assertIn("fabrikam", dlg.table.item(self.row_of(dlg, "plain"), 4).text())
        self.assertIn("Re-analyze", w.statusBar().currentMessage())

    def test_reload_failure_after_write_shows_warning(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        with mock.patch.object(w.engine, "reload_rules", side_effect=RuntimeError("boom")), \
                mock.patch.object(ps.QtWidgets.QMessageBox, "warning") as warn:
            dlg._changed()
        warn.assert_called_once()

    def test_manager_is_deleted_after_close(self):
        w = self.window()
        w.engine.reload_rules()
        dlg = self.manager(w)
        ps.QtCore.QCoreApplication.sendPostedEvents(None, ps.QtCore.QEvent.Type.DeferredDelete)
        self.assertTrue(sip.isdeleted(dlg))

    def test_gui_saves_to_engine_rules_root(self):
        w = self.window()
        w.engine.reload_rules()
        mr = ps.ManualRule("exact", "contoso-host", "HOSTNAME", True)
        w._selected_manual = lambda: [mr]
        with mock.patch.object(ps.QtWidgets.QMessageBox, "information"), \
                mock.patch.object(ps, "append_rule_to_file") as app:
            w.promote_manual_rules()
        self.assertEqual(app.call_args[0][0], self.saved)


if __name__ == "__main__":
    unittest.main()
