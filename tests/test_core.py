"""Core engine tests:  python -m unittest discover -s tests -v"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
