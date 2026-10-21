"""GitHub sync tests against a local mock of the GitHub REST 'contents' API over HTTPS.
Requires the `openssl` CLI to mint a throwaway localhost certificate."""
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import pii_sanitizer as ps  # noqa: E402

TOKEN = "ghp_testtoken"


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class MockGitHub(BaseHTTPRequestHandler):
    repo_files = {}          # path -> bytes   (paths relative to repo root)
    tamper = set()           # paths whose served bytes differ from the advertised sha
    requests_seen = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        ref = parse_qs(u.query).get("ref", ["main"])[0]
        MockGitHub.requests_seen.append((u.path, ref, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"message": "Bad credentials"})
        if ref != "main":
            return self._send(404, {"message": "No commit found for the ref"})
        base = "/api/v3/repos/acme/rules-repo"
        if u.path == base:
            return self._send(200, {"full_name": "acme/rules-repo", "private": True, "default_branch": "main"})
        if not u.path.startswith(base + "/contents/"):
            return self._send(404, {"message": "Not Found"})
        path = unquote(u.path[len(base + "/contents/"):]).strip("/")
        host = f"https://{self.headers['Host']}"
        if path in self.repo_files:
            if "raw" in (self.headers.get("Accept") or ""):
                data = self.repo_files[path]
                return self._send(200, data + (b"#tampered" if path in self.tamper else b""), "application/octet-stream")
            d = self.repo_files[path]
            return self._send(200, {"type": "file", "name": path.split("/")[-1], "path": path,
                                    "sha": blob_sha(d), "size": len(d), "url": f"{host}{base}/contents/{path}?ref=main"})
        children = {}
        for p, d in self.repo_files.items():
            if p.startswith(path + "/"):
                rest = p[len(path) + 1:]
                name = rest.split("/")[0]
                full = f"{path}/{name}"
                if "/" in rest:
                    children[name] = {"type": "dir", "name": name, "path": full, "sha": "0" * 40, "size": 0,
                                      "url": f"{host}{base}/contents/{full}?ref=main"}
                else:
                    children[name] = {"type": "file", "name": name, "path": full, "sha": blob_sha(d),
                                      "size": len(d), "url": f"{host}{base}/contents/{full}?ref=main"}
        if not children:
            return self._send(404, {"message": "Not Found"})
        return self._send(200, list(children.values()))


GOOD_RULES = b"""version: 1
allow_list: [localhost]
recognizers:
  - name: Hosts
    entity: HOSTNAME
    patterns: [{name: srv, regex: '\\bSRV-[A-Z0-9]+\\b', score: 0.9}]
  - name: Customers
    entity: CUSTOMER
    wordlist: wordlists/customers.txt
"""


class SyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cert, key = cls.tmp / "c.pem", cls.tmp / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockGitHub)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.cert = cert
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "localhost,127.0.0.1"
        ps.install_network_guard()   # sync must still work with the guard active

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        MockGitHub.repo_files = {
            "rules/rules.yaml": GOOD_RULES,
            "rules/wordlists/customers.txt": b"# customers\nContoso\nFabrikam\n",
            "rules/README.md": b"ignored",
            "app/version.json": b"",
        }
        MockGitHub.tamper = set()
        self.root = Path(tempfile.mkdtemp(dir=self.tmp))
        self.rules = self.root / "rules"
        (self.rules / "local").mkdir(parents=True)
        (self.rules / "local" / "mine.yaml").write_text(
            "recognizers:\n  - name: Mine\n    entity: CODENAME\n    deny_list: [Bluebird]\n", "utf-8")
        self.cfg = ps.AppConfig(self.root / "config.json")
        self.cfg["github"].update(repo_url=f"https://localhost:{self.port}/api/v3/repos/acme/rules-repo/contents/rules",
                                  branch="main", ca_bundle=str(self.cert))
        ps.BACKUP_DIR = self.root / "backups"
        self.engine = ps.DetectionEngine(self.cfg, self.rules)
        self.engine.initialize()

    def client(self, token=TOKEN):
        return ps.GitHubSync(self.cfg, token, self.engine, self.rules)

    def test_url_normalization(self):
        n = ps.normalize_repo_url
        self.assertEqual(n("https://api.github.com/repos/o/r/contents/rules"), ("https://api.github.com", "o/r", "rules"))
        self.assertEqual(n("https://github.com/o/r/tree/main/a/b"), ("https://api.github.com", "o/r", "a/b"))
        self.assertEqual(n("https://github.com/o/r"), ("https://api.github.com", "o/r", ""))
        self.assertEqual(n("o/r/rules"), ("https://api.github.com", "o/r", "rules"))
        self.assertEqual(n("https://ghe.corp/api/v3/repos/o/r/contents/x"), ("https://ghe.corp/api/v3", "o/r", "x"))
        with self.assertRaises(ps.SyncError):
            n("http://github.com/o/r")

    def test_connection_and_auth(self):
        self.assertIn("acme/rules-repo", self.client().test_connection())
        with self.assertRaisesRegex(ps.SyncError, "401"):
            self.client("wrong").test_connection()

    def test_wrong_branch(self):
        self.cfg["github"]["branch"] = "nope"
        with self.assertRaisesRegex(ps.SyncError, "404"):
            self.client().plan()

    def test_full_cycle(self):
        before = len(self.engine.ruleset.rules)
        plan, rs = self.client().pull()
        self.assertEqual(sorted(plan.added), ["rules.yaml", "wordlists/customers.txt"])  # README ignored
        self.assertEqual(len(rs.rules), before + 2)
        self.assertTrue((self.rules / "remote" / "wordlists" / "customers.txt").exists())
        fs = self.engine.analyze("Contoso asked about SRV-DC01 and Bluebird", [], ps.SessionVault())
        self.assertEqual({f.entity for f in fs}, {"CUSTOMER", "HOSTNAME", "CODENAME"})
        # second pull: nothing to do
        plan2, _ = self.client().pull()
        self.assertFalse(plan2.has_changes)
        # remote change -> only that file reported changed
        MockGitHub.repo_files["rules/wordlists/customers.txt"] += b"Initech\n"
        plan3, _ = self.client().pull()
        self.assertEqual(plan3.changed, ["wordlists/customers.txt"])
        fs = self.engine.analyze("Initech", [], ps.SessionVault())
        self.assertEqual([f.entity for f in fs], ["CUSTOMER"])
        self.assertTrue(any((self.root / "backups").glob("remote-*")))
        # remote deletion
        del MockGitHub.repo_files["rules/wordlists/customers.txt"]
        MockGitHub.repo_files["rules/rules.yaml"] = GOOD_RULES.split(b"  - name: Customers")[0]
        plan4, rs4 = self.client().pull()
        self.assertEqual(plan4.removed, ["wordlists/customers.txt"])
        self.assertFalse((self.rules / "remote" / "wordlists" / "customers.txt").exists())

    def test_invalid_remote_rules_are_rejected_atomically(self):
        self.client().pull()
        snapshot = (self.rules / "remote" / "rules.yaml").read_bytes()
        n_rules = len(self.engine.ruleset.rules)
        MockGitHub.repo_files["rules/rules.yaml"] = GOOD_RULES.replace(b"SRV-[A-Z0-9]+", b"SRV-[A-Z0-9+")
        with self.assertRaisesRegex(ps.SyncError, "Validation failed"):
            self.client().pull()
        self.assertEqual((self.rules / "remote" / "rules.yaml").read_bytes(), snapshot)
        self.assertEqual(len(self.engine.ruleset.rules), n_rules)

    def test_missing_wordlist_rejected(self):
        del MockGitHub.repo_files["rules/wordlists/customers.txt"]
        with self.assertRaisesRegex(ps.SyncError, "wordlist not found"):
            self.client().pull()
        self.assertFalse((self.rules / "remote").exists())

    def test_integrity_check(self):
        MockGitHub.tamper = {"rules/rules.yaml"}
        with self.assertRaisesRegex(ps.SyncError, "Integrity"):
            self.client().pull()

    def test_local_tamper_detected(self):
        self.client().pull()
        (self.rules / "remote" / "rules.yaml").write_text("recognizers: []\n")
        plan = self.client().plan()
        self.assertEqual(plan.changed, ["rules.yaml"])

    def test_app_update(self):
        new_script = b'__version__ = "9.9.9"\nprint("hello")\n'
        good = {"version": "9.9.9", "script_path": "app/pii_sanitizer.py",
                "sha256": hashlib.sha256(new_script).hexdigest(), "notes": "test"}
        MockGitHub.repo_files["app/pii_sanitizer.py"] = new_script
        MockGitHub.repo_files["app/version.json"] = json.dumps(good).encode()
        c = self.client()
        info = c.check_app_version()
        self.assertTrue(info["newer"])
        target = self.root / "pii_sanitizer.py"
        target.write_bytes(b'__version__ = "1.0.0"\n')
        c.download_app_update(info, target)
        self.assertEqual(target.read_bytes(), new_script)
        bad = dict(good, sha256="0" * 64)
        with self.assertRaisesRegex(ps.SyncError, "SHA-256 mismatch"):
            c.download_app_update(bad, target)
        MockGitHub.repo_files["app/pii_sanitizer.py"] = b"def broken(:\n"
        broken = dict(good, sha256=hashlib.sha256(b"def broken(:\n").hexdigest())
        with self.assertRaisesRegex(ps.SyncError, "syntax"):
            c.download_app_update(broken, target)

    def test_offline_mode_blocks_sync(self):
        self.cfg["behavior"]["offline_mode"] = True
        with self.assertRaisesRegex(ps.SyncError, "Offline"):
            self.client()

    def test_token_never_sent_to_foreign_host(self):
        c = self.client()
        with self.assertRaisesRegex(ps.SyncError, "different host"):
            c._get("https://evil.example.com/steal")


if __name__ == "__main__":
    unittest.main()
