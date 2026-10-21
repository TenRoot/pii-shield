"""GitHub sync tests against a local mock of the GitHub REST 'contents' API over HTTPS.
Requires the `openssl` CLI to mint a throwaway localhost certificate."""
import gc
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


class MockPyPI(BaseHTTPRequestHandler):
    """PyPI JSON API: GET /pypi/<package>/json -> {"info": {"version": ...}}"""
    versions = {}
    requests_seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        MockPyPI.requests_seen.append(self.path)
        parts = self.path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "pypi" or parts[2] != "json" or parts[1] not in self.versions:
            body, code = b'{"message": "Not Found"}', 404
        else:
            body, code = json.dumps({"info": {"version": self.versions[parts[1]]}}).encode(), 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockDownloads(BaseHTTPRequestHandler):
    """Static release assets (github.com/.../releases/download/...): no auth, plain bytes."""
    files = {}
    auth_seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        MockDownloads.auth_seen.append(self.headers.get("Authorization"))
        data = self.files.get(self.path)
        self.send_response(200 if data is not None else 404)
        self.send_header("Content-Length", str(len(data or b"")))
        self.end_headers()
        self.wfile.write(data or b"")


def make_zip(entries) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


WIN_BUILD = {"PII-Shield/PII-Shield.exe": b"MZ new exe", "PII-Shield/_internal/python312.dll": b"dll"}


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
        cls.pypi = ThreadingHTTPServer(("127.0.0.1", 0), MockPyPI)
        cls.pypi.socket = ctx.wrap_socket(cls.pypi.socket, server_side=True)
        threading.Thread(target=cls.pypi.serve_forever, daemon=True).start()
        cls.pypi_url = f"https://localhost:{cls.pypi.server_address[1]}/pypi"
        cls.dl = ThreadingHTTPServer(("127.0.0.1", 0), MockDownloads)
        cls.dl.socket = ctx.wrap_socket(cls.dl.socket, server_side=True)
        threading.Thread(target=cls.dl.serve_forever, daemon=True).start()
        cls.dl_url = f"https://127.0.0.1:{cls.dl.server_address[1]}"
        cls.cert = cert
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "localhost,127.0.0.1"
        ps.install_network_guard()   # sync must still work with the guard active

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.pypi.shutdown()
        cls.dl.shutdown()
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
        self.cfg = self.new_config()
        ps.BACKUP_DIR = self.root / "backups"
        self.engine = ps.DetectionEngine(self.cfg, self.rules)
        self.engine.initialize()

    def tearDown(self):
        # unittest keeps every TestCase instance alive; drop the spaCy-backed engine so memory stays flat
        self.engine = None
        gc.collect()

    def new_config(self, name="config.json"):
        cfg = ps.AppConfig(self.root / name)
        cfg["github"].update(repo_url=f"https://localhost:{self.port}/api/v3/repos/acme/rules-repo/contents/rules",
                             branch="main", ca_bundle=str(self.cert))
        return cfg

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

    # ---- startup updates
    def test_auto_sync_on_startup(self):
        plan, rs = ps.auto_sync_rules(self.cfg, TOKEN, self.engine, self.rules)
        self.assertEqual(sorted(plan.added), ["rules.yaml", "wordlists/customers.txt"])
        self.assertIn("Hosts", {r.name for r in rs.rules})
        self.assertTrue((self.rules / "remote" / "rules.yaml").exists())

    def test_auto_sync_skipped(self):
        cases = {"disabled": ("github", {"auto_sync_on_startup": False}),
                 "offline": ("behavior", {"offline_mode": True}),
                 "no repo": ("github", {"repo_url": ""})}
        for name, (section, change) in cases.items():
            with self.subTest(name):
                cfg = self.new_config(f"{name}.json")
                cfg[section].update(change)
                seen = len(MockGitHub.requests_seen)
                self.assertIsNone(ps.auto_sync_rules(cfg, TOKEN, self.engine, self.rules))
                self.assertEqual(len(MockGitHub.requests_seen), seen, "a skipped sync must not touch the network")
                self.assertFalse((self.rules / "remote").exists())

    def set_remote_app(self, version):
        script = f'__version__ = "{version}"\n'.encode()
        MockGitHub.repo_files["app/pii_sanitizer.py"] = script
        MockGitHub.repo_files["app/version.json"] = json.dumps(
            {"version": version, "script_path": "app/pii_sanitizer.py",
             "sha256": hashlib.sha256(script).hexdigest(), "notes": "test"}).encode()

    def test_startup_app_check(self):
        self.set_remote_app("999.0.0")
        info = ps.auto_check_app_update(self.cfg, TOKEN)
        self.assertTrue(info["newer"])
        self.assertEqual(info["version"], "999.0.0")
        self.set_remote_app(ps.__version__)
        self.assertFalse(ps.auto_check_app_update(self.cfg, TOKEN)["newer"])

    def test_startup_app_check_without_version_file(self):
        del MockGitHub.repo_files["app/version.json"]
        self.assertIsNone(ps.auto_check_app_update(self.cfg, TOKEN))

    def test_startup_app_check_skipped(self):
        self.set_remote_app("999.0.0")
        cases = {"disabled": ("github", {"check_app_updates": False}),
                 "offline": ("behavior", {"offline_mode": True}),
                 "no repo": ("github", {"repo_url": ""})}
        for name, (section, change) in cases.items():
            with self.subTest(name):
                cfg = self.new_config(f"{name}.json")
                cfg[section].update(change)
                seen = len(MockGitHub.requests_seen)
                self.assertIsNone(ps.auto_check_app_update(cfg, TOKEN))
                self.assertEqual(len(MockGitHub.requests_seen), seen, "a skipped check must not touch the network")

    # ---- frozen (PyInstaller) app update: verified release zip + updater script
    def win_info(self, data, sha=None, url=None, name="build"):
        path = f"/releases/download/v9.9.9/{name}/PII-Shield-9.9.9-win64.zip"
        MockDownloads.files[path] = data
        return {"version": "9.9.9", "newer": True,
                "windows_zip_url": url or f"{self.dl_url}{path}",
                "windows_zip_sha256": sha or hashlib.sha256(data).hexdigest()}

    def test_windows_build_download(self):
        MockDownloads.auth_seen = []
        app = self.root / "app"
        app.mkdir()
        info = self.win_info(make_zip(WIN_BUILD))
        script = ps.download_windows_build(info, self.cfg, app_dir=app, pid=4321)
        new = app / "updates" / "9.9.9" / "PII-Shield"
        self.assertEqual((new / "PII-Shield.exe").read_bytes(), b"MZ new exe")
        self.assertTrue((new / "_internal" / "python312.dll").exists())
        self.assertFalse(list((app / "updates").glob("*.zip")), "the verified zip is deleted after extraction")
        text = script.read_text("utf-8")
        self.assertEqual(script.suffix, ".ps1")
        self.assertIn("$procId = 4321", text)
        self.assertIn(f"$app = '{app}'", text)
        self.assertIn(f"$new = '{new}'", text)
        self.assertEqual(MockDownloads.auth_seen, [None], "the GitHub token must never go to the download host")

    def test_update_script_quotes_paths(self):
        app = self.root / "it's here"
        new = app / "updates" / "9.9.9" / "PII-Shield"
        new.mkdir(parents=True)
        text = ps.write_update_script(new, app, 7).read_text("utf-8")
        self.assertIn("$app = '" + str(app).replace("'", "''") + "'", text)

    def test_windows_build_rejected(self):
        good = make_zip(WIN_BUILD)
        cases = {
            "sha mismatch": (self.win_info(good, sha="0" * 64, name="sha"), "SHA-256 mismatch"),
            "zip slip": (self.win_info(make_zip({**WIN_BUILD, "PII-Shield/../../evil.txt": b"x"}), name="slip"),
                         "unsafe path"),
            "no exe": (self.win_info(make_zip({"PII-Shield/_internal/a.dll": b"x"}), name="noexe"), "PII-Shield.exe"),
            "http url": (self.win_info(good, url="http://example.com/x.zip"), "https"),
            "no fields": ({"version": "9.9.9", "newer": True}, "windows_zip_url"),
        }
        for name, (info, err) in cases.items():
            with self.subTest(name):
                app = self.root / name.replace(" ", "_")
                app.mkdir()
                with self.assertRaisesRegex(ps.SyncError, err):
                    ps.download_windows_build(info, self.cfg, app_dir=app, pid=1)
                self.assertFalse((self.root / "evil.txt").exists())
                self.assertFalse(list(app.rglob("*.exe")), "nothing is left behind on failure")

    def test_install_dispatch(self):
        from unittest import mock
        c = self.client()
        with mock.patch.object(sys, "frozen", False, create=True), \
                mock.patch.object(ps.GitHubSync, "download_app_update", return_value=Path("s.py")) as m:
            self.assertEqual(c.install_app_update({"version": "9.9.9"}), ("script", Path("s.py")))
            m.assert_called_once()
        with mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.object(ps, "download_windows_build", return_value=Path("u.ps1")) as m:
            self.assertEqual(c.install_app_update({"version": "9.9.9"}), ("restart", Path("u.ps1")))
            m.assert_called_once()

    def test_concurrent_pull_refused(self):
        with ps.SYNC_LOCK:
            with self.assertRaisesRegex(ps.SyncError, "already running"):
                self.client().pull()
        self.client().pull()   # the lock is released again

    def test_presidio_update_check(self):
        from importlib import metadata
        installed = metadata.version("presidio-anonymizer")
        MockPyPI.versions = {"presidio-analyzer": "999.0.0", "presidio-anonymizer": installed}
        res = {r["package"]: r for r in ps.check_package_updates(self.cfg, index_url=self.pypi_url)}
        self.assertTrue(res["presidio-analyzer"]["newer"])
        self.assertEqual(res["presidio-analyzer"]["latest"], "999.0.0")
        self.assertEqual(res["presidio-analyzer"]["installed"], metadata.version("presidio-analyzer"))
        self.assertFalse(res["presidio-anonymizer"]["newer"])

    def test_presidio_update_check_skipped(self):
        MockPyPI.versions = {"presidio-analyzer": "999.0.0", "presidio-anonymizer": "999.0.0"}
        cases = {"disabled": ("engine", {"check_presidio_updates": False}),
                 "offline": ("behavior", {"offline_mode": True})}
        for name, (section, change) in cases.items():
            with self.subTest(name):
                cfg = self.new_config(f"{name}.json")
                cfg[section].update(change)
                seen = len(MockPyPI.requests_seen)
                self.assertIsNone(ps.check_package_updates(cfg, index_url=self.pypi_url))
                self.assertEqual(len(MockPyPI.requests_seen), seen)

    def test_presidio_update_check_error(self):
        MockPyPI.versions = {}
        with self.assertRaisesRegex(ps.SyncError, "PyPI check"):
            ps.check_package_updates(self.cfg, index_url=self.pypi_url)


if __name__ == "__main__":
    unittest.main()
