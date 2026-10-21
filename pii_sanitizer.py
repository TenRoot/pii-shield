#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Shield - local, two-way PII / sensitive-data sanitizer for LLM prompt engineering.

  * 100% local processing: Microsoft Presidio + local spaCy model. The only network
    traffic this program makes is the GitHub rules sync (HTTP GET of rule files, plus an
    optional version check; at startup and on demand) and a startup PyPI version check for
    Presidio. Offline mode turns all of it off. Prompt text is never transmitted.
  * Human-in-the-loop: every detection is staged in an editable table before masking.
  * Consistent tokens: identical values always map to the same token for the session.
  * Hot-reloadable custom recognizers from ./rules (local) and ./rules/remote (GitHub).

Usage:
    python pii_sanitizer.py                     # launch the GUI
    python pii_sanitizer.py --validate-rules DIR  # validate a rules folder (CI-friendly)
    python pii_sanitizer.py --version
"""
from __future__ import annotations

__version__ = "1.4.0"
APP_NAME = "PII Shield"
APP_ID = "pii-shield"

import os

# Hard-disable any accidental model hub traffic from optional NLP back-ends.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

import argparse
import base64
import copy
import datetime as _dt
import hashlib
import json
import logging
import re
import shutil
import sys
import tempfile
import threading
import traceback
import uuid
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, quote

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def is_frozen() -> bool:
    """True when running from the PyInstaller build (PII-Shield.exe)."""
    return bool(getattr(sys, "frozen", False))


def default_app_dir() -> Path:
    """Data folder: PII_SHIELD_HOME, else next to PII-Shield.exe (the build's own files live in
    _internal/), else next to this script."""
    if os.environ.get("PII_SHIELD_HOME"):
        return Path(os.environ["PII_SHIELD_HOME"])
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = default_app_dir()
RULES_DIR = APP_DIR / "rules"
LOCAL_RULES_DIR = RULES_DIR / "local"
REMOTE_RULES_DIR = RULES_DIR / "remote"
BACKUP_DIR = APP_DIR / "backups"
CONFIG_PATH = APP_DIR / "config.json"
MANUAL_RULES_FILE = LOCAL_RULES_DIR / "promoted_rules.yaml"
ALLOW_LIST_FILE = LOCAL_RULES_DIR / "allow_list.yaml"
SYNC_MANIFEST = ".sync_manifest.json"

RULE_EXTENSIONS = {".yaml", ".yml", ".json"}
WORDLIST_EXTENSIONS = {".txt", ".lst", ".csv"}
SYNC_EXTENSIONS = RULE_EXTENSIONS | WORDLIST_EXTENSIONS

log = logging.getLogger(APP_ID)
logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)
logging.getLogger("presidio-anonymizer").setLevel(logging.WARNING)
# IMPORTANT: never log raw detected values or prompt text anywhere in this program.


# ===========================================================================
# 1. Configuration & secrets
# ===========================================================================
DEFAULT_BUILTIN_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "CREDIT_CARD",
    "IBAN_CODE", "URL", "LOCATION", "ORGANIZATION", "US_SSN", "CRYPTO", "MAC_ADDRESS",
]

# The shared rules: github-repo-template/rules in the public PII Shield repo (no token needed).
DEFAULT_RULES_REPO = "https://api.github.com/repos/TenRoot/pii-shield/contents/github-repo-template/rules"

DEFAULT_CONFIG: Dict = {
    "github": {
        "repo_url": DEFAULT_RULES_REPO,  # GitHub contents API URL of the rules folder
        "branch": "main",
        "check_app_updates": True,
        "auto_sync_on_startup": True,  # pull rules in the background when the app starts
        "version_path": "version.json",  # repo-root path; the release workflow keeps it on main
        "ca_bundle": "",              # optional corporate CA bundle for TLS inspection proxies
        "timeout": 20,
        "token_in_config": "",        # only used when the OS keyring is unavailable
    },
    "engine": {
        "spacy_model": "en_core_web_lg",
        "language": "en",
        "score_threshold": 0.35,
        "builtin_entities": list(DEFAULT_BUILTIN_ENTITIES),
        "detect_organizations": True,   # spaCy ORG: some false positives, but safer to over-detect
        "check_presidio_updates": True,  # ask PyPI at startup; reports only, never installs
    },
    "behavior": {
        "token_format": "<{entity}_{n}>",
        "propagate_values": True,        # mask every literal occurrence of a detected value
        "case_insensitive_values": True,  # "SRV-DC01" and "srv-dc01" share a token
        "lenient_restore": True,         # also restore HOSTNAME_1, [HOSTNAME_1], &lt;HOSTNAME_1&gt;
        "clipboard_clear_seconds": 0,    # 0 = never auto-clear
        "offline_mode": False,           # True = no network at all: no GitHub sync, no update checks
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class AppConfig:
    """config.json persisted next to the script."""

    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self.data = copy.deepcopy(DEFAULT_CONFIG)
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                self.data = _deep_merge(DEFAULT_CONFIG, json.loads(self.path.read_text("utf-8")))
                g = self.data["github"]
                if not (g.get("repo_url") or "").strip():   # saved empty by <= 1.4.0
                    g["repo_url"] = DEFAULT_RULES_REPO
                if g["repo_url"] == DEFAULT_RULES_REPO and g.get("version_path") == "app/version.json":
                    g["version_path"] = "version.json"   # old default; this repo keeps it at the root
            except Exception as exc:  # corrupt config -> keep defaults, keep a copy
                log.error("config.json unreadable (%s); using defaults", exc)
                shutil.copy2(self.path, self.path.with_suffix(".json.bad"))

    def save(self) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2), "utf-8")
        os.replace(tmp, self.path)

    def __getitem__(self, section: str) -> Dict:
        return self.data[section]


class SecretStore:
    """GitHub PAT storage: OS keyring when available, else config.json (plaintext, flagged)."""

    SERVICE = APP_ID
    USER = "github_pat"

    def __init__(self, config: AppConfig):
        self.config = config
        try:
            import keyring  # optional
            keyring.get_keyring()
            self._kr = keyring
        except Exception:
            self._kr = None

    @property
    def backend(self) -> str:
        return "OS keyring" if self._kr else "config.json (plaintext - install 'keyring' to secure)"

    def get(self) -> str:
        if self._kr:
            try:
                return self._kr.get_password(self.SERVICE, self.USER) or ""
            except Exception:
                pass
        enc = self.config["github"].get("token_in_config", "")
        try:
            return base64.b64decode(enc).decode() if enc else ""
        except Exception:
            return ""

    def set(self, token: str) -> None:
        token = (token or "").strip()
        if self._kr:
            try:
                if token:
                    self._kr.set_password(self.SERVICE, self.USER, token)
                else:
                    try:
                        self._kr.delete_password(self.SERVICE, self.USER)
                    except Exception:
                        pass
                self.config["github"]["token_in_config"] = ""
                return
            except Exception:
                pass
        # base64 is NOT encryption - it only stops casual shoulder-surfing of config.json
        self.config["github"]["token_in_config"] = base64.b64encode(token.encode()).decode() if token else ""


# ===========================================================================
# 2. Rule schema, validation and loading
# ===========================================================================
ENTITY_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,47}$")
RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,80}$")
# crude ReDoS heuristic: a quantified group around a single quantified atom, e.g. (a+)+ (\w*)* (.+)+
_NESTED_QUANT_RE = re.compile(r"\((?:\?:)?(?:\\.|\[[^\]]*\]|[^()\\])[+*]\)[+*{]")


class RuleError(Exception):
    pass


# ---- validators usable from YAML: `validator: luhn | israeli_id | ipv4 | private_ipv4`
def _v_luhn(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 12:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _v_israeli_id(text: str) -> bool:
    digits = "".join(c for c in text if c.isdigit())
    if not 5 <= len(digits) <= 9:
        return False
    digits = digits.zfill(9)
    total = 0
    for i, c in enumerate(digits):
        n = int(c) * (1 if i % 2 == 0 else 2)
        total += n if n < 10 else n - 9
    return total % 10 == 0 and digits != "000000000"


def _v_ipv4(text: str) -> bool:
    m = re.search(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", text)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


def _v_private_ipv4(text: str) -> bool:
    if not _v_ipv4(text):
        return False
    a, b = [int(x) for x in re.search(r"(\d+)\.(\d+)", text).groups()]
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127 or (a == 169 and b == 254)


VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "luhn": _v_luhn,
    "israeli_id": _v_israeli_id,
    "ipv4": _v_ipv4,
    "private_ipv4": _v_private_ipv4,
}


@dataclass
class PatternDef:
    name: str
    regex: str
    score: float


@dataclass
class RuleDef:
    name: str
    entity: str
    patterns: List[PatternDef] = field(default_factory=list)
    deny_list: List[str] = field(default_factory=list)
    context: List[str] = field(default_factory=list)
    score: float = 0.85                # score for deny_list / wordlist hits
    case_sensitive: bool = False
    validator: Optional[str] = None
    description: str = ""
    source_file: str = ""

    @property
    def flags(self) -> int:
        f = re.DOTALL | re.MULTILINE
        return f if self.case_sensitive else f | re.IGNORECASE


@dataclass
class RuleSet:
    rules: List[RuleDef] = field(default_factory=list)
    allow_list: set = field(default_factory=set)       # casefolded literal values never to mask
    files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)    # per-file problems (file skipped)
    warnings: List[str] = field(default_factory=list)

    @property
    def entities(self) -> List[str]:
        return sorted({r.entity for r in self.rules})

    @property
    def pattern_count(self) -> int:
        return sum(len(r.patterns) + (1 if r.deny_list else 0) for r in self.rules)


def _read_structured(path: Path):
    text = path.read_text("utf-8-sig")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        raise RuleError("PyYAML is not installed")
    return yaml.safe_load(text)  # safe_load: no arbitrary object construction


def _read_wordlist(path: Path) -> List[str]:
    items = []
    for line in path.read_text("utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            items.append(line)
    return items


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _safe_child(base: Path, rel: str, root: Path) -> Path:
    """Resolve rel against base, refusing anything that escapes the rules root."""
    p = (base / rel).resolve()
    r = root.resolve()
    if p != r and r not in p.parents:
        raise RuleError(f"path escapes rules folder: {rel}")
    return p


def parse_rule_document(doc, path: Path, root: Path) -> Tuple[List[RuleDef], set, List[str]]:
    """Validate one YAML/JSON document. Raises RuleError with all problems listed."""
    problems: List[str] = []
    warnings: List[str] = []
    if doc is None:
        return [], set(), [f"{path.name}: empty file"]
    if isinstance(doc, list):           # bare list == list of recognizers
        doc = {"recognizers": doc}
    if not isinstance(doc, dict):
        raise RuleError(f"{path.name}: top level must be a mapping")
    unknown_top = set(doc) - {"version", "recognizers", "allow_list", "description", "metadata"}
    if unknown_top:
        warnings.append(f"{path.name}: ignoring unknown keys {sorted(unknown_top)}")

    allow = {str(x).strip().casefold() for x in _as_list(doc.get("allow_list")) if str(x).strip()}
    rules: List[RuleDef] = []
    recs = doc.get("recognizers", []) or []
    if not isinstance(recs, list):
        raise RuleError(f"{path.name}: 'recognizers' must be a list")

    for i, r in enumerate(recs):
        where = f"{path.name}#{i + 1}"
        if not isinstance(r, dict):
            problems.append(f"{where}: recognizer must be a mapping")
            continue
        if r.get("enabled", True) is False:
            continue
        name = str(r.get("name", "")).strip()
        entity = str(r.get("entity", r.get("supported_entity", ""))).strip().upper()
        where = f"{path.name}:{name or i + 1}"
        if not name or not RULE_NAME_RE.match(name):
            problems.append(f"{where}: invalid or missing 'name'")
        if not ENTITY_NAME_RE.match(entity):
            problems.append(f"{where}: invalid 'entity' (use UPPER_SNAKE_CASE, e.g. HOSTNAME)")
        try:
            score = float(r.get("score", 0.85))
            if not 0 < score <= 1:
                raise ValueError
        except (TypeError, ValueError):
            problems.append(f"{where}: 'score' must be in (0, 1]")
            score = 0.85
        validator = r.get("validator")
        if validator and validator not in VALIDATORS:
            problems.append(f"{where}: unknown validator '{validator}' (have: {', '.join(VALIDATORS)})")
        case_sensitive = bool(r.get("case_sensitive", False))
        rd = RuleDef(name=name, entity=entity, score=score, case_sensitive=case_sensitive,
                     validator=validator or None, description=str(r.get("description", "")),
                     context=[str(c) for c in _as_list(r.get("context"))],
                     source_file=str(path.relative_to(root)) if root in path.parents else path.name)

        for j, p in enumerate(_as_list(r.get("patterns"))):
            if isinstance(p, str):
                p = {"regex": p}
            if not isinstance(p, dict) or "regex" not in p:
                problems.append(f"{where}: pattern #{j + 1} needs a 'regex'")
                continue
            rx = str(p["regex"])
            try:
                compiled = re.compile(rx, rd.flags)
            except re.error as exc:
                problems.append(f"{where}: pattern #{j + 1} invalid regex: {exc}")
                continue
            if compiled.search("") is not None and compiled.fullmatch("") is not None:
                problems.append(f"{where}: pattern #{j + 1} matches the empty string")
                continue
            if _NESTED_QUANT_RE.search(rx):
                warnings.append(f"{where}: pattern #{j + 1} has nested quantifiers (possible ReDoS)")
            try:
                pscore = float(p.get("score", score))
                if not 0 < pscore <= 1:
                    raise ValueError
            except (TypeError, ValueError):
                problems.append(f"{where}: pattern #{j + 1} score must be in (0, 1]")
                continue
            rd.patterns.append(PatternDef(str(p.get("name", f"{name}_{j + 1}")), rx, pscore))

        deny = [str(x).strip() for x in _as_list(r.get("deny_list")) if str(x).strip()]
        for wl in _as_list(r.get("wordlist")):
            try:
                wl_path = _safe_child(path.parent, str(wl), root)
                if not wl_path.exists():
                    problems.append(f"{where}: wordlist not found: {wl}")
                    continue
                deny.extend(_read_wordlist(wl_path))
            except RuleError as exc:
                problems.append(f"{where}: {exc}")
        rd.deny_list = sorted(set(deny), key=lambda s: (-len(s), s))

        if not rd.patterns and not rd.deny_list:
            problems.append(f"{where}: needs at least one of 'patterns', 'deny_list', 'wordlist'")
        rules.append(rd)

    if problems:
        raise RuleError("\n".join(problems))
    return rules, allow, warnings


def _load_rule_files(root: Path, files: List[Path], rs: RuleSet,
                     by_name: "OrderedDict[str, RuleDef]", label: str = "") -> None:
    for f in files:
        try:
            rules, allow, warns = parse_rule_document(_read_structured(f), f, root)
        except RuleError as exc:
            rs.errors.append(label + str(exc))
            continue
        except Exception as exc:
            rs.errors.append(f"{label}{f.name}: cannot parse ({exc.__class__.__name__}: {exc})")
            continue
        rs.files.append(label + str(f.relative_to(root)))
        rs.warnings.extend(label + w for w in warns)
        rs.allow_list |= allow
        for r in rules:
            r.source_file = label + r.source_file
            old = by_name.pop(r.name, None)
            if old and not old.source_file.startswith(BUNDLED_LABEL):  # overriding a default is expected
                rs.warnings.append(f"rule '{r.name}' from {r.source_file} overrides {old.source_file}")
            by_name[r.name] = r


def load_rules_dir(root: Path, strict: bool = False, bundled: bool = False) -> RuleSet:
    """Load every rule file under root (recursively). Later files override same-named rules.
    Load order: BUNDLED_RULES (if bundled), then remote/, then everything else (local wins)."""
    rs = RuleSet()
    by_name: "OrderedDict[str, RuleDef]" = OrderedDict()
    if bundled:
        # wordlist paths resolve relative to the rule file, so parse the defaults from a temp copy
        with tempfile.TemporaryDirectory(prefix="pii_shield_bundled_") as tmp:
            broot = Path(tmp)
            for rel, text in BUNDLED_RULES.items():
                (broot / rel).parent.mkdir(parents=True, exist_ok=True)
                (broot / rel).write_text(text, "utf-8")
            files = sorted(broot / rel for rel in BUNDLED_RULES if Path(rel).suffix.lower() in RULE_EXTENSIONS)
            _load_rule_files(broot, files, rs, by_name, BUNDLED_LABEL)
    if root.exists():
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in RULE_EXTENSIONS
                 and not p.name.startswith(".")]
        remote = root / "remote"
        files.sort(key=lambda p: (0 if remote in p.parents else 1, str(p)))
        _load_rule_files(root, files, rs, by_name)
    rs.rules = list(by_name.values())
    if strict and rs.errors:
        raise RuleError("\n".join(rs.errors))
    return rs


# Default rules embedded in the script: active on a fresh install, updated with the app,
# and overridden by any remote or local rule with the same name.
BUNDLED_LABEL = "bundled/"
# BEGIN BUNDLED RULES (generated by tools/bundle_rules.py from github-repo-template/rules/ - do not edit)
BUNDLED_RULES: Dict[str, str] = {
    "patterns.json": r"""{
  "version": 1,
  "recognizers": [
    {
      "name": "TicketIDs",
      "entity": "TICKET_ID",
      "description": "Internal ticketing references (JSON format example)",
      "score": 0.8,
      "patterns": [
        {"name": "jira", "regex": "\\b(?:SEC|IR|SOC)-\\d{3,6}\\b"}
      ]
    },
    {
      "name": "OnPremMailboxes",
      "entity": "EMAIL_ADDRESS",
      "deny_list": ["helpdesk@example-corp.com"],
      "score": 1.0
    }
  ]
}
""",
    "rules.yaml": r"""# =============================================================================
# PII Shield - shared custom recognizers (hosted on GitHub, pulled on demand)
# =============================================================================
# Schema (version 1)
#   allow_list:   [values that must NEVER be masked - matched case-insensitively]
#   recognizers:
#     - name:            unique rule name (later files / local rules override same name)
#       entity:          UPPER_SNAKE_CASE entity -> token prefix, e.g. HOSTNAME -> <HOSTNAME_1>
#       patterns:        list of {name, regex, score}  (Python 're' syntax)
#       deny_list:       list of literal values (whole-word match)
#       wordlist:        path(s) to .txt files, one value per line, relative to this file
#       context:         words that boost the score when found near a match (Presidio)
#       score:           0-1, default for patterns and the score for deny_list/wordlist hits
#       case_sensitive:  default false
#       validator:       optional: luhn | israeli_id | ipv4 | private_ipv4
#       enabled:         default true
#   A rule needs at least one of: patterns, deny_list, wordlist.
#   Validate before pushing:  python pii_sanitizer.py --validate-rules rules/
# =============================================================================
version: 1

allow_list:
  - localhost
  - 127.0.0.1
  - 0.0.0.0
  - example.com
  - Microsoft
  - Windows
  - PowerShell
  - CrowdStrike
  - Teudat
  - Python
  - Zehut

recognizers:

  # ---------------------------------------------------------------- network
  - name: InternalIPv4
    entity: INTERNAL_IP
    description: RFC1918 / loopback / link-local IPv4, optional CIDR suffix
    validator: private_ipv4
    score: 0.9
    patterns:
      - name: rfc1918
        regex: '(?<![\d.])(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){1,3}(?:/\d{1,2})?(?![\d.])'

  - name: InternalFQDN
    entity: HOSTNAME
    description: host.sub.domain in internal-only DNS suffixes (3+ labels = a host)
    score: 0.9
    patterns:
      - name: internal_host_fqdn
        regex: '\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})+\.(?:local|corp|lan|internal|intra|ad|home\.arpa)\b'

  - name: InternalADDomain
    entity: DOMAIN
    description: bare internal AD/DNS domain, e.g. acme.local, contoso.corp
    score: 0.9
    patterns:
      - name: internal_domain
        regex: '\b[a-z0-9][a-z0-9-]{0,62}\.(?:local|corp|lan|internal|intra|ad)\b'

  - name: HostNamingConvention
    entity: HOSTNAME
    description: Role-prefixed host names - SRV-APP01, DC-02, DC01, FS1, SQL03 (adjust prefixes to your estate)
    score: 0.85
    case_sensitive: true
    patterns:
      - name: prefix_separator
        regex: '\b(?:SRV|DC|WS|LT|PC|SQL|FS|EXCH|APP|WEB|VDI|RDS|ADFS|CA|ESX|HV|NAS|FW|SW|RTR|AP)[-_][A-Z0-9]{2,}(?:[-_][A-Z0-9]+)*\b'
      - name: prefix_digits
        regex: '\b(?:SRV|DC|WS|LT|PC|SQL|FS|EXCH|VDI|RDS|ADFS|ESX|HV|NAS|FW|RTR)\d{1,4}[A-Z]?\b'
    context: [server, host, hostname, machine, computer, endpoint, device]

  - name: HostRoleSuffix
    entity: HOSTNAME
    description: Role-suffixed host names - File-SRV, HR-DC, Backup-SQL01 (role must be UPPERCASE to avoid prose like file-server)
    score: 0.85
    case_sensitive: true
    patterns:
      - name: role_suffix
        regex: '\b[A-Za-z][A-Za-z0-9]{1,30}(?:[-_][A-Za-z0-9]+)*[-_](?:SRV|SVR|DC|FS|SQL|DB|EXCH|NAS|HV|ESX)\d{0,4}\b'
    context: [server, host, hostname, machine, from, on, to]

  - name: HostNumberedAnyCase
    entity: HOSTNAME
    description: Role prefix + 2-3 digits in any case - host223, ws54, srv01, dc02a (4 digits skipped so sql2019 stays a version)
    score: 0.8
    patterns:
      - name: prefix_2_3_digits
        regex: '(?<![\w.-])(?:host|server|srv|svr|dc|ws|pc|lt|vm|sql|db|fs|nas|fw|rtr|esx|hv|vdi|rds|exch|web|app)\d{2,3}[a-z]?(?![\w-])'
    context: [server, host, hostname, machine, computer, endpoint, device]

  - name: NetworkAppliances
    entity: HOSTNAME
    description: Vendor + model appliance host names - fortigate40d, FGT-60F, asa5506, synology918 (no space, so "FortiGate 40D" prose is skipped)
    score: 0.8
    patterns:
      - name: vendor_model
        regex: '(?<![\w.-])(?:forti(?:gate|wifi|switch|ap|analyzer|manager|mail|web)|fgt|fwf|paloalto|sonicwall|checkpoint|juniper|srx|asa|mikrotik|meraki|synology|qnap|unifi|aruba|netgear|cisco)[-_]?\d{2,5}[a-z]{0,3}(?![\w-])'
    context: [firewall, appliance, device, router, switch, nas, gateway, host]

  - name: InternalDomains
    entity: DOMAIN
    description: Customer / internal DNS domains from a wordlist
    score: 0.95
    wordlist: wordlists/internal_domains.txt

  # ---------------------------------------------------------------- identity
  - name: ADDownLevelLogon
    entity: USERNAME
    description: DOMAIN\user (down-level logon name)
    score: 0.9
    patterns:
      - name: domain_backslash_user
        regex: '(?<![\\:/\w.$-])[A-Za-z][A-Za-z0-9-]{1,14}\\[A-Za-z0-9._$-]{2,64}\b(?!\\)'

  - name: MachineAccount
    entity: HOSTNAME
    description: AD computer account names - dmizrahi$, WS54$ (skips the ADMIN$, IPC$, PRINT$ shares)
    score: 0.85
    patterns:
      - name: computer_account
        regex: '(?<![\w$\\-])(?!(?:ADMIN|IPC|PRINT)\$)[A-Za-z][A-Za-z0-9._-]{2,19}\$(?![\w$])'

  - name: KnownUsernames
    entity: USERNAME
    score: 0.9
    wordlist: wordlists/usernames.txt

  - name: WindowsProfilePath
    entity: USER_PATH
    description: C:\Users\<name>\... paths leak usernames
    score: 0.85
    patterns:
      - name: user_profile
        regex: '\b[A-Za-z]:\\Users\\(?!Public\b|Default\b|All Users\b)[^\\\s"''<>|]+'

  - name: UNCPath
    entity: UNC_PATH
    score: 0.85
    patterns:
      - name: unc
        regex: '\\\\[A-Za-z0-9._$-]+\\[^\s"''<>|]+'

  - name: CustomerNames
    entity: CUSTOMER
    score: 0.95
    wordlist: wordlists/customers.txt

  # ---------------------------------------------------------------- cloud / EDR identifiers
  - name: AzureGuidInContext
    entity: TENANT_ID
    description: GUIDs only flagged when tenant/subscription/client context is nearby (base score below threshold)
    score: 0.3
    patterns:
      - name: guid
        regex: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    context: [tenant, tenantid, subscription, client, clientid, application, appid, directory, object]

  - name: CrowdStrikeCID
    entity: CS_CID
    description: Falcon Customer ID with checksum suffix
    score: 0.9
    patterns:
      - name: cid
        regex: '\b[0-9a-fA-F]{32}-[0-9a-fA-F]{2}\b'
    context: [cid, customer, falcon, crowdstrike, ccid]

  # ---------------------------------------------------------------- secrets
  - name: CloudAndDevTokens
    entity: SECRET
    score: 0.95
    case_sensitive: true
    patterns:
      - {name: aws_access_key, regex: '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'}
      - {name: github_token,   regex: '\bgh[pousr]_[A-Za-z0-9]{36,}\b'}
      - {name: github_pat,     regex: '\bgithub_pat_[A-Za-z0-9_]{22,}\b'}
      - {name: slack_token,    regex: '\bxox[abposr]-[A-Za-z0-9-]{10,}\b'}
      - {name: jwt,            regex: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'}
      - {name: azure_conn_key, regex: '(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}'}
      - {name: private_key,    regex: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'}

  - name: CredentialAssignment
    entity: SECRET
    description: key=value credentials in configs/logs (the whole "password=..." span is masked)
    score: 0.85
    patterns:
      - name: kv_secret
        regex: '(?:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|token)\s*[:=]\s*["'']?[^\s"'',;]{6,}'

  - name: NTLMHashPair
    entity: SECRET
    score: 0.9
    patterns:
      - name: lm_nt
        regex: '\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b'

  # ---------------------------------------------------------------- addresses / organizations
  - name: StreetAddressInContext
    entity: STREET_ADDRESS
    description: "Street + number (Rothschild 1, Herzl St 12) - base score below threshold, flagged only near address words"
    score: 0.3
    patterns:
      - name: street_number
        regex: '\b[A-Z][a-z]{2,}(?:\s[A-Z][a-z]+){0,2}(?:\s(?:St|Street|Rd|Road|Ave|Avenue|Blvd|Lane|Ln|Way))?\.?\s\d{1,4}[A-Za-z]?\b'
      - name: hebrew_street
        regex: '(?:רחוב|רח''|שד''|שדרות)\s[\u0590-\u05FF"''\s]{2,30}\s\d{1,4}'
    context: [live, lives, living, address, street, road, located, apartment, residence, רחוב, כתובת, גר, גרה]

  - name: OrganizationNames
    entity: ORGANIZATION
    description: Our own company and partner names (spaCy ORG detection also available in Settings)
    score: 0.95
    wordlist: wordlists/organizations.txt

  # ---------------------------------------------------------------- Israel
  - name: IsraeliID
    entity: IL_ID
    description: Teudat Zehut - 9 digits, checksum validated
    validator: israeli_id
    score: 0.6
    patterns:
      - name: tz
        regex: '(?<!\d)\d{9}(?!\d)'
    context: [id, "t.z", teudat, zehut, ת.ז, תעודת, זהות]

  - name: IsraeliPhone
    entity: PHONE_NUMBER
    score: 0.75
    patterns:
      - name: il_phone
        regex: '(?<![\d+])(?:\+972[-\s]?|0)(?:5\d|[23489]|7\d)[-\s]?\d{3}[-\s]?\d{4}(?!\d)'
""",
    "wordlists/customers.txt": r"""# Customer / project code names (whole-word, case-insensitive)
Contoso
Fabrikam
Project Nightjar
""",
    "wordlists/internal_domains.txt": r"""# One domain per line. Lines starting with # are comments.
example-corp.com
contoso.local
fabrikam.internal
""",
    "wordlists/organizations.txt": r"""# Company / organization names to always mask (whole-word, case-insensitive)
Tenroot Cybersecurity
Tenroot
""",
    "wordlists/usernames.txt": r"""# Service / admin account names that must never reach an LLM
svc_backup
svc_sql
adm-jdoe
""",
}
# END BUNDLED RULES


def append_rule_to_file(path: Path, rule: Dict) -> None:
    """Persist a rule (e.g. a promoted manual rule) into a local YAML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"version": 1, "recognizers": []}
    if path.exists():
        doc = _read_structured(path) or doc
        doc.setdefault("recognizers", [])
    doc["recognizers"] = [r for r in doc["recognizers"] if r.get("name") != rule["name"]] + [rule]
    parse_rule_document(doc, path, path.parent)  # validate before writing
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), "utf-8")


def add_to_allow_list(values: Iterable[str], path: Path = ALLOW_LIST_FILE) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"version": 1, "allow_list": []}
    if path.exists():
        doc = _read_structured(path) or doc
    current = [str(x) for x in _as_list(doc.get("allow_list"))]
    seen = {x.casefold() for x in current}
    added = 0
    for v in values:
        if v.casefold() not in seen:
            current.append(v)
            seen.add(v.casefold())
            added += 1
    doc["allow_list"] = current
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), "utf-8")
    return added


# ===========================================================================
# 3. Matching helpers
# ===========================================================================
_HOSTCHARS = r"[\w\-]"


def wildcard_to_regex(pattern: str) -> str:
    """SRV-*  -> SRV-DC01, SRV-DC01.corp.local ;  *.corp -> a.b.corp ;  ? = one char."""
    seg = _HOSTCHARS + r"+(?:\." + _HOSTCHARS + r"+)*"
    out = []
    for ch in pattern.strip():
        if ch == "*":
            out.append(seg)
        elif ch == "?":
            out.append(_HOSTCHARS)
        else:
            out.append(re.escape(ch))
    return r"(?<![\w\-])" + "".join(out) + r"(?![\w\-])"


def literal_to_regex(term: str) -> str:
    pre = r"(?<!\w)" if term[:1].isalnum() or term[:1] == "_" else ""
    post = r"(?!\w)" if term[-1:].isalnum() or term[-1:] == "_" else ""
    return pre + re.escape(term) + post


@dataclass
class ManualRule:
    match_type: str          # "exact" | "wildcard" | "regex"
    pattern: str
    entity: str
    case_insensitive: bool = True
    rid: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    @property
    def label(self) -> str:
        return f"[{self.match_type}] {self.pattern} -> {self.entity}"

    def compile(self) -> "re.Pattern":
        if self.match_type == "exact":
            rx = literal_to_regex(self.pattern)
        elif self.match_type == "wildcard":
            rx = wildcard_to_regex(self.pattern)
        else:
            rx = self.pattern
        return re.compile(rx, re.IGNORECASE if self.case_insensitive else 0)

    def to_rule_yaml(self) -> Dict:
        name = f"manual_{self.entity.lower()}_{hashlib.sha1(self.pattern.encode()).hexdigest()[:8]}"
        rule = {"name": name, "entity": self.entity, "score": 0.95,
                "case_sensitive": not self.case_insensitive,
                "description": f"Promoted from manual {self.match_type} rule"}
        if self.match_type == "exact":
            rule["deny_list"] = [self.pattern]
        else:
            rx = wildcard_to_regex(self.pattern) if self.match_type == "wildcard" else self.pattern
            rule["patterns"] = [{"name": name, "regex": rx, "score": 0.95}]
        return rule


@dataclass
class Finding:
    start: int
    end: int
    text: str
    entity: str
    score: float
    source: str                 # presidio | custom | manual | propagated | session
    recognizer: str = ""
    enabled: bool = True
    token: str = ""
    token_edited: bool = False

    @property
    def length(self) -> int:
        return self.end - self.start


SOURCE_PRIORITY = {"manual": 3, "custom": 2, "session": 2, "presidio": 1, "propagated": 0}


def resolve_overlaps(findings: List[Finding]) -> List[Finding]:
    """Greedy non-overlapping selection: manual > custom/session > presidio > propagated,
    then the longer span (fs01.corp.local beats corp.local), then the higher score."""
    ranked = sorted(findings, key=lambda f: (-SOURCE_PRIORITY.get(f.source, 1), -f.length,
                                              -round(f.score, 3), f.start))
    taken: List[Tuple[int, int]] = []
    keep: List[Finding] = []
    for f in ranked:
        if f.length <= 0:
            continue
        if any(f.start < e and s < f.end for s, e in taken):
            continue
        taken.append((f.start, f.end))
        keep.append(f)
    return sorted(keep, key=lambda f: f.start)


def find_literal(text: str, value: str, case_insensitive: bool) -> Iterable[Tuple[int, int]]:
    if not value.strip():
        return []
    rx = re.compile(literal_to_regex(value), re.IGNORECASE if case_insensitive else 0)
    return [(m.start(), m.end()) for m in rx.finditer(text)]


# ===========================================================================
# 4. Session vault (token <-> raw value), in memory only
# ===========================================================================
class TokenCollision(Exception):
    pass


class SessionVault:
    def __init__(self, token_format: str = "<{entity}_{n}>", case_insensitive: bool = True):
        self.token_format = token_format
        self.case_insensitive = case_insensitive
        self.clear()

    def clear(self) -> None:
        self.key_to_token: Dict[str, str] = {}
        self.token_to_value: Dict[str, str] = {}   # includes aliases (old tokens after a rename)
        self.token_entity: Dict[str, str] = {}
        self.counters: Dict[str, int] = defaultdict(int)
        self.created: Dict[str, str] = {}

    # ---- helpers
    def key(self, value: str) -> str:
        return value.casefold() if self.case_insensitive else value

    def make_token(self, entity: str, n: int) -> str:
        return self.token_format.replace("{entity}", entity).replace("{n}", str(n))

    def _token_number(self, token: str, entity: str) -> Optional[int]:
        rx = re.escape(self.token_format).replace(re.escape("{entity}"), re.escape(entity)).replace(re.escape("{n}"), r"(\d+)")
        m = re.fullmatch(rx, token)
        return int(m.group(1)) if m else None

    def lookup(self, value: str) -> Optional[str]:
        return self.key_to_token.get(self.key(value))

    def owner_of(self, token: str) -> Optional[str]:
        v = self.token_to_value.get(token)
        return None if v is None else self.key(v)

    @property
    def active_tokens(self) -> Dict[str, str]:
        """token -> value for current (non-alias) tokens."""
        return {t: self.token_to_value[t] for t in self.key_to_token.values()}

    def __len__(self) -> int:
        return len(self.key_to_token)

    # ---- proposals (no mutation) and commits
    def propose(self, value: str, entity: str, pending: Dict[str, str]) -> str:
        k = self.key(value)
        if k in self.key_to_token:
            return self.key_to_token[k]
        if k in pending:
            return pending[k]
        used = set(self.token_to_value) | set(pending.values())
        n = self.counters[entity] + 1
        while self.make_token(entity, n) in used:
            n += 1
        tok = self.make_token(entity, n)
        pending[k] = tok
        return tok

    def check(self, value: str, token: str) -> None:
        owner = self.owner_of(token)
        if owner is not None and owner != self.key(value):
            raise TokenCollision(f"token {token} is already assigned to a different value")

    def commit(self, value: str, token: str, entity: str) -> None:
        self.check(value, token)
        k = self.key(value)
        old = self.key_to_token.get(k)
        self.key_to_token[k] = token            # old token remains as an alias for restore
        self.token_to_value.setdefault(token, value)
        self.token_entity[token] = entity
        self.created.setdefault(token, _dt.datetime.now().strftime("%H:%M:%S"))
        n = self._token_number(token, entity)
        if n is not None:
            self.counters[entity] = max(self.counters[entity], n)
        if old and old != token:
            log.info("token renamed (old token kept as restore alias)")

    # ---- restore
    def restore(self, text: str, lenient: bool = True) -> Tuple[str, int, List[str]]:
        if not self.token_to_value:
            return text, 0, sorted(set(re.findall(r"<[A-Z][A-Z0-9_]*_\d+>", text)))
        tokens = sorted(self.token_to_value, key=len, reverse=True)
        count = 0
        exact_alt = "|".join(map(re.escape, tokens))
        if lenient:
            core_of: Dict[str, str] = {}
            for t in tokens:
                core = re.sub(r"^\W+|\W+$", "", t) or t
                core_of.setdefault(core, t)
            c = "(?:" + "|".join(map(re.escape, sorted(core_of, key=len, reverse=True))) + ")"
            # every bracket style must be balanced, so a literal "\\" before "<TOKEN>" is never eaten
            rx = re.compile("(?P<exact>" + exact_alt + ")"
                            "|&lt;(?P<html>" + c + ")&gt;"
                            "|\\\\<(?P<md>" + c + ")\\\\>"
                            "|\\[(?P<sq>" + c + ")\\]"
                            "|\\{\\{(?P<dbl>" + c + ")\\}\\}"
                            "|\\{(?P<cur>" + c + ")\\}"
                            "|(?<![\\w])(?P<bare>" + c + ")(?![\\w])")

            def rep(m):
                g = m.lastgroup
                if g == "exact":
                    return self.token_to_value[m.group("exact")]
                return self.token_to_value[core_of[m.group(g)]]
            out, count = rx.subn(rep, text)
        else:
            out, count = re.subn(exact_alt, lambda m: self.token_to_value[m.group(0)], text)
        unknown = sorted({t for t in re.findall(r"<[A-Z][A-Z0-9_]*_\d+>", out)})
        return out, count, unknown

    # ---- export / import (contains raw values!)
    def export(self) -> Dict:
        return {"app": APP_ID, "version": __version__, "token_format": self.token_format,
                "case_insensitive": self.case_insensitive,
                "entries": [{"token": t, "value": v, "entity": self.token_entity.get(t, ""),
                             "active": self.key_to_token.get(self.key(v)) == t}
                            for t, v in self.token_to_value.items()]}

    def import_(self, data: Dict) -> int:
        n = 0
        for e in data.get("entries", []):
            if e.get("active", True):
                self.commit(e["value"], e["token"], e.get("entity", "CUSTOM"))
            else:
                self.token_to_value.setdefault(e["token"], e["value"])
            n += 1
        return n


# ===========================================================================
# 5. Detection engine (Presidio + spaCy, hot-reloadable)
# ===========================================================================
try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_OK = True
    PRESIDIO_ERR = ""
except Exception as _exc:  # pragma: no cover
    PRESIDIO_OK = False
    PRESIDIO_ERR = f"{_exc.__class__.__name__}: {_exc}"

try:
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig, RecognizerResult as AnonResult
    ANONYMIZER_OK = True
except Exception:  # pragma: no cover
    ANONYMIZER_OK = False

# ---------------------------------------------------------------------------
# Offline guarantees
# ---------------------------------------------------------------------------
def _force_offline_tldextract() -> None:
    """Presidio's EMAIL recognizer uses tldextract, which by default downloads the Public
    Suffix List on first use. Pin it to the bundled snapshot so no request is ever made."""
    try:
        import tldextract
        import tldextract.tldextract as _tx
        _tx.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                                  fallback_to_snapshot=True)
    except Exception:
        pass


_force_offline_tldextract()

_NET = threading.local()
NETWORK_GUARD = {"enabled": True, "blocked": 0}


def _network_audit_hook(event: str, args) -> None:
    """Python audit hook: sockets may only be opened from code explicitly running inside
    allow_network() (the GitHub sync and the PyPI update check). Everything else - analysis, anonymization,
    any third-party library - is blocked from touching the network."""
    if event in ("socket.connect", "socket.getaddrinfo", "socket.sendto") and NETWORK_GUARD["enabled"]:
        if not getattr(_NET, "allowed", False):
            NETWORK_GUARD["blocked"] += 1
            raise PermissionError(f"{APP_NAME} network guard: outbound connection blocked")


class allow_network:
    """Context manager that permits sockets for the current thread only."""

    def __enter__(self):
        self._prev = getattr(_NET, "allowed", False)
        _NET.allowed = True

    def __exit__(self, *exc):
        _NET.allowed = self._prev
        return False


def install_network_guard() -> None:
    if not getattr(sys, "_pii_shield_guard", False):
        sys.addaudithook(_network_audit_hook)
        sys._pii_shield_guard = True


SPACY_CANDIDATES = ["en_core_web_lg", "en_core_web_trf", "en_core_web_md", "en_core_web_sm"]


def installed_spacy_models() -> List[str]:
    try:
        import spacy.util
        return [m for m in SPACY_CANDIDATES if spacy.util.is_package(m)]
    except Exception:
        return []


if PRESIDIO_OK:
    class ValidatedPatternRecognizer(PatternRecognizer):
        """PatternRecognizer with an optional checksum/semantic validator from VALIDATORS."""

        def __init__(self, *args, validator: Optional[str] = None, **kwargs):
            self._validator = VALIDATORS.get(validator) if validator else None
            super().__init__(*args, **kwargs)

        def validate_result(self, pattern_text: str) -> Optional[bool]:
            return self._validator(pattern_text) if self._validator else None


class DetectionEngine:
    """Owns the (expensive) NLP engine once; recognizer registries are rebuilt on hot reload."""

    def __init__(self, config: AppConfig, rules_root: Path = RULES_DIR):
        self.config = config
        self.rules_root = rules_root
        self.lock = threading.RLock()
        self.nlp_engine = None
        self.analyzer = None
        self.model_name: Optional[str] = None
        self.mode = "uninitialized"       # presidio+spacy | presidio-regex-only | lite
        self.ruleset = RuleSet()
        self.builtin_supported: List[str] = []

    # ---- lifecycle
    def initialize(self, progress: Callable[[str], None] = lambda s: None) -> str:
        with self.lock:
            if not PRESIDIO_OK:
                self.mode = "lite"
                progress(f"Presidio not available ({PRESIDIO_ERR}); regex-only lite mode")
                self.reload_rules()
                return self.mode
            ecfg = self.config["engine"]
            wanted = ecfg.get("spacy_model") or "en_core_web_lg"
            installed = installed_spacy_models()
            # NEVER let Presidio auto-download a model: pick only installed ones.
            model = wanted if wanted in installed else (installed[0] if installed else None)
            if model:
                progress(f"Loading spaCy model {model} (offline)...")
                ignore = ["CARDINAL", "EVENT", "LANGUAGE", "LAW", "MONEY", "ORDINAL",
                          "PERCENT", "PRODUCT", "QUANTITY", "WORK_OF_ART"]
                if not ecfg.get("detect_organizations"):
                    ignore += ["ORG", "ORGANIZATION"]
                nlp_conf = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model}],
                    "ner_model_configuration": {
                        "model_to_presidio_entity_mapping": {
                            "PER": "PERSON", "PERSON": "PERSON", "NORP": "NRP", "FAC": "LOCATION",
                            "LOC": "LOCATION", "LOCATION": "LOCATION", "GPE": "LOCATION",
                            "ORG": "ORGANIZATION", "ORGANIZATION": "ORGANIZATION",
                            "DATE": "DATE_TIME", "TIME": "DATE_TIME"},
                        "low_confidence_score_multiplier": 0.4,
                        "low_score_entity_names": [],
                        "labels_to_ignore": ignore,
                    },
                }
                self.nlp_engine = NlpEngineProvider(nlp_configuration=nlp_conf).create_engine()
                self.model_name = model
                self.mode = "presidio+spacy"
                if model != wanted:
                    progress(f"Requested model {wanted} not installed - using {model}")
            else:
                from presidio_analyzer.nlp_engine import NoOpNlpEngine
                self.nlp_engine = NoOpNlpEngine()
                self.model_name = None
                self.mode = "presidio-regex-only"
                progress("No spaCy model installed - NER (names/locations) disabled. "
                         "Run: python -m spacy download en_core_web_lg")
            self.reload_rules()
            return self.mode

    def _build_registry(self, rs: RuleSet):
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(languages=["en"], nlp_engine=self.nlp_engine)
        if self.mode == "presidio-regex-only":
            for rec in list(registry.recognizers):
                if rec.__class__.__name__ in ("SpacyRecognizer", "StanzaRecognizer", "TransformersRecognizer"):
                    registry.recognizers.remove(rec)
        for r in rs.rules:
            kw = dict(supported_entity=r.entity, name=r.name, supported_language="en",
                      context=r.context or None, global_regex_flags=r.flags)
            if r.patterns:
                registry.add_recognizer(ValidatedPatternRecognizer(
                    patterns=[Pattern(p.name, p.regex, p.score) for p in r.patterns],
                    validator=r.validator, **kw))
            if r.deny_list:
                registry.add_recognizer(ValidatedPatternRecognizer(
                    deny_list=r.deny_list, deny_list_score=r.score, validator=r.validator,
                    **{**kw, "name": r.name + "_wordlist"}))
        return registry

    def dry_run(self, root: Path) -> RuleSet:
        """Strictly validate a rules folder and prove the recognizers can be built."""
        rs = load_rules_dir(root, strict=True)
        if PRESIDIO_OK and self.nlp_engine is not None:
            self._build_registry(rs)
        return rs

    def reload_rules(self) -> RuleSet:
        """Hot reload: re-read rule files and atomically swap the analyzer."""
        rs = load_rules_dir(self.rules_root, bundled=True)
        if PRESIDIO_OK and self.nlp_engine is not None:
            registry = self._build_registry(rs)
            analyzer = AnalyzerEngine(registry=registry, nlp_engine=self.nlp_engine,
                                      supported_languages=["en"])
            builtin = sorted(set(analyzer.get_supported_entities("en")) - set(rs.entities))
            with self.lock:
                self.analyzer, self.ruleset, self.builtin_supported = analyzer, rs, builtin
        else:
            with self.lock:
                self.ruleset = rs
        log.info("rules reloaded: %d recognizers from %d files, %d errors",
                 len(rs.rules), len(rs.files), len(rs.errors))
        return rs

    # ---- analysis
    def _lite_detect(self, text: str, rs: RuleSet) -> List[Finding]:
        out = []
        for r in rs.rules:
            vfn = VALIDATORS.get(r.validator) if r.validator else None
            regexes = [(re.compile(p.regex, r.flags), p.score) for p in r.patterns]
            if r.deny_list:
                regexes.append((re.compile(r"(?:^|(?<=\W))(" + "|".join(map(re.escape, r.deny_list)) +
                                           r")(?:(?=\W)|$)", r.flags), r.score))
            for rx, score in regexes:
                for m in rx.finditer(text):
                    if m.end() > m.start() and (not vfn or vfn(m.group(0))):
                        out.append(Finding(m.start(), m.end(), m.group(0), r.entity, score, "custom", r.name))
        return out

    def analyze(self, text: str, manual_rules: Sequence[ManualRule], vault: SessionVault,
                threshold: Optional[float] = None) -> List[Finding]:
        with self.lock:
            analyzer, rs = self.analyzer, self.ruleset
        ecfg, bcfg = self.config["engine"], self.config["behavior"]
        threshold = ecfg.get("score_threshold", 0.35) if threshold is None else threshold
        custom_names = {r.name for r in rs.rules} | {r.name + "_wordlist" for r in rs.rules}
        found: List[Finding] = []

        if analyzer is not None:
            entities = sorted(set(ecfg.get("builtin_entities", [])) | set(rs.entities))
            results = analyzer.analyze(text=text, language="en", entities=entities or None,
                                       score_threshold=threshold)
            for r in results:
                rname = (r.recognition_metadata or {}).get("recognizer_name", "")
                src = "custom" if rname in custom_names else "presidio"
                found.append(Finding(r.start, r.end, text[r.start:r.end], r.entity_type,
                                     float(r.score), src, rname))
        else:
            found.extend(f for f in self._lite_detect(text, rs) if f.score >= threshold)

        # manual on-the-fly rules
        for mr in manual_rules:
            try:
                rx = mr.compile()
            except re.error:
                continue
            for i, m in enumerate(rx.finditer(text)):
                if i > 5000:
                    break
                if m.end() > m.start():
                    found.append(Finding(m.start(), m.end(), m.group(0), mr.entity, 1.0, "manual",
                                         f"manual:{mr.rid}"))

        # allow-list (never applies to manual rules)
        allow = rs.allow_list
        found = [f for f in found if f.source == "manual" or f.text.strip().casefold() not in allow]
        found = resolve_overlaps(found)

        # propagation: every literal occurrence of a detected value or a value already in the session map
        if bcfg.get("propagate_values", True):
            ci = bcfg.get("case_insensitive_values", True)
            values: Dict[str, Tuple[str, float]] = {}
            for f in found:
                values.setdefault(vault.key(f.text), (f.text, f.entity))
            extra: List[Finding] = []
            for k, (v, ent) in values.items():
                for s, e in find_literal(text, v, ci):
                    extra.append(Finding(s, e, text[s:e], ent, 0.5, "propagated", "value-propagation"))
            for tok, v in vault.active_tokens.items():
                if v.casefold() in allow:
                    continue
                for s, e in find_literal(text, v, ci):
                    extra.append(Finding(s, e, text[s:e], vault.token_entity.get(tok, "CUSTOM"), 0.99,
                                         "session", "session-map"))
            found = resolve_overlaps(found + extra)

        # entity consistency for identical values, then token proposals
        entity_for: Dict[str, str] = {}
        for f in found:
            entity_for.setdefault(vault.key(f.text), f.entity)
        pending: Dict[str, str] = {}
        for f in found:
            f.entity = entity_for[vault.key(f.text)]
            f.token = vault.propose(f.text, f.entity, pending)
        return found


# ===========================================================================
# 6. Sanitize / leak check
# ===========================================================================
def sanitize(text: str, findings: Sequence[Finding], vault: SessionVault) -> Tuple[str, List[Finding]]:
    """Replace enabled findings with their tokens and commit them to the session map."""
    enabled = resolve_overlaps([f for f in findings if f.enabled and f.token.strip()])
    # 1) validate the whole selection before mutating the vault
    chosen: Dict[str, str] = {}
    for f in enabled:
        k = vault.key(f.text)
        if k in chosen and chosen[k] != f.token:
            raise TokenCollision(f"one value has two different tokens ({chosen[k]} / {f.token})")
        chosen[k] = f.token
    owners: Dict[str, str] = {}
    for f in enabled:
        k = vault.key(f.text)
        if owners.setdefault(f.token, k) != k:
            raise TokenCollision(f"token {f.token} is assigned to two different values")
        vault.check(f.text, f.token)
    # 2) commit
    for f in enabled:
        vault.commit(f.text, f.token, f.entity)
    # 3) replace
    if ANONYMIZER_OK and enabled:
        # one synthetic entity type per finding: prevents Presidio from merging adjacent spans
        results, ops = [], {}
        for i, f in enumerate(enabled):
            et = f"F{i}"
            results.append(AnonResult(entity_type=et, start=f.start, end=f.end, score=1.0))
            ops[et] = OperatorConfig("replace", {"new_value": f.token})
        out = AnonymizerEngine().anonymize(text=text, analyzer_results=results, operators=ops).text
    else:
        out = splice(text, enabled)
    return out, enabled


def splice(text: str, findings: Sequence[Finding]) -> str:
    parts, pos = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        parts.append(text[pos:f.start])
        parts.append(f.token)
        pos = f.end
    parts.append(text[pos:])
    return "".join(parts)


def leak_check(output: str, vault: SessionVault, extra_values: Iterable[str] = ()) -> List[str]:
    """Return raw values (len>=3) from the session that still appear in the sanitized output."""
    values = {v for v in list(vault.token_to_value.values()) + list(extra_values) if len(v.strip()) >= 3}
    tokens = set(vault.token_to_value)
    leaks = []
    for v in sorted(values, key=len, reverse=True):
        if v in tokens:
            continue
        if find_literal(output, v, True):
            leaks.append(v)
    return leaks


# ===========================================================================
# 7. GitHub rules sync
# ===========================================================================
class SyncError(Exception):
    pass


@dataclass
class RemoteFile:
    path: str       # relative to the configured rules folder
    sha: str        # git blob sha from the listing
    size: int
    api_url: str


@dataclass
class SyncPlan:
    files: List[RemoteFile]
    added: List[str]
    changed: List[str]
    removed: List[str]
    unchanged: List[str]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.changed or self.removed)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def parse_version(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4]) or (0,)


def normalize_repo_url(url: str) -> Tuple[str, str, str]:
    """Return (api_base, 'owner/repo', path). Accepts:
       https://api.github.com/repos/o/r/contents/rules
       https://github.com/o/r/tree/main/rules     https://github.com/o/r
       https://ghe.corp/api/v3/repos/o/r/contents/rules      o/r/rules"""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise SyncError("Repository URL is empty")
    if not url.startswith("http"):
        parts = url.split("/")
        if len(parts) < 2:
            raise SyncError("Use owner/repo[/path] or a full URL")
        return "https://api.github.com", f"{parts[0]}/{parts[1]}", "/".join(parts[2:])
    u = urlparse(url)
    if u.scheme != "https":
        raise SyncError("Only https:// URLs are allowed")
    m = re.match(r"^(.*?)/repos/([^/]+)/([^/]+)(?:/contents/?(.*))?$", u.path)
    if m:
        return f"https://{u.netloc}{m.group(1)}", f"{m.group(2)}/{m.group(3)}", m.group(4) or ""
    m = re.match(r"^/([^/]+)/([^/]+?)(?:\.git)?(?:/(?:tree|blob)/[^/]+(?:/(.*))?)?$", u.path)
    if m and u.netloc in ("github.com", "www.github.com"):
        return "https://api.github.com", f"{m.group(1)}/{m.group(2)}", m.group(3) or ""
    if m:  # GitHub Enterprise web URL
        return f"https://{u.netloc}/api/v3", f"{m.group(1)}/{m.group(2)}", m.group(3) or ""
    raise SyncError("Unrecognized GitHub URL")


SYNC_LOCK = threading.Lock()   # one rules pull at a time (startup sync vs. the sync dialog)


class GitHubSync:
    MAX_FILES = 500
    MAX_FILE_BYTES = 5 * 1024 * 1024
    MAX_DEPTH = 6

    def __init__(self, config: AppConfig, token: str = "", engine: Optional[DetectionEngine] = None,
                 rules_root: Path = RULES_DIR, progress: Callable[[str], None] = lambda s: None):
        import requests  # imported lazily: the app never needs the network otherwise
        self.requests = requests
        self.cfg = config["github"]
        if config["behavior"].get("offline_mode"):
            raise SyncError("Offline mode is enabled - GitHub sync is disabled")
        self.engine = engine
        self.rules_root = rules_root
        self.remote_dir = rules_root / "remote"
        self.progress = progress
        self.api_base, self.repo, self.path = normalize_repo_url(self.cfg.get("repo_url", ""))
        self.host = urlparse(self.api_base).netloc
        self.branch = (self.cfg.get("branch") or "main").strip()
        self.timeout = int(self.cfg.get("timeout", 20))
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28",
                               "User-Agent": f"{APP_ID}/{__version__}"})
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        ca = (self.cfg.get("ca_bundle") or "").strip()
        self.verify = ca if ca else True

    # ---- HTTP
    def _get(self, url: str, raw: bool = False):
        if urlparse(url).netloc != self.host:   # never send the PAT to another host
            raise SyncError("Refusing to follow a URL on a different host")
        headers = {"Accept": "application/vnd.github.raw"} if raw else {}
        try:
            with allow_network():   # with check_package_updates, the only code allowed to open a socket
                r = self.s.get(url, headers=headers, timeout=self.timeout, verify=self.verify,
                               params={"ref": self.branch}, allow_redirects=False)
        except self.requests.exceptions.SSLError as exc:
            raise SyncError(f"TLS error (set a CA bundle in settings if behind an inspecting proxy): {exc}")
        except self.requests.exceptions.RequestException as exc:
            raise SyncError(f"Network error: {exc}")
        if r.status_code in (301, 302, 307, 308):
            raise SyncError("Repository redirected (renamed/moved?) - update the URL")
        if r.status_code == 401:
            raise SyncError("401 Unauthorized - check the Personal Access Token")
        if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            raise SyncError("GitHub API rate limit reached - add a PAT or wait")
        if r.status_code == 404:
            raise SyncError("404 Not found - check URL, branch/tag, and PAT access to the repo")
        if r.status_code >= 400:
            raise SyncError(f"GitHub API error {r.status_code}: {r.text[:200]}")
        return r

    def contents_url(self, path: str) -> str:
        return f"{self.api_base}/repos/{self.repo}/contents/{quote(path.strip('/'))}"

    def test_connection(self) -> str:
        r = self._get(f"{self.api_base}/repos/{self.repo}")
        info = r.json()
        return f"OK - {info.get('full_name')} ({'private' if info.get('private') else 'public'}), " \
               f"default branch '{info.get('default_branch')}'"

    def list_remote(self) -> List[RemoteFile]:
        out: List[RemoteFile] = []

        def walk(path: str, rel: str, depth: int):
            if depth > self.MAX_DEPTH:
                raise SyncError("Remote folder nesting too deep")
            items = self._get(self.contents_url(path)).json()
            if isinstance(items, dict):     # path points at a single file
                items = [items]
            for it in items:
                name = it.get("name", "")
                if name.startswith(".") or "/" in name or "\\" in name or name in ("..", "."):
                    continue
                r = f"{rel}/{name}" if rel else name
                if it.get("type") == "dir":
                    walk(it["path"], r, depth + 1)
                elif it.get("type") == "file" and Path(name).suffix.lower() in SYNC_EXTENSIONS:
                    if int(it.get("size", 0)) > self.MAX_FILE_BYTES:
                        raise SyncError(f"{r} exceeds {self.MAX_FILE_BYTES // 1024} KB")
                    out.append(RemoteFile(r, it["sha"], int(it.get("size", 0)), it["url"].split("?")[0]))
                    if len(out) > self.MAX_FILES:
                        raise SyncError("Too many files in remote rules folder")
        walk(self.path, "", 0)
        return out

    def _manifest(self) -> Dict[str, str]:
        try:
            return json.loads((self.remote_dir / SYNC_MANIFEST).read_text("utf-8")).get("files", {})
        except Exception:
            return {}

    def plan(self) -> SyncPlan:
        self.progress(f"Listing {self.repo}/{self.path or ''} @ {self.branch} ...")
        files = self.list_remote()
        local = self._manifest()
        remote = {f.path: f.sha for f in files}
        added = sorted(p for p in remote if p not in local)
        changed = sorted(p for p in remote if p in local and local[p] != remote[p])
        unchanged = sorted(p for p in remote if p in local and local[p] == remote[p])
        removed = sorted(p for p in local if p not in remote)
        # locally tampered/missing files count as changed
        for p in list(unchanged):
            fp = self.remote_dir / p
            if not fp.exists() or git_blob_sha(fp.read_bytes()) != remote[p]:
                unchanged.remove(p)
                changed.append(p)
        return SyncPlan(files, added, sorted(changed), removed, unchanged)

    def pull(self, force: bool = False) -> Tuple[SyncPlan, RuleSet]:
        if not SYNC_LOCK.acquire(blocking=False):
            raise SyncError("Another rules sync is already running - try again in a moment")
        try:
            return self._pull(force)
        finally:
            SYNC_LOCK.release()

    def _pull(self, force: bool) -> Tuple[SyncPlan, RuleSet]:
        plan = self.plan()
        if not plan.has_changes and not force:
            self.progress("Already up to date.")
            return plan, self.engine.ruleset if self.engine else load_rules_dir(self.rules_root, bundled=True)
        staging_root = Path(tempfile.mkdtemp(prefix="pii_shield_sync_"))
        try:
            stage = staging_root / "remote"
            stage.mkdir()
            for f in plan.files:
                dest = (stage / f.path).resolve()
                if stage.resolve() not in dest.parents:
                    raise SyncError(f"Unsafe path in remote listing: {f.path}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if f.path in plan.unchanged:
                    shutil.copy2(self.remote_dir / f.path, dest)
                    continue
                self.progress(f"Downloading {f.path}")
                data = self._get(f.api_url, raw=True).content
                if git_blob_sha(data) != f.sha:
                    raise SyncError(f"Integrity check failed for {f.path} (git blob sha mismatch)")
                dest.write_bytes(data)
            # Validate the staged set together with the existing local rules
            self.progress("Validating downloaded rules ...")
            local_dir = self.rules_root / "local"
            if local_dir.exists():
                shutil.copytree(local_dir, staging_root / "local")
            try:
                if self.engine is not None:
                    self.engine.dry_run(staging_root)
                else:
                    load_rules_dir(staging_root, strict=True)
            except RuleError as exc:
                raise SyncError(f"Validation failed - nothing was applied:\n{exc}")
            except Exception as exc:
                raise SyncError(f"Recognizer build failed - nothing was applied: {exc}")
            (stage / SYNC_MANIFEST).write_text(json.dumps({
                "repo": self.repo, "path": self.path, "ref": self.branch,
                "synced_at": _dt.datetime.now().isoformat(timespec="seconds"),
                "files": {f.path: f.sha for f in plan.files}}, indent=2), "utf-8")
            # Atomic-ish swap with backup
            backup = None
            if self.remote_dir.exists():
                BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                backup = BACKUP_DIR / f"remote-{_dt.datetime.now():%Y%m%d-%H%M%S}"
                shutil.move(str(self.remote_dir), str(backup))
            shutil.move(str(stage), str(self.remote_dir))
            try:
                rs = self.engine.reload_rules() if self.engine else load_rules_dir(self.rules_root, bundled=True)
            except Exception as exc:
                shutil.rmtree(self.remote_dir, ignore_errors=True)
                if backup:
                    shutil.move(str(backup), str(self.remote_dir))
                    if self.engine:
                        self.engine.reload_rules()
                raise SyncError(f"Hot reload failed, previous rules restored: {exc}")
            self._prune_backups()
            self.progress(f"Applied: +{len(plan.added)} ~{len(plan.changed)} -{len(plan.removed)}")
            return plan, rs
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)

    @staticmethod
    def _prune_backups(keep: int = 5) -> None:
        if BACKUP_DIR.exists():
            old = sorted(BACKUP_DIR.glob("remote-*"))[:-keep]
            for p in old:
                shutil.rmtree(p, ignore_errors=True)

    # ---- application self-update (optional)
    def check_app_version(self) -> Optional[Dict]:
        vp = (self.cfg.get("version_path") or "").strip()
        if not vp:
            return None
        try:
            info = json.loads(self._get(self.contents_url(vp), raw=True).content.decode("utf-8"))
        except SyncError as exc:
            if "404" in str(exc):
                return None
            raise
        if not isinstance(info, dict) or "version" not in info:
            raise SyncError("version.json must contain a 'version' field")
        info["newer"] = parse_version(info["version"]) > parse_version(__version__)
        return info

    def install_app_update(self, info: Dict) -> Tuple[str, Path]:
        """("script", path): the .py was replaced - restart to use it.
        ("restart", path): the build was downloaded - run this updater script after the app exits."""
        if is_frozen():
            return "restart", download_windows_build(info, {"github": self.cfg}, pid=os.getpid())
        return "script", self.download_app_update(info)

    def download_app_update(self, info: Dict, target: Path = Path(__file__).resolve()) -> Path:
        script = info.get("script_path")
        expected = (info.get("sha256") or "").lower()
        if not script or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SyncError("version.json must provide 'script_path' and a 'sha256' for updates")
        data = self._get(self.contents_url(script), raw=True).content
        if hashlib.sha256(data).hexdigest() != expected:
            raise SyncError("SHA-256 mismatch - update rejected")
        try:
            compile(data, script, "exec")
        except SyntaxError as exc:
            raise SyncError(f"Downloaded script has a syntax error - update rejected: {exc}")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, BACKUP_DIR / f"{target.stem}-{__version__}{target.suffix}")
        tmp = target.with_suffix(".py.new")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        return target


# ===========================================================================
# 7. (cont.) Windows build update: verified release zip + updater script
# ===========================================================================
WINDOWS_EXE = "PII-Shield.exe"
WINDOWS_ZIP_ROOT = "PII-Shield"     # the release zip holds PII-Shield/PII-Shield.exe and PII-Shield/_internal/


def download_windows_build(info: Dict, config, app_dir: Optional[Path] = None, pid: Optional[int] = None,
                           progress: Callable[[str], None] = lambda s: None) -> Path:
    """Download the release zip named in version.json, verify its SHA-256, extract it under
    <app_dir>/updates/<version>/ and write the updater script. Returns the script path.
    The download is unauthenticated: the GitHub token never leaves the API host."""
    app_dir = app_dir or APP_DIR
    url = str(info.get("windows_zip_url") or "")
    expected = str(info.get("windows_zip_sha256") or "").lower()
    if not url or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SyncError("version.json has no Windows build (windows_zip_url and windows_zip_sha256) - "
                        "download the new release manually")
    if urlparse(url).scheme != "https":
        raise SyncError("windows_zip_url must use https")
    version = re.sub(r"[^0-9A-Za-z._-]", "_", str(info.get("version", "new")))
    updates = app_dir / "updates"
    dest = updates / version
    zpath = updates / f"{WINDOWS_ZIP_ROOT}-{version}.zip"
    shutil.rmtree(dest, ignore_errors=True)
    updates.mkdir(parents=True, exist_ok=True)
    import requests
    import zipfile
    g = config["github"]
    try:
        h = hashlib.sha256()
        progress(f"Downloading {url}")
        with allow_network():
            with requests.get(url, stream=True, timeout=int(g.get("timeout", 20)),
                              verify=(g.get("ca_bundle") or "").strip() or True,
                              headers={"User-Agent": f"{APP_ID}/{__version__}"}) as r:
                r.raise_for_status()
                with open(zpath, "wb") as fh:
                    for chunk in r.iter_content(1 << 20):
                        h.update(chunk)
                        fh.write(chunk)
        if h.hexdigest() != expected:
            raise SyncError("SHA-256 mismatch - update rejected")
        progress("Download verified - extracting")
        with zipfile.ZipFile(zpath) as z:
            root = dest.resolve()
            for name in z.namelist():
                target = (dest / name).resolve()
                if target != root and root not in target.parents:
                    raise SyncError(f"Zip contains an unsafe path - update rejected: {name}")
            z.extractall(dest)
        new = dest / WINDOWS_ZIP_ROOT
        if not (new / WINDOWS_EXE).is_file() or not (new / "_internal").is_dir():
            raise SyncError(f"Zip has no {WINDOWS_ZIP_ROOT}/{WINDOWS_EXE} and _internal/ - update rejected")
    except SyncError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise SyncError(f"Windows build download failed: {exc}")
    finally:
        zpath.unlink(missing_ok=True)
    return write_update_script(new, app_dir, os.getpid() if pid is None else pid)


def _ps_quote(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def write_update_script(new_dir: Path, app_dir: Path, pid: int) -> Path:
    """PowerShell updater: wait for the app to exit, swap PII-Shield.exe and _internal/ (rolling
    back on failure), restart. config.json, rules/ and backups/ are never touched."""
    script = app_dir / "updates" / "apply-update.ps1"
    script.write_text(f"""# Generated by {APP_NAME} {__version__} - installs the downloaded build, then restarts the app.
$ErrorActionPreference = 'Stop'
$procId = {int(pid)}
$app = {_ps_quote(app_dir)}
$new = {_ps_quote(new_dir)}
$exe = {_ps_quote(WINDOWS_EXE)}
Start-Transcript -Path (Join-Path $app 'updates\\update.log') -Append | Out-Null
Wait-Process -Id $procId -Timeout 120 -ErrorAction SilentlyContinue
if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {{ throw 'PII Shield is still running - update not installed' }}
$oldInternal = Join-Path $app '_internal.old'
$oldExe = Join-Path $app ($exe + '.old')
Remove-Item -Recurse -Force -LiteralPath $oldInternal, $oldExe -ErrorAction SilentlyContinue
Rename-Item -LiteralPath (Join-Path $app '_internal') -NewName '_internal.old'
Rename-Item -LiteralPath (Join-Path $app $exe) -NewName ($exe + '.old')
try {{
    Move-Item -LiteralPath (Join-Path $new '_internal') -Destination (Join-Path $app '_internal')
    Move-Item -LiteralPath (Join-Path $new $exe) -Destination (Join-Path $app $exe)
}} catch {{
    Remove-Item -Recurse -Force -LiteralPath (Join-Path $app '_internal'), (Join-Path $app $exe) -ErrorAction SilentlyContinue
    Rename-Item -LiteralPath $oldInternal -NewName '_internal'
    Rename-Item -LiteralPath $oldExe -NewName $exe
    Start-Process -FilePath (Join-Path $app $exe) -WorkingDirectory $app
    throw
}}
Remove-Item -Recurse -Force -LiteralPath $oldInternal, $oldExe, (Split-Path $new -Parent) -ErrorAction SilentlyContinue
Start-Process -FilePath (Join-Path $app $exe) -WorkingDirectory $app
Stop-Transcript | Out-Null
""", "utf-8")
    return script


def launch_update_script(script: Path) -> None:
    """Start the updater detached; the caller then quits so the files are no longer locked."""
    import subprocess
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                      "-File", str(script)], creationflags=flags, close_fds=True)


# ===========================================================================
# 7a. Startup updates (run in the background by the GUI, testable without Qt)
# ===========================================================================
PRESIDIO_PACKAGES = ("presidio-analyzer", "presidio-anonymizer")
PYPI_URL = "https://pypi.org/pypi"


def auto_sync_rules(config: AppConfig, token: str, engine: Optional[DetectionEngine] = None,
                    rules_root: Path = RULES_DIR) -> Optional[Tuple[SyncPlan, RuleSet]]:
    """Startup rules pull. Returns None, with no network traffic, when the sync is disabled,
    offline mode is on, or no repo is set. The pull itself is validated and atomic."""
    g = config["github"]
    if (not g.get("auto_sync_on_startup", True) or config["behavior"].get("offline_mode")
            or not (g.get("repo_url") or "").strip()):
        return None
    return GitHubSync(config, token, engine, rules_root).pull()


def auto_check_app_update(config: AppConfig, token: str) -> Optional[Dict]:
    """Startup app-version check against version.json in the rules repo. Returns None, with no
    network traffic, when check_app_updates is off, offline mode is on, or no repo is set;
    also None when the repo has no version.json. Installing stays a separate, confirmed step."""
    g = config["github"]
    if (not g.get("check_app_updates", True) or config["behavior"].get("offline_mode")
            or not (g.get("repo_url") or "").strip()):
        return None
    return GitHubSync(config, token).check_app_version()


def check_package_updates(config: AppConfig, packages: Sequence[str] = PRESIDIO_PACKAGES,
                          index_url: str = PYPI_URL) -> Optional[List[Dict]]:
    """Ask PyPI for the newest release of each package. Reports only - never installs anything.
    Returns None, with no network traffic, when the check is disabled or offline mode is on."""
    if not config["engine"].get("check_presidio_updates", True) or config["behavior"].get("offline_mode"):
        return None
    import requests
    from importlib import metadata
    verify = (config["github"].get("ca_bundle") or "").strip() or True
    timeout = int(config["github"].get("timeout", 20))
    out = []
    for pkg in packages:
        try:
            installed = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            installed = None
        try:
            with allow_network():   # sends only the package name; no prompt text, no token
                r = requests.get(f"{index_url}/{pkg}/json", timeout=timeout, verify=verify,
                                 allow_redirects=False, headers={"User-Agent": f"{APP_ID}/{__version__}"})
            r.raise_for_status()
            latest = str(r.json()["info"]["version"])
        except Exception as exc:
            raise SyncError(f"PyPI check for {pkg} failed: {exc}")
        out.append({"package": pkg, "installed": installed, "latest": latest,
                    "newer": installed is not None and parse_version(latest) > parse_version(installed)})
    return out


def presidio_update_hint(newer: Sequence[Dict], frozen: bool) -> str:
    """What the user can do about a newer Presidio: pip for a script install; the next
    release for the Windows build, which carries its own copy of Presidio."""
    if frozen:
        found = ", ".join(f"{r['package']} {r['latest']}" for r in newer)
        return f"Presidio update available ({found}) - it ships with the next new PII Shield release"
    return "Presidio update available - close the app and run: pip install -U " + " ".join(r["package"] for r in newer)


def self_test(engine: Optional[DetectionEngine] = None) -> Tuple[bool, List[str]]:
    """Load the real NLP engine with only the bundled rules and analyze a known sentence.
    Catches a build that is missing the spaCy model, Presidio config or rule data."""
    tmp = Path(tempfile.mkdtemp(prefix="pii_shield_selftest_"))
    try:
        if engine is None:
            engine = DetectionEngine(AppConfig(tmp / "config.json"), tmp / "rules")
        if engine.mode == "uninitialized":
            engine.initialize()
        text = "John Smith logged into SRV-DC01 from 10.20.30.40 as CORP\\jsmith."
        found = {(f.entity, f.text) for f in engine.analyze(text, [], SessionVault())}
        checks = [("engine mode presidio+spacy", engine.mode == "presidio+spacy"),
                  ("bundled rules loaded without errors", bool(engine.ruleset.rules) and not engine.ruleset.errors),
                  ("PERSON John Smith (spaCy NER)", ("PERSON", "John Smith") in found),
                  ("HOSTNAME SRV-DC01 (bundled rule)", ("HOSTNAME", "SRV-DC01") in found),
                  ("USERNAME CORP\\jsmith (bundled rule)", ("USERNAME", "CORP\\jsmith") in found)]
        lines = [f"{'ok  ' if ok else 'FAIL'}  {name}" for name, ok in checks]
        ok = all(ok for _, ok in checks)
        lines.append(f"{APP_NAME} {__version__} self-test: {'PASS' if ok else 'FAIL'} "
                     f"(model {engine.model_name}, {len(engine.ruleset.rules)} rules)")
        return ok, lines
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# 7b. Staging helpers (used by the GUI, testable without Qt)
# ===========================================================================
def repropose_tokens(findings: List[Finding], vault: SessionVault) -> None:
    """Recompute suggested tokens after edits, keeping user-edited and already-committed tokens."""
    pending: Dict[str, str] = {}
    for f in findings:                       # user-edited tokens are fixed points
        if f.token_edited:
            pending.setdefault(vault.key(f.text), f.token)
    for f in findings:
        k = vault.key(f.text)
        if f.token_edited:
            f.token = pending[k]
        else:
            f.token = vault.propose(f.text, f.entity, pending)


def merge_manual_rule(text: str, findings: List[Finding], rule: ManualRule,
                      vault: SessionVault, limit: int = 5000) -> Tuple[List[Finding], int]:
    """Apply one manual rule to already-staged findings: manual matches replace overlapping ones."""
    rx = rule.compile()
    new: List[Finding] = []
    for i, m in enumerate(rx.finditer(text)):
        if i >= limit:
            break
        if m.end() > m.start():
            new.append(Finding(m.start(), m.end(), m.group(0), rule.entity, 1.0, "manual", f"manual:{rule.rid}"))
    if not new:
        return findings, 0
    kept = [f for f in findings if not any(f.start < n.end and n.start < f.end for n in new)]
    merged = sorted(kept + new, key=lambda f: f.start)
    # keep entity/token consistent with values the user already staged or edited
    by_key = {vault.key(f.text): f for f in kept}
    for n in new:
        prev = by_key.get(vault.key(n.text))
        if prev is not None:
            n.entity, n.token, n.token_edited = prev.entity, prev.token, prev.token_edited
    repropose_tokens(merged, vault)
    return merged, len(new)


def mask_value(v: str) -> str:
    if len(v) <= 2:
        return "•" * len(v)
    return v[0] + "•" * min(len(v) - 2, 12) + v[-1]


def py_to_qt_index(text: str, idx: int) -> int:
    """Qt positions count UTF-16 code units; Python counts code points."""
    return idx + sum(1 for c in text[:idx] if ord(c) > 0xFFFF)


# ===========================================================================
# 8. GUI (PyQt6)
# ===========================================================================
try:
    from PyQt6 import QtCore, QtGui, QtWidgets
    from PyQt6.QtCore import Qt
    QT_OK, QT_ERR = True, ""
except Exception as _exc:  # pragma: no cover
    QT_OK, QT_ERR = False, str(_exc)

ENTITY_COLORS = ["#ffe08a", "#b6e3ff", "#c9f2c7", "#ffc9de", "#e3d2ff", "#ffd7b5", "#c2f0ef", "#f0e1c2"]
SOURCE_LABEL = {"presidio": "Presidio", "custom": "Custom rule", "manual": "Manual", "propagated": "Propagated",
                "session": "Session map"}

if QT_OK:
    class TaskSignals(QtCore.QObject):
        done = QtCore.pyqtSignal(object)
        error = QtCore.pyqtSignal(str)
        progress = QtCore.pyqtSignal(str)

    class Task(QtCore.QRunnable):
        """Run fn(*args, progress=cb) in the thread pool."""

        def __init__(self, fn, *args, wants_progress=False, **kwargs):
            super().__init__()
            self.fn, self.args, self.kwargs, self.wants_progress = fn, args, kwargs, wants_progress
            self.signals = TaskSignals()

        def run(self):
            try:
                if self.wants_progress:
                    self.kwargs["progress"] = self.signals.progress.emit
                self.signals.done.emit(self.fn(*self.args, **self.kwargs))
            except Exception as exc:
                log.debug(traceback.format_exc())
                self.signals.error.emit(f"{exc.__class__.__name__}: {exc}" if not isinstance(exc, (SyncError, RuleError, TokenCollision)) else str(exc))

    def _mono_font() -> QtGui.QFont:
        f = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        f.setPointSize(max(f.pointSize(), 10))
        return f

    def _text_box(placeholder: str = "", read_only: bool = False) -> QtWidgets.QPlainTextEdit:
        w = QtWidgets.QPlainTextEdit()
        w.setPlaceholderText(placeholder)
        w.setReadOnly(read_only)
        w.setFont(_mono_font())
        w.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.WidgetWidth)
        return w

    def _button(text: str, primary: bool = False, tip: str = "") -> QtWidgets.QPushButton:
        b = QtWidgets.QPushButton(text)
        if primary:
            b.setObjectName("primary")
        if tip:
            b.setToolTip(tip)
        return b

    STYLE = """
    QPushButton#primary { background:#2563eb; color:white; font-weight:600; padding:6px 14px;
                          border-radius:4px; border:1px solid #1d4ed8; }
    QPushButton#primary:disabled { background:#93a8d6; border-color:#93a8d6; }
    QPushButton#primary:hover { background:#1d4ed8; }
    QLabel#badge_ok   { background:#dcfce7; color:#166534; border:1px solid #86efac; border-radius:9px; padding:1px 9px; }
    QLabel#badge_warn { background:#fef3c7; color:#92400e; border:1px solid #fcd34d; border-radius:9px; padding:1px 9px; }
    QLabel#badge_err  { background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; border-radius:9px; padding:1px 9px; }
    QLabel#badge_info { background:#e0e7ff; color:#3730a3; border:1px solid #a5b4fc; border-radius:9px; padding:1px 9px; }
    QLabel#stale { background:#fef3c7; color:#92400e; padding:4px 8px; border-radius:4px; }
    QLabel#leak  { background:#fee2e2; color:#991b1b; padding:4px 8px; border-radius:4px; font-weight:600; }
    QLabel#okmsg { background:#dcfce7; color:#166534; padding:4px 8px; border-radius:4px; }
    QGroupBox { font-weight:600; }
    """

    def set_badge(label: QtWidgets.QLabel, text: str, kind: str = "ok") -> None:
        label.setText(text)
        label.setObjectName(f"badge_{kind}")
        label.style().unpolish(label)
        label.style().polish(label)

    def set_note(label: QtWidgets.QLabel, text: str, kind: str) -> None:
        label.setText(text)
        label.setObjectName(kind)
        label.setVisible(bool(text))
        label.style().unpolish(label)
        label.style().polish(label)

    def finish_app_update(parent, result: Tuple[str, Path]) -> None:
        """Script install: ask for a restart. Windows build: run the updater and quit, so it can swap the files."""
        kind, path = result
        if kind == "script":
            log.info("Installed update to %s. Restart the app to use it.", Path(path).name)
            QtWidgets.QMessageBox.information(parent, "Update installed", "Update installed. Please restart PII Shield.")
            return
        log.info("Windows build downloaded and verified; updater: %s", path)
        QtWidgets.QMessageBox.information(parent, "Update ready",
                                          "The new version is downloaded and verified.\n\nPII Shield will now close, "
                                          "install it and start again. Your settings and rules are kept.")
        launch_update_script(Path(path))
        QtWidgets.QApplication.quit()

    # -----------------------------------------------------------------------
    class SyncDialog(QtWidgets.QDialog):
        rules_updated = QtCore.pyqtSignal(object, object)   # RuleSet, SyncPlan

        def __init__(self, parent, config: AppConfig, secrets: SecretStore, engine: DetectionEngine):
            super().__init__(parent)
            self.setWindowTitle("Update Rules from GitHub")
            self.resize(720, 560)
            self.config, self.secrets, self.engine = config, secrets, engine
            g = config["github"]
            form = QtWidgets.QFormLayout()
            self.url = QtWidgets.QLineEdit(g.get("repo_url", ""))
            self.url.setPlaceholderText("https://api.github.com/repos/org/repo-name/contents/rules")
            self.branch = QtWidgets.QLineEdit(g.get("branch", "main"))
            self.pat = QtWidgets.QLineEdit(secrets.get())
            self.pat.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.pat.setPlaceholderText("optional - fine-grained PAT with Contents: read-only")
            show = QtWidgets.QCheckBox("show")
            show.toggled.connect(lambda on: self.pat.setEchoMode(
                QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password))
            pat_row = QtWidgets.QHBoxLayout()
            pat_row.addWidget(self.pat)
            pat_row.addWidget(show)
            self.check_app = QtWidgets.QCheckBox("Also check for a new application version")
            self.check_app.setChecked(bool(g.get("check_app_updates", True)))
            self.version_path = QtWidgets.QLineEdit(g.get("version_path", "version.json"))
            self.ca = QtWidgets.QLineEdit(g.get("ca_bundle", ""))
            self.ca.setPlaceholderText("optional - PEM bundle for corporate TLS inspection")
            ca_btn = QtWidgets.QToolButton()
            ca_btn.setText("...")
            ca_btn.clicked.connect(self._pick_ca)
            ca_row = QtWidgets.QHBoxLayout()
            ca_row.addWidget(self.ca)
            ca_row.addWidget(ca_btn)
            form.addRow("Repository URL", self.url)
            form.addRow("Branch / Tag", self.branch)
            form.addRow("Personal Access Token", pat_row)
            store = QtWidgets.QLabel(f"Token storage: {secrets.backend}")
            store.setStyleSheet("color:gray;")
            form.addRow("", store)
            form.addRow("Version file (repo path)", self.version_path)
            form.addRow("", self.check_app)
            form.addRow("CA bundle", ca_row)

            self.status = QtWidgets.QLabel("")
            self.status.setVisible(False)
            self.log = _text_box(read_only=True)
            self.log.setMaximumBlockCount(2000)
            self.btn_save = _button("Save")
            self.btn_test = _button("Test Connection")
            self.btn_check = _button("Check for Updates")
            self.btn_pull = _button("Check && Pull Updates", primary=True)
            self.btn_close = _button("Close")
            for b, fn in ((self.btn_save, self.save), (self.btn_test, self.test), (self.btn_check, self.check),
                          (self.btn_pull, self.pull), (self.btn_close, self.accept)):
                b.clicked.connect(fn)
            btns = QtWidgets.QHBoxLayout()
            for b in (self.btn_save, self.btn_test, self.btn_check):
                btns.addWidget(b)
            btns.addStretch(1)
            btns.addWidget(self.btn_pull)
            btns.addWidget(self.btn_close)
            note = QtWidgets.QLabel("Only rule files (.yaml .yml .json .txt .lst .csv) are downloaded into "
                                    "rules/remote/. Files are integrity-checked (git blob SHA), fully validated "
                                    "in a staging folder, and applied atomically with a backup. "
                                    "No prompt text is ever sent.")
            note.setWordWrap(True)
            note.setStyleSheet("color:gray;")
            lay = QtWidgets.QVBoxLayout(self)
            lay.addLayout(form)
            lay.addWidget(note)
            lay.addWidget(self.status)
            lay.addWidget(self.log, 1)
            lay.addLayout(btns)
            if config["behavior"].get("offline_mode"):
                set_note(self.status, "Offline mode is enabled in Settings - sync is disabled.", "leak")
                for b in (self.btn_test, self.btn_check, self.btn_pull):
                    b.setEnabled(False)

        def _pick_ca(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "CA bundle", "", "PEM (*.pem *.crt *.cer);;All (*)")
            if p:
                self.ca.setText(p)

        def save(self, quiet=False):
            g = self.config["github"]
            g["repo_url"] = self.url.text().strip()
            g["branch"] = self.branch.text().strip() or "main"
            g["check_app_updates"] = self.check_app.isChecked()
            g["version_path"] = self.version_path.text().strip()
            g["ca_bundle"] = self.ca.text().strip()
            self.secrets.set(self.pat.text())
            self.config.save()
            if not quiet:
                self._log("Settings saved.")

        def _log(self, msg: str):
            self.log.appendPlainText(f"[{_dt.datetime.now():%H:%M:%S}] {msg}")

        def _busy(self, on: bool):
            for b in (self.btn_save, self.btn_test, self.btn_check, self.btn_pull):
                b.setEnabled(not on)
            self.setCursor(Qt.CursorShape.BusyCursor if on else Qt.CursorShape.ArrowCursor)

        def _client(self, progress):
            return GitHubSync(self.config, self.secrets.get(), self.engine, RULES_DIR, progress)

        def _run(self, fn, on_done):
            self.save(quiet=True)
            self._busy(True)
            t = Task(fn, wants_progress=True)
            t.signals.progress.connect(self._log)
            t.signals.done.connect(lambda r: (self._busy(False), on_done(r)))
            t.signals.error.connect(self._error)
            QtCore.QThreadPool.globalInstance().start(t)
            self._task = t

        def _error(self, msg):
            self._busy(False)
            self._log("ERROR: " + msg)
            set_note(self.status, msg.splitlines()[0], "leak")

        def test(self):
            self._run(lambda progress: self._client(progress).test_connection(),
                      lambda r: (self._log(r), set_note(self.status, r, "okmsg")))

        def check(self):
            def job(progress):
                c = self._client(progress)
                plan = c.plan()
                app = c.check_app_version() if self.config["github"].get("check_app_updates") else None
                return plan, app

            def done(res):
                plan, app = res
                msg = (f"{len(plan.files)} remote files: +{len(plan.added)} new, ~{len(plan.changed)} changed, "
                       f"-{len(plan.removed)} removed, {len(plan.unchanged)} unchanged")
                self._log(msg)
                for p in plan.added:
                    self._log(f"  + {p}")
                for p in plan.changed:
                    self._log(f"  ~ {p}")
                for p in plan.removed:
                    self._log(f"  - {p}")
                set_note(self.status, ("Updates available - " if plan.has_changes else "Rules up to date - ") + msg,
                         "stale" if plan.has_changes else "okmsg")
                self._report_app(app, offer=False)
            self._run(job, done)

        def pull(self):
            def job(progress):
                c = self._client(progress)
                plan, rs = c.pull()
                app = c.check_app_version() if self.config["github"].get("check_app_updates") else None
                return plan, rs, app

            def done(res):
                plan, rs, app = res
                if plan.has_changes:
                    msg = f"Rules updated successfully ({len(rs.rules)} rules loaded)"
                else:
                    msg = f"Rules already up to date ({len(rs.rules)} rules loaded)"
                self._log(msg)
                for e in rs.errors:
                    self._log("WARN (local file skipped): " + e.replace("\n", " | "))
                set_note(self.status, msg, "okmsg")
                self.rules_updated.emit(rs, plan)
                self._report_app(app, offer=True)
            self._run(job, done)

        def _report_app(self, app: Optional[Dict], offer: bool):
            if not app:
                return
            if not app.get("newer"):
                self._log(f"Application is current (v{__version__}; remote v{app['version']}).")
                return
            self._log(f"New application version available: v{app['version']} (you have v{__version__}). "
                      f"{app.get('notes', '')}")
            if not offer:
                return
            ans = QtWidgets.QMessageBox.question(
                self, "Application update",
                f"Version {app['version']} is available (installed: {__version__}).\n\n{app.get('notes', '')}\n\n"
                "Download and install it now? The current script is backed up first, and the download is "
                "verified against the SHA-256 published in version.json.")
            if ans != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            self._run(lambda progress: self._client(progress).install_app_update(app),
                      lambda res: finish_app_update(self, res))

    # -----------------------------------------------------------------------
    class SettingsDialog(QtWidgets.QDialog):
        def __init__(self, parent, config: AppConfig, engine: DetectionEngine):
            super().__init__(parent)
            self.setWindowTitle("Settings")
            self.resize(560, 640)
            self.config, self.engine = config, engine
            e, b = config["engine"], config["behavior"]
            tabs = QtWidgets.QTabWidget()

            # detection
            w1 = QtWidgets.QWidget()
            f1 = QtWidgets.QFormLayout(w1)
            self.model = QtWidgets.QComboBox()
            models = installed_spacy_models() or ["(none installed)"]
            if e.get("spacy_model") not in models:
                models.insert(0, e.get("spacy_model"))
            self.model.addItems(models)
            self.model.setCurrentText(e.get("spacy_model"))
            self.threshold = QtWidgets.QDoubleSpinBox()
            self.threshold.setRange(0.0, 1.0)
            self.threshold.setSingleStep(0.05)
            self.threshold.setValue(float(e.get("score_threshold", 0.35)))
            self.orgs = QtWidgets.QCheckBox("Detect ORGANIZATION names with spaCy NER (noisy)")
            self.orgs.setChecked(bool(e.get("detect_organizations")))
            self.entities = QtWidgets.QListWidget()
            known = sorted(set(engine.builtin_supported) | set(DEFAULT_BUILTIN_ENTITIES) |
                           set(e.get("builtin_entities", [])) | ({"ORGANIZATION"} if e.get("detect_organizations") else set()))
            enabled = set(e.get("builtin_entities", []))
            for ent in known:
                it = QtWidgets.QListWidgetItem(ent)
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(Qt.CheckState.Checked if ent in enabled else Qt.CheckState.Unchecked)
                self.entities.addItem(it)
            f1.addRow("spaCy model", self.model)
            f1.addRow("Score threshold", self.threshold)
            f1.addRow("", self.orgs)
            f1.addRow(QtWidgets.QLabel("Built-in Presidio entities (custom-rule entities are always on):"))
            f1.addRow(self.entities)
            tabs.addTab(w1, "Detection")

            # behaviour
            w2 = QtWidgets.QWidget()
            f2 = QtWidgets.QFormLayout(w2)
            self.token_format = QtWidgets.QLineEdit(b.get("token_format", "<{entity}_{n}>"))
            self.propagate = QtWidgets.QCheckBox("Mask every occurrence of a detected value (recommended)")
            self.propagate.setChecked(bool(b.get("propagate_values", True)))
            self.ci = QtWidgets.QCheckBox("Case-insensitive value matching (SRV-DC01 = srv-dc01)")
            self.ci.setChecked(bool(b.get("case_insensitive_values", True)))
            self.lenient = QtWidgets.QCheckBox("Lenient restore (HOSTNAME_1, [HOSTNAME_1], &&lt;HOSTNAME_1&&gt;)")
            self.lenient.setChecked(bool(b.get("lenient_restore", True)))
            self.clip = QtWidgets.QSpinBox()
            self.clip.setRange(0, 3600)
            self.clip.setSuffix(" s  (0 = never)")
            self.clip.setValue(int(b.get("clipboard_clear_seconds", 0)))
            self.offline = QtWidgets.QCheckBox("Offline mode - no GitHub sync and no update checks")
            self.offline.setChecked(bool(b.get("offline_mode")))
            self.auto_sync = QtWidgets.QCheckBox("Sync rules from GitHub at startup (in the background)")
            self.auto_sync.setChecked(bool(self.config["github"].get("auto_sync_on_startup", True)))
            self.check_presidio = QtWidgets.QCheckBox("Check PyPI for Presidio updates at startup (report only)")
            self.check_presidio.setChecked(bool(e.get("check_presidio_updates", True)))
            f2.addRow("Token format", self.token_format)
            f2.addRow("", QtWidgets.QLabel("Must contain {entity} and {n}, e.g. <{entity}_{n}> or [[{entity}-{n}]]"))
            f2.addRow("", self.propagate)
            f2.addRow("", self.ci)
            f2.addRow("", self.lenient)
            f2.addRow("Auto-clear clipboard", self.clip)
            f2.addRow("", self.offline)
            f2.addRow("", self.auto_sync)
            f2.addRow("", self.check_presidio)
            tabs.addTab(w2, "Behavior")

            bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok |
                                            QtWidgets.QDialogButtonBox.StandardButton.Cancel)
            bb.accepted.connect(self._accept)
            bb.rejected.connect(self.reject)
            lay = QtWidgets.QVBoxLayout(self)
            lay.addWidget(tabs)
            lay.addWidget(bb)
            self.needs_engine_restart = False

        def _accept(self):
            tf = self.token_format.text().strip()
            if "{entity}" not in tf or "{n}" not in tf:
                QtWidgets.QMessageBox.warning(self, "Token format", "Token format must contain {entity} and {n}.")
                return
            e, b = self.config["engine"], self.config["behavior"]
            model = self.model.currentText()
            self.needs_engine_restart = (model != e.get("spacy_model") or
                                         self.orgs.isChecked() != bool(e.get("detect_organizations")))
            e["spacy_model"] = model
            e["score_threshold"] = round(self.threshold.value(), 2)
            e["detect_organizations"] = self.orgs.isChecked()
            ents = [self.entities.item(i).text() for i in range(self.entities.count())
                    if self.entities.item(i).checkState() == Qt.CheckState.Checked]
            if self.orgs.isChecked() and "ORGANIZATION" not in ents:
                ents.append("ORGANIZATION")
            e["builtin_entities"] = ents
            b.update(token_format=tf, propagate_values=self.propagate.isChecked(),
                     case_insensitive_values=self.ci.isChecked(), lenient_restore=self.lenient.isChecked(),
                     clipboard_clear_seconds=self.clip.value(), offline_mode=self.offline.isChecked())
            self.config["github"]["auto_sync_on_startup"] = self.auto_sync.isChecked()
            e["check_presidio_updates"] = self.check_presidio.isChecked()
            self.config.save()
            self.accept()

    # -----------------------------------------------------------------------
    COLS = ["Enable", "Original Text", "Entity Type", "Token", "Start", "End", "Score", "Source"]
    C_EN, C_TEXT, C_ENT, C_TOK, C_START, C_END, C_SCORE, C_SRC = range(8)

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self, config: AppConfig):
            super().__init__()
            self.config = config
            self.secrets = SecretStore(config)
            self._startup_checked = False
            self.engine = DetectionEngine(config)
            b = config["behavior"]
            self.vault = SessionVault(b.get("token_format", "<{entity}_{n}>"), b.get("case_insensitive_values", True))
            self.findings: List[Finding] = []
            self.manual_rules: List[ManualRule] = []
            self.analyzed_text: Optional[str] = None
            self.last_sanitized: str = ""
            self._updating = False
            self._tasks = []
            self.setWindowTitle(f"{APP_NAME} {__version__} - local PII sanitizer for LLM prompts")
            self.resize(1360, 880)
            self._build_ui()
            self._start_engine()

        # ================= UI construction
        def _build_ui(self):
            st = self.style()
            tb = self.addToolBar("Main")
            tb.setMovable(False)
            tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            self.act_sync = tb.addAction(st.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ArrowDown),
                                         "Update Rules", self.open_sync)
            self.act_reload = tb.addAction(st.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_BrowserReload),
                                           "Reload Local Rules", self.reload_rules)
            tb.addAction(st.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DirOpenIcon),
                         "Rules Folder", lambda: QtGui.QDesktopServices.openUrl(
                             QtCore.QUrl.fromLocalFile(str(RULES_DIR))))
            tb.addAction(st.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_FileDialogDetailedView),
                         "Settings", self.open_settings)
            tb.addSeparator()
            tb.addAction(st.standardIcon(QtWidgets.QStyle.StandardPixmap.SP_TrashIcon),
                         "Reset Session", self.reset_session)

            self.tabs = QtWidgets.QTabWidget()
            self.tabs.addTab(self._build_analyze_tab(), "1 · Input && Review")
            self.tabs.addTab(self._build_sanitize_tab(), "2 · Sanitize")
            self.tabs.addTab(self._build_restore_tab(), "3 · Restore")
            self.tabs.addTab(self._build_map_tab(), "Session Map")
            self.tabs.addTab(self._build_log_tab(), "Log")
            self.setCentralWidget(self.tabs)

            sb = self.statusBar()
            self.lbl_engine = QtWidgets.QLabel("Engine: loading...")
            self.badge_rules = QtWidgets.QLabel("Rules: -")
            self.badge_rules.setCursor(Qt.CursorShape.PointingHandCursor)
            self.badge_rules.mousePressEvent = lambda e: self.show_rule_report()
            self.badge_session = QtWidgets.QLabel("Session: 0 tokens")
            self.badge_guard = QtWidgets.QLabel("Offline guard: ON")
            self.badge_guard.setToolTip("All sockets are blocked except the on-demand GitHub sync request.")
            set_badge(self.badge_session, "Session: 0 tokens", "info")
            set_badge(self.badge_guard, "Network guard: ON", "ok")
            sb.addWidget(self.lbl_engine, 1)
            sb.addPermanentWidget(self.badge_guard)
            sb.addPermanentWidget(self.badge_session)
            sb.addPermanentWidget(self.badge_rules)

            QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Return"), self, self.analyze)
            QtGui.QShortcut(QtGui.QKeySequence("Ctrl+G"), self, self.generate)
            QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+R"), self, self.restore)

        def _build_analyze_tab(self):
            page = QtWidgets.QWidget()
            outer = QtWidgets.QVBoxLayout(page)
            vsplit = QtWidgets.QSplitter(Qt.Orientation.Vertical)

            # --- Step 1 input
            g1 = QtWidgets.QGroupBox("Step 1 — Input: paste raw text, logs, code or a prompt")
            l1 = QtWidgets.QVBoxLayout(g1)
            self.input = _text_box("Paste text here...  (Ctrl+Enter to analyze)")
            self.input.textChanged.connect(self._on_input_changed)
            row = QtWidgets.QHBoxLayout()
            self.btn_analyze = _button("Analyze PII && Sensitive Data", primary=True, tip="Ctrl+Enter")
            self.btn_analyze.clicked.connect(self.analyze)
            self.btn_analyze.setEnabled(False)
            btn_load = _button("Load File...")
            btn_load.clicked.connect(self.load_file)
            btn_clear = _button("Clear")
            btn_clear.clicked.connect(lambda: self.input.clear())
            self.thr = QtWidgets.QDoubleSpinBox()
            self.thr.setRange(0.0, 1.0)
            self.thr.setSingleStep(0.05)
            self.thr.setValue(float(self.config["engine"].get("score_threshold", 0.35)))
            self.thr.setPrefix("min score ")
            self.lbl_stale = QtWidgets.QLabel()
            self.lbl_stale.setVisible(False)
            row.addWidget(self.btn_analyze)
            row.addWidget(self.thr)
            row.addWidget(btn_load)
            row.addWidget(btn_clear)
            row.addWidget(self.lbl_stale)
            row.addStretch(1)
            self.lbl_input_stats = QtWidgets.QLabel("")
            self.lbl_input_stats.setStyleSheet("color:gray;")
            row.addWidget(self.lbl_input_stats)
            l1.addWidget(self.input, 1)
            l1.addLayout(row)
            vsplit.addWidget(g1)

            # --- Step 2 staging
            g2 = QtWidgets.QGroupBox("Step 2 — Review: uncheck false positives, edit entity types or tokens")
            l2 = QtWidgets.QHBoxLayout(g2)
            hsplit = QtWidgets.QSplitter(Qt.Orientation.Horizontal)
            left = QtWidgets.QWidget()
            ll = QtWidgets.QVBoxLayout(left)
            ll.setContentsMargins(0, 0, 0, 0)
            frow = QtWidgets.QHBoxLayout()
            self.search = QtWidgets.QLineEdit()
            self.search.setPlaceholderText("Filter rows...")
            self.search.setClearButtonEnabled(True)
            self.search.textChanged.connect(self._apply_row_filter)
            self.type_filter = QtWidgets.QComboBox()
            self.type_filter.addItem("All types")
            self.type_filter.currentTextChanged.connect(self._apply_row_filter)
            b_all = _button("Enable shown")
            b_none = _button("Disable shown")
            b_all.clicked.connect(lambda: self._set_enabled_visible(True))
            b_none.clicked.connect(lambda: self._set_enabled_visible(False))
            frow.addWidget(self.search, 1)
            frow.addWidget(self.type_filter)
            frow.addWidget(b_all)
            frow.addWidget(b_none)
            ll.addLayout(frow)
            self.table = QtWidgets.QTableWidget(0, len(COLS))
            self.table.setHorizontalHeaderLabels(COLS)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.DoubleClicked |
                                       QtWidgets.QAbstractItemView.EditTrigger.EditKeyPressed |
                                       QtWidgets.QAbstractItemView.EditTrigger.SelectedClicked)
            hh = self.table.horizontalHeader()
            hh.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Interactive)
            hh.setStretchLastSection(False)
            hh.setSectionResizeMode(C_TEXT, QtWidgets.QHeaderView.ResizeMode.Stretch)
            for c, w in ((C_EN, 60), (C_ENT, 150), (C_TOK, 170), (C_START, 60), (C_END, 60), (C_SCORE, 55), (C_SRC, 100)):
                self.table.setColumnWidth(c, w)
            self.table.setSortingEnabled(True)
            self.table.sortByColumn(C_START, Qt.SortOrder.AscendingOrder)
            self.table.itemChanged.connect(self._on_item_changed)
            self.table.itemSelectionChanged.connect(self._on_row_selected)
            self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._table_menu)
            ll.addWidget(self.table, 1)
            self.lbl_counts = QtWidgets.QLabel("No analysis yet.")
            self.lbl_counts.setStyleSheet("color:gray;")
            ll.addWidget(self.lbl_counts)
            hsplit.addWidget(left)

            # on-the-fly matcher
            gm = QtWidgets.QGroupBox("On-the-fly Matcher")
            lm = QtWidgets.QVBoxLayout(gm)
            fm = QtWidgets.QFormLayout()
            self.m_type = QtWidgets.QComboBox()
            self.m_type.addItems(["Exact Match", "Wildcard", "Custom Regex"])
            self.m_pattern = QtWidgets.QLineEdit()
            self.m_pattern.setPlaceholderText("e.g. SRV-*   *.corp   acme-prod")
            self.m_pattern.returnPressed.connect(self.add_manual_rule)
            self.m_entity = QtWidgets.QComboBox()
            self.m_entity.setEditable(True)
            self.m_entity.addItems(["HOSTNAME", "DOMAIN", "USERNAME", "INTERNAL_IP", "PROJECT", "CUSTOMER",
                                    "SECRET", "PERSON", "ORGANIZATION", "CUSTOM"])
            self.m_ci = QtWidgets.QCheckBox("Case-insensitive")
            self.m_ci.setChecked(True)
            fm.addRow("Match type", self.m_type)
            fm.addRow("Pattern", self.m_pattern)
            fm.addRow("Entity", self.m_entity)
            fm.addRow("", self.m_ci)
            lm.addLayout(fm)
            self.m_hint = QtWidgets.QLabel("Wildcards: * = any host-name chars (incl. dots), ? = one char.")
            self.m_hint.setWordWrap(True)
            self.m_hint.setStyleSheet("color:gray;")
            lm.addWidget(self.m_hint)
            b_add = _button("Add Rule && Match", primary=True)
            b_add.clicked.connect(self.add_manual_rule)
            lm.addWidget(b_add)
            self.m_list = QtWidgets.QListWidget()
            self.m_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
            lm.addWidget(QtWidgets.QLabel("Temporary rules (this session):"))
            lm.addWidget(self.m_list, 1)
            mrow = QtWidgets.QHBoxLayout()
            b_rm = _button("Remove")
            b_rm.clicked.connect(self.remove_manual_rules)
            b_promote = _button("Save to Local Rules", tip="Persist selected rules into rules/local/promoted_rules.yaml")
            b_promote.clicked.connect(self.promote_manual_rules)
            mrow.addWidget(b_rm)
            mrow.addWidget(b_promote)
            lm.addLayout(mrow)
            gm.setMinimumWidth(300)
            hsplit.addWidget(gm)
            hsplit.setStretchFactor(0, 4)
            hsplit.setStretchFactor(1, 1)
            l2.addWidget(hsplit)
            vsplit.addWidget(g2)
            vsplit.setStretchFactor(0, 2)
            vsplit.setStretchFactor(1, 3)
            outer.addWidget(vsplit)
            return page

        def _build_sanitize_tab(self):
            page = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(page)
            g = QtWidgets.QGroupBox("Step 3 — Anonymize: generate the clean prompt")
            l = QtWidgets.QVBoxLayout(g)
            row = QtWidgets.QHBoxLayout()
            self.btn_generate = _button("Generate Sanitized Prompt", primary=True, tip="Ctrl+G")
            self.btn_generate.clicked.connect(self.generate)
            self.btn_copy_clean = _button("Copy Clean Text to Clipboard")
            self.btn_copy_clean.clicked.connect(lambda: self.copy_text(self.output.toPlainText()))
            row.addWidget(self.btn_generate)
            row.addWidget(self.btn_copy_clean)
            row.addStretch(1)
            self.lbl_gen = QtWidgets.QLabel("")
            row.addWidget(self.lbl_gen)
            self.lbl_leak = QtWidgets.QLabel()
            self.lbl_leak.setVisible(False)
            self.lbl_leak.setWordWrap(True)
            self.output = _text_box("Sanitized text appears here.", read_only=True)
            l.addLayout(row)
            l.addWidget(self.lbl_leak)
            l.addWidget(self.output, 1)
            lay.addWidget(g)
            return page

        def _build_restore_tab(self):
            page = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(page)
            g = QtWidgets.QGroupBox("Step 4 — Re-identify: paste the AI response")
            l = QtWidgets.QVBoxLayout(g)
            split = QtWidgets.QSplitter(Qt.Orientation.Vertical)
            self.ai_input = _text_box("Paste the LLM response containing tokens like <HOSTNAME_1> ...")
            self.restored = _text_box("Restored text appears here.", read_only=True)
            split.addWidget(self.ai_input)
            split.addWidget(self.restored)
            row = QtWidgets.QHBoxLayout()
            self.btn_restore = _button("Restore Original Values", primary=True, tip="Ctrl+Shift+R")
            self.btn_restore.clicked.connect(self.restore)
            self.chk_lenient = QtWidgets.QCheckBox("Lenient token matching")
            self.chk_lenient.setChecked(bool(self.config["behavior"].get("lenient_restore", True)))
            self.chk_lenient.setToolTip("Also restores HOSTNAME_1, [HOSTNAME_1], {HOSTNAME_1}, &lt;HOSTNAME_1&gt;")
            b_copy = _button("Copy Restored Text")
            b_copy.clicked.connect(lambda: self.copy_text(self.restored.toPlainText()))
            b_reset = _button("Reset Session")
            b_reset.clicked.connect(self.reset_session)
            self.lbl_restore = QtWidgets.QLabel("")
            row.addWidget(self.btn_restore)
            row.addWidget(self.chk_lenient)
            row.addWidget(b_copy)
            row.addStretch(1)
            row.addWidget(self.lbl_restore)
            row.addWidget(b_reset)
            l.addLayout(row)
            l.addWidget(split, 1)
            lay.addWidget(g)
            return page

        def _build_map_tab(self):
            page = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(page)
            row = QtWidgets.QHBoxLayout()
            self.map_filter = QtWidgets.QLineEdit()
            self.map_filter.setPlaceholderText("Filter tokens...")
            self.map_filter.textChanged.connect(self.refresh_map)
            self.chk_reveal = QtWidgets.QCheckBox("Show raw values")
            self.chk_reveal.toggled.connect(self.refresh_map)
            b_exp = _button("Export Map...")
            b_imp = _button("Import Map...")
            b_exp.clicked.connect(self.export_map)
            b_imp.clicked.connect(self.import_map)
            row.addWidget(self.map_filter, 1)
            row.addWidget(self.chk_reveal)
            row.addWidget(b_exp)
            row.addWidget(b_imp)
            self.map_table = QtWidgets.QTableWidget(0, 5)
            self.map_table.setHorizontalHeaderLabels(["Token", "Original Value", "Entity", "First Seen", "Status"])
            self.map_table.verticalHeader().setVisible(False)
            self.map_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.map_table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
            self.map_table.setColumnWidth(0, 200)
            self.map_table.setColumnWidth(2, 150)
            self.map_table.setSortingEnabled(True)
            info = QtWidgets.QLabel("The session map lives only in memory: identical values always receive the "
                                    "same token. It is destroyed on Reset Session or when the app closes.")
            info.setStyleSheet("color:gray;")
            info.setWordWrap(True)
            lay.addLayout(row)
            lay.addWidget(self.map_table, 1)
            lay.addWidget(info)
            return page

        def _build_log_tab(self):
            self.log_box = _text_box(read_only=True)
            self.log_box.setMaximumBlockCount(5000)
            handler = _QtLogHandler(self.log_box)
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
            log.addHandler(handler)
            if log.getEffectiveLevel() > logging.INFO:
                log.setLevel(logging.INFO)
            self._log_handler = handler
            return self.log_box

        # ================= engine / rules
        def _run(self, fn, done, *args, error=None, progress=False):
            t = Task(fn, *args, wants_progress=progress)
            t.signals.done.connect(done)
            t.signals.error.connect(error or self._task_error)
            if progress:
                t.signals.progress.connect(lambda m: (self.lbl_engine.setText(m), log.info(m)))
            self._tasks = [x for x in self._tasks if x is not None][-10:] + [t]
            QtCore.QThreadPool.globalInstance().start(t)

        def _task_error(self, msg):
            self.setCursor(Qt.CursorShape.ArrowCursor)
            self.btn_analyze.setEnabled(self.engine.mode != "uninitialized")
            log.error(msg)
            QtWidgets.QMessageBox.critical(self, APP_NAME, msg)

        def _start_engine(self):
            self.btn_analyze.setEnabled(False)
            self.lbl_engine.setText("Engine: loading NLP model (first start can take ~10-20 s)...")

            def done(mode):
                desc = {"presidio+spacy": f"Presidio + spaCy {self.engine.model_name}",
                        "presidio-regex-only": "Presidio (regex only - no spaCy model installed)",
                        "lite": "Lite regex engine (Presidio not installed)"}.get(mode, mode)
                self.lbl_engine.setText(f"Engine: {desc}  ·  offline")
                self.btn_analyze.setEnabled(True)
                self._update_rules_badge(self.engine.ruleset)
                self._startup_updates()
            self._run(self.engine.initialize, done, progress=True)

        def _startup_updates(self):
            """Once per app start, after the engine is ready: pull rules, check for a newer app version,
            and check Presidio, all in the background.
            Failures only go to the log - a missing network must not interrupt work."""
            if self._startup_checked:
                return
            self._startup_checked = True

            def synced(res):
                if res is None:
                    return
                plan, rs = res
                self._update_rules_badge(rs)
                if plan.has_changes:
                    log.info("Startup rules sync: +%d ~%d -%d files", len(plan.added), len(plan.changed),
                             len(plan.removed))
                    set_badge(self.badge_rules, f"Rules auto-updated ({len(rs.rules)} rules loaded)",
                              "warn" if rs.errors else "ok")
                else:
                    log.info("Startup rules sync: already up to date")
            self._run(auto_sync_rules, synced, self.config, self.secrets.get(), self.engine,
                      error=lambda m: log.warning("Startup rules sync failed: %s", m))

            def app_checked(info):
                if not info:
                    return
                if not info.get("newer"):
                    log.info("Application is current (v%s; remote v%s)", __version__, info["version"])
                    return
                log.warning("New application version available: v%s (you have v%s). %s",
                            info["version"], __version__, info.get("notes", ""))
                self.statusBar().showMessage(f"PII Shield {info['version']} is available - see Log")
                ans = QtWidgets.QMessageBox.question(
                    self, "Application update",
                    f"Version {info['version']} is available (installed: {__version__}).\n\n"
                    f"{info.get('notes', '')}\n\nDownload and install it now? The current script is backed up "
                    "first, and the download is verified against the SHA-256 published in version.json.")
                if ans != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                self._run(lambda: GitHubSync(self.config, self.secrets.get()).install_app_update(info),
                          lambda res: finish_app_update(self, res))
            self._run(auto_check_app_update, app_checked, self.config, self.secrets.get(),
                      error=lambda m: log.warning("Startup app update check failed: %s", m))

            def checked(res):
                if res is None:
                    return
                newer = [r for r in res if r["newer"]]
                for r in res:
                    log.info("%s: installed %s, latest %s", r["package"], r["installed"] or "(none)", r["latest"])
                if newer:
                    hint = presidio_update_hint(newer, is_frozen())
                    log.warning("%s", hint)
                    self.statusBar().showMessage(hint + " (see Log)")
            self._run(check_package_updates, checked, self.config,
                      error=lambda m: log.warning("Presidio update check failed: %s", m))

        def reload_rules(self):
            self._run(self.engine.reload_rules, lambda rs: (self._update_rules_badge(rs),
                                                            self.statusBar().showMessage("Rules reloaded", 4000)))

        def _update_rules_badge(self, rs: RuleSet, prefix: str = "Rules"):
            if rs.errors:
                set_badge(self.badge_rules, f"{prefix}: {len(rs.rules)} loaded · {len(rs.errors)} file error(s)", "warn")
            else:
                set_badge(self.badge_rules, f"{prefix}: {len(rs.rules)} rules loaded", "ok")
            self.badge_rules.setToolTip("Click for details")
            for e in rs.errors:
                log.warning("rule file skipped: %s", e.replace("\n", " | "))
            for w in rs.warnings:
                log.info("rule warning: %s", w)
            ents = sorted(set(self.config["engine"].get("builtin_entities", [])) | set(rs.entities))
            cur = self.m_entity.currentText()
            existing = {self.m_entity.itemText(i) for i in range(self.m_entity.count())}
            for e in ents:
                if e not in existing:
                    self.m_entity.addItem(e)
            self.m_entity.setCurrentText(cur)

        def show_rule_report(self):
            rs = self.engine.ruleset
            lines = [f"Loaded {len(rs.rules)} recognizers ({rs.pattern_count} patterns/wordlists) "
                     f"from {len(rs.files)} files; allow-list: {len(rs.allow_list)} values.", ""]
            lines += [f"  {r.entity:<22} {r.name}  [{r.source_file}]" for r in rs.rules]
            if rs.errors:
                lines += ["", "ERRORS (file skipped):"] + ["  " + e for e in rs.errors]
            if rs.warnings:
                lines += ["", "Warnings:"] + ["  " + w for w in rs.warnings]
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle("Loaded Rules")
            dlg.resize(760, 520)
            box = _text_box(read_only=True)
            box.setPlainText("\n".join(lines))
            QtWidgets.QVBoxLayout(dlg).addWidget(box)
            dlg.exec()

        def open_sync(self):
            dlg = SyncDialog(self, self.config, self.secrets, self.engine)
            dlg.rules_updated.connect(lambda rs, plan: (
                self._update_rules_badge(rs),
                set_badge(self.badge_rules,
                          f"Rules updated successfully ({len(rs.rules)} rules loaded)" if plan.has_changes
                          else f"Rules up to date ({len(rs.rules)} rules loaded)", "warn" if rs.errors else "ok")))
            dlg.exec()

        def open_settings(self):
            dlg = SettingsDialog(self, self.config, self.engine)
            if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            b = self.config["behavior"]
            self.vault.token_format = b["token_format"]
            if len(self.vault) == 0:
                self.vault.case_insensitive = b["case_insensitive_values"]
            self.chk_lenient.setChecked(b["lenient_restore"])
            self.thr.setValue(self.config["engine"]["score_threshold"])
            if dlg.needs_engine_restart:
                self._start_engine()
            if self.findings:
                self.statusBar().showMessage("Settings saved - re-analyze to apply detection changes", 6000)

        # ================= Step 1 / 2
        def load_file(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load text file", "", "Text (*.txt *.log *.md *.json *.yaml *.yml *.csv *.xml *.ps1 *.py *.conf *.ini);;All (*)")
            if p:
                try:
                    self.input.setPlainText(Path(p).read_text("utf-8", errors="replace"))
                except Exception as exc:
                    QtWidgets.QMessageBox.warning(self, "Load file", str(exc))

        def _on_input_changed(self):
            text = self.input.toPlainText()
            self.lbl_input_stats.setText(f"{len(text):,} chars · {text.count(chr(10)) + (1 if text else 0):,} lines")
            if self.analyzed_text is not None and text != self.analyzed_text:
                set_note(self.lbl_stale, "Input changed since analysis — re-analyze before generating", "stale")
                self.input.setExtraSelections([])
            elif self.analyzed_text is not None:
                set_note(self.lbl_stale, "", "stale")
                self._highlight()

        def analyze(self):
            if not self.btn_analyze.isEnabled():
                return
            text = self.input.toPlainText()
            if not text.strip():
                self.statusBar().showMessage("Nothing to analyze", 3000)
                return
            self.btn_analyze.setEnabled(False)
            self.setCursor(Qt.CursorShape.BusyCursor)
            self.lbl_counts.setText("Analyzing...")
            thr = self.thr.value()

            def done(findings):
                self.setCursor(Qt.CursorShape.ArrowCursor)
                self.btn_analyze.setEnabled(True)
                self.findings = findings
                self.analyzed_text = text
                set_note(self.lbl_stale, "", "stale")
                self.populate_table()
                self._highlight()
                log.info("analysis: %d detections, %d unique values", len(findings),
                         len({self.vault.key(f.text) for f in findings}))
            self._run(self.engine.analyze, done, text, list(self.manual_rules), self.vault, thr)

        def populate_table(self):
            self._updating = True
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(self.findings))
            ents = sorted({f.entity for f in self.findings})
            color = {e: QtGui.QColor(ENTITY_COLORS[i % len(ENTITY_COLORS)]) for i, e in enumerate(ents)}
            for row, f in enumerate(self.findings):
                en = QtWidgets.QTableWidgetItem()
                en.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                en.setCheckState(Qt.CheckState.Checked if f.enabled else Qt.CheckState.Unchecked)
                en.setData(Qt.ItemDataRole.UserRole, row)
                txt = QtWidgets.QTableWidgetItem(f.text.replace("\n", "↵"))
                txt.setFlags(txt.flags() & ~Qt.ItemFlag.ItemIsEditable)
                txt.setToolTip(f.text)
                ent = QtWidgets.QTableWidgetItem(f.entity)
                ent.setBackground(color[f.entity])
                ent.setForeground(QtGui.QColor("#111"))
                tok = QtWidgets.QTableWidgetItem(f.token)
                tok.setFont(_mono_font())
                if f.token_edited:
                    tok.setToolTip("Edited by you")
                    f2 = tok.font()
                    f2.setBold(True)
                    tok.setFont(f2)
                items = [en, txt, ent, tok]
                for val in (f.start, f.end):
                    it = QtWidgets.QTableWidgetItem()
                    it.setData(Qt.ItemDataRole.DisplayRole, val)
                    items.append(it)
                sc = QtWidgets.QTableWidgetItem()
                sc.setData(Qt.ItemDataRole.DisplayRole, round(f.score, 2))
                src = QtWidgets.QTableWidgetItem(SOURCE_LABEL.get(f.source, f.source))
                src.setToolTip(f.recognizer)
                items += [sc, src]
                for c in (C_START, C_END, C_SCORE, C_SRC):
                    items[c].setFlags(items[c].flags() & ~Qt.ItemFlag.ItemIsEditable)
                if not f.enabled:
                    for it in items[1:]:
                        it.setForeground(QtGui.QColor("#9ca3af"))
                for c, it in enumerate(items):
                    self.table.setItem(row, c, it)
            self.table.setSortingEnabled(True)
            self._updating = False
            # type filter
            cur = self.type_filter.currentText()
            self.type_filter.blockSignals(True)
            self.type_filter.clear()
            self.type_filter.addItem("All types")
            self.type_filter.addItems(ents)
            self.type_filter.setCurrentText(cur if cur in ents else "All types")
            self.type_filter.blockSignals(False)
            self._apply_row_filter()
            self._update_counts()

        def _row_index(self, row: int) -> Optional[int]:
            it = self.table.item(row, C_EN)
            return None if it is None else it.data(Qt.ItemDataRole.UserRole)

        def _update_counts(self):
            n = len(self.findings)
            en = [f for f in self.findings if f.enabled]
            uniq = len({self.vault.key(f.text) for f in en})
            types = len({f.entity for f in en})
            self.lbl_counts.setText(f"{n} detections · {len(en)} enabled · {uniq} unique values · "
                                    f"{types} entity types · {len(self.manual_rules)} temporary rules")

        def _apply_row_filter(self):
            q = self.search.text().strip().casefold()
            t = self.type_filter.currentText()
            for row in range(self.table.rowCount()):
                idx = self._row_index(row)
                if idx is None:
                    continue
                f = self.findings[idx]
                hide = (t != "All types" and f.entity != t) or \
                       (q and q not in f.text.casefold() and q not in f.entity.casefold() and q not in f.token.casefold())
                self.table.setRowHidden(row, bool(hide))

        def _set_enabled_visible(self, on: bool):
            for row in range(self.table.rowCount()):
                if not self.table.isRowHidden(row):
                    self.findings[self._row_index(row)].enabled = on
            self._refresh_after_edit()

        def _refresh_after_edit(self):
            vpos = self.table.verticalScrollBar().value()
            self.populate_table()
            self.table.verticalScrollBar().setValue(vpos)
            self._highlight()

        def _on_item_changed(self, item: QtWidgets.QTableWidgetItem):
            if self._updating:
                return
            idx = self._row_index(item.row())
            if idx is None:
                return
            f = self.findings[idx]
            col = item.column()
            key = self.vault.key(f.text)
            same = [x for x in self.findings if self.vault.key(x.text) == key]
            if col == C_EN:
                f.enabled = item.checkState() == Qt.CheckState.Checked
                self._updating = True
                color = QtGui.QColor("#9ca3af") if not f.enabled else self.palette().color(QtGui.QPalette.ColorRole.Text)
                for c in range(1, len(COLS)):
                    if c != C_ENT:
                        it = self.table.item(item.row(), c)
                        if it:
                            it.setForeground(color)
                self._updating = False
                self._update_counts()
                self._highlight()
                return
            if col == C_ENT:
                ent = re.sub(r"[^A-Z0-9_]", "_", item.text().strip().upper())
                if not ENTITY_NAME_RE.match(ent):
                    QtWidgets.QMessageBox.warning(self, "Entity type", "Use UPPER_SNAKE_CASE, e.g. HOSTNAME")
                    self._refresh_after_edit()
                    return
                for x in same:
                    x.entity = ent
                repropose_tokens(self.findings, self.vault)
                self._refresh_after_edit()
                return
            if col == C_TOK:
                tok = item.text().strip()
                problem = None
                if not tok:
                    problem = "Token cannot be empty."
                elif any(self.vault.key(x.text) != key and x.token == tok for x in self.findings):
                    problem = f"{tok} is already used for a different value in this text."
                else:
                    try:
                        self.vault.check(f.text, tok)
                    except TokenCollision as exc:
                        problem = str(exc) + " in the session map."
                if not problem and tok in (self.analyzed_text or "") and tok != f.token:
                    problem = f"{tok} already appears literally in the input - restore would be ambiguous."
                if problem:
                    QtWidgets.QMessageBox.warning(self, "Token", problem)
                    self._refresh_after_edit()
                    return
                for x in same:
                    x.token, x.token_edited = tok, True
                self._refresh_after_edit()

        def _selected_indices(self) -> List[int]:
            rows = sorted({i.row() for i in self.table.selectedIndexes()})
            return [self._row_index(r) for r in rows if self._row_index(r) is not None]

        def _on_row_selected(self):
            idxs = self._selected_indices()
            if len(idxs) != 1 or self.analyzed_text is None or self.input.toPlainText() != self.analyzed_text:
                return
            f = self.findings[idxs[0]]
            cur = self.input.textCursor()
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.start))
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.end), QtGui.QTextCursor.MoveMode.KeepAnchor)
            self.input.setTextCursor(cur)
            self.input.ensureCursorVisible()

        def _table_menu(self, pos):
            idxs = self._selected_indices()
            if not idxs:
                return
            m = QtWidgets.QMenu(self)
            a_en = m.addAction("Enable selected")
            a_dis = m.addAction("Disable selected")
            m.addSeparator()
            a_en_all = m.addAction("Enable all occurrences of these values")
            a_dis_all = m.addAction("Disable all occurrences of these values")
            a_dis_type = m.addAction("Disable all of this entity type")
            m.addSeparator()
            a_allow = m.addAction("Add to permanent allow-list (never flag again)")
            a_rule = m.addAction("Create permanent exact-match rule from value")
            a_copy = m.addAction("Copy original value")
            act = m.exec(self.table.viewport().mapToGlobal(pos))
            if not act:
                return
            sel = [self.findings[i] for i in idxs]
            keys = {self.vault.key(f.text) for f in sel}
            if act in (a_en, a_dis):
                for f in sel:
                    f.enabled = act is a_en
            elif act in (a_en_all, a_dis_all):
                for f in self.findings:
                    if self.vault.key(f.text) in keys:
                        f.enabled = act is a_en_all
            elif act is a_dis_type:
                types = {f.entity for f in sel}
                for f in self.findings:
                    if f.entity in types:
                        f.enabled = False
            elif act is a_allow:
                vals = sorted({f.text.strip() for f in sel})
                if QtWidgets.QMessageBox.question(
                        self, "Allow-list", f"Add {len(vals)} value(s) to rules/local/allow_list.yaml?\n"
                        "They will never be flagged again (except by manual rules).") != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                add_to_allow_list(vals)
                for f in self.findings:
                    if self.vault.key(f.text) in keys:
                        f.enabled = False
                self.reload_rules()
            elif act is a_rule:
                for f in sel:
                    mr = ManualRule("exact", f.text, f.entity, True)
                    append_rule_to_file(MANUAL_RULES_FILE, mr.to_rule_yaml())
                self.reload_rules()
                self.statusBar().showMessage(f"Saved {len(sel)} rule(s) to {MANUAL_RULES_FILE.name}", 5000)
                return
            elif act is a_copy:
                self.copy_text("\n".join(sorted({f.text for f in sel})))
                return
            self._refresh_after_edit()

        def _highlight(self):
            if self.analyzed_text is None or self.input.toPlainText() != self.analyzed_text:
                return
            sels = []
            ents = sorted({f.entity for f in self.findings})
            color = {e: QtGui.QColor(ENTITY_COLORS[i % len(ENTITY_COLORS)]) for i, e in enumerate(ents)}
            doc = self.input.document()
            for f in self.findings:
                s = QtWidgets.QTextEdit.ExtraSelection()
                cur = QtGui.QTextCursor(doc)
                cur.setPosition(py_to_qt_index(self.analyzed_text, f.start))
                cur.setPosition(py_to_qt_index(self.analyzed_text, f.end), QtGui.QTextCursor.MoveMode.KeepAnchor)
                s.cursor = cur
                fmt = QtGui.QTextCharFormat()
                if f.enabled:
                    fmt.setBackground(color[f.entity])
                    fmt.setForeground(QtGui.QColor("#111"))
                else:
                    fmt.setFontStrikeOut(True)
                    fmt.setForeground(QtGui.QColor("#9ca3af"))
                fmt.setToolTip(f"{f.entity} → {f.token}")
                s.format = fmt
                sels.append(s)
            self.input.setExtraSelections(sels)

        # ---- manual matcher
        def add_manual_rule(self):
            pat = self.m_pattern.text()
            if not pat.strip():
                return
            mtype = {"Exact Match": "exact", "Wildcard": "wildcard", "Custom Regex": "regex"}[self.m_type.currentText()]
            ent = re.sub(r"[^A-Z0-9_]", "_", self.m_entity.currentText().strip().upper()) or "CUSTOM"
            if not ENTITY_NAME_RE.match(ent):
                QtWidgets.QMessageBox.warning(self, "Entity", "Entity must be UPPER_SNAKE_CASE")
                return
            rule = ManualRule(mtype, pat if mtype == "regex" else pat.strip(), ent, self.m_ci.isChecked())
            try:
                rx = rule.compile()
                if rx.fullmatch(""):
                    raise re.error("pattern matches the empty string")
            except re.error as exc:
                QtWidgets.QMessageBox.warning(self, "Invalid pattern", str(exc))
                return
            self.manual_rules.append(rule)
            it = QtWidgets.QListWidgetItem(rule.label)
            it.setData(Qt.ItemDataRole.UserRole, rule.rid)
            self.m_list.addItem(it)
            self.m_pattern.clear()
            if self.analyzed_text is not None and self.input.toPlainText() == self.analyzed_text:
                self.findings, n = merge_manual_rule(self.analyzed_text, self.findings, rule, self.vault)
                it.setText(f"{rule.label}   ({n} match{'es' if n != 1 else ''})")
                self._refresh_after_edit()
                self.statusBar().showMessage(f"Manual rule matched {n} span(s)", 4000)
            else:
                self.statusBar().showMessage("Rule added - it will be applied on the next analysis", 4000)
                self._update_counts()

        def _selected_manual(self) -> List[ManualRule]:
            ids = {i.data(Qt.ItemDataRole.UserRole) for i in self.m_list.selectedItems()}
            return [r for r in self.manual_rules if r.rid in ids]

        def remove_manual_rules(self):
            rules = self._selected_manual()
            if not rules:
                return
            ids = {r.rid for r in rules}
            self.manual_rules = [r for r in self.manual_rules if r.rid not in ids]
            for i in reversed(range(self.m_list.count())):
                if self.m_list.item(i).data(Qt.ItemDataRole.UserRole) in ids:
                    self.m_list.takeItem(i)
            self.findings = [f for f in self.findings if f.recognizer.replace("manual:", "") not in ids]
            self._refresh_after_edit()
            self.statusBar().showMessage("Rule removed - re-analyze to restore any detections it had replaced", 5000)

        def promote_manual_rules(self):
            rules = self._selected_manual()
            if not rules:
                QtWidgets.QMessageBox.information(self, "Save rules", "Select one or more temporary rules first.")
                return
            try:
                for r in rules:
                    append_rule_to_file(MANUAL_RULES_FILE, r.to_rule_yaml())
            except Exception as exc:
                QtWidgets.QMessageBox.warning(self, "Save rules", str(exc))
                return
            self.reload_rules()
            QtWidgets.QMessageBox.information(self, "Save rules", f"Saved {len(rules)} rule(s) to "
                                              f"rules/local/{MANUAL_RULES_FILE.name}.\nConsider adding them to the "
                                              "shared GitHub rules repo so the whole team gets them.")

        # ================= Step 3
        def generate(self):
            if self.analyzed_text is None:
                QtWidgets.QMessageBox.information(self, APP_NAME, "Analyze some text first (Step 1).")
                self.tabs.setCurrentIndex(0)
                return
            if self.input.toPlainText() != self.analyzed_text:
                QtWidgets.QMessageBox.warning(self, APP_NAME, "The input changed after analysis. Re-analyze first "
                                              "so that every span is reviewed.")
                self.tabs.setCurrentIndex(0)
                return
            try:
                out, used = sanitize(self.analyzed_text, self.findings, self.vault)
            except TokenCollision as exc:
                QtWidgets.QMessageBox.warning(self, "Token conflict", str(exc))
                return
            self.output.setPlainText(out)
            self.last_sanitized = out
            leaks = leak_check(out, self.vault)
            if leaks:
                set_note(self.lbl_leak, f"Leak check: {len(leaks)} known sensitive value(s) still appear in the output "
                         f"(e.g. disabled rows). Review before sending.", "leak")
                self.lbl_leak.setToolTip("\n".join(leaks[:50]))
            else:
                set_note(self.lbl_leak, "Leak check passed: no known session value appears in the output.", "okmsg")
            self.lbl_gen.setText(f"Masked {len(used)} spans · {len({self.vault.key(f.text) for f in used})} "
                                 f"unique values")
            self.refresh_map()
            self.tabs.setCurrentIndex(1)
            log.info("generated sanitized prompt: %d spans masked, %d leaks flagged", len(used), len(leaks))

        def copy_text(self, text: str):
            if not text:
                return
            cb = QtWidgets.QApplication.clipboard()
            cb.setText(text)
            secs = int(self.config["behavior"].get("clipboard_clear_seconds", 0))
            msg = "Copied to clipboard"
            if secs > 0:
                QtCore.QTimer.singleShot(secs * 1000, lambda: cb.clear() if cb.text() == text else None)
                msg += f" (auto-clears in {secs}s)"
            self.statusBar().showMessage(msg, 4000)

        # ================= Step 4
        def restore(self):
            text = self.ai_input.toPlainText()
            if not text.strip():
                return
            out, n, unknown = self.vault.restore(text, lenient=self.chk_lenient.isChecked())
            self.restored.setPlainText(out)
            msg = f"Restored {n} token(s)"
            if unknown:
                msg += f" · {len(unknown)} unknown token(s): {', '.join(unknown[:5])}"
                self.lbl_restore.setStyleSheet("color:#b45309;")
            else:
                self.lbl_restore.setStyleSheet("color:#166534;")
            if not len(self.vault):
                msg = "Session map is empty - nothing to restore"
            self.lbl_restore.setText(msg)

        # ================= session map
        def refresh_map(self):
            q = self.map_filter.text().strip().casefold()
            reveal = self.chk_reveal.isChecked()
            rows = []
            for tok, val in self.vault.token_to_value.items():
                active = self.vault.key_to_token.get(self.vault.key(val)) == tok
                ent = self.vault.token_entity.get(tok, "")
                if q and q not in tok.casefold() and q not in ent.casefold() and (not reveal or q not in val.casefold()):
                    continue
                rows.append((tok, val if reveal else mask_value(val), ent, self.vault.created.get(tok, ""),
                             "active" if active else "alias (renamed)"))
            self.map_table.setSortingEnabled(False)
            self.map_table.setRowCount(len(rows))
            for r, vals in enumerate(rows):
                for c, v in enumerate(vals):
                    it = QtWidgets.QTableWidgetItem(v)
                    if c == 0:
                        it.setFont(_mono_font())
                    self.map_table.setItem(r, c, it)
            self.map_table.setSortingEnabled(True)
            set_badge(self.badge_session, f"Session: {len(self.vault)} tokens", "info")

        def export_map(self):
            if not len(self.vault):
                return
            if QtWidgets.QMessageBox.warning(
                    self, "Export session map",
                    "The exported file contains the RAW sensitive values in plaintext.\n"
                    "Store it only in a protected location and delete it when done.\n\nContinue?",
                    QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
            ) != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export session map",
                                                         f"pii_session_{_dt.datetime.now():%Y%m%d_%H%M}.json", "JSON (*.json)")
            if p:
                Path(p).write_text(json.dumps(self.vault.export(), indent=2, ensure_ascii=False), "utf-8")
                try:
                    os.chmod(p, 0o600)
                except Exception:
                    pass

        def import_map(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Import session map", "", "JSON (*.json)")
            if not p:
                return
            try:
                n = self.vault.import_(json.loads(Path(p).read_text("utf-8")))
            except Exception as exc:
                QtWidgets.QMessageBox.warning(self, "Import", f"Import failed: {exc}")
                return
            self.refresh_map()
            self.statusBar().showMessage(f"Imported {n} map entries", 4000)

        def reset_session(self):
            if (len(self.vault) or self.findings) and QtWidgets.QMessageBox.question(
                    self, "Reset session", "Clear the session map, staged detections, temporary rules and all "
                    "text boxes?\nTokens in earlier AI responses can no longer be restored after this.") \
                    != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            self.vault.clear()
            b = self.config["behavior"]
            self.vault.token_format = b.get("token_format", "<{entity}_{n}>")
            self.vault.case_insensitive = b.get("case_insensitive_values", True)
            self.findings, self.manual_rules, self.analyzed_text, self.last_sanitized = [], [], None, ""
            self.m_list.clear()
            for w in (self.input, self.output, self.ai_input, self.restored):
                w.clear()
            self.input.setExtraSelections([])
            set_note(self.lbl_leak, "", "leak")
            set_note(self.lbl_stale, "", "stale")
            self.lbl_gen.setText("")
            self.lbl_restore.setText("")
            self.populate_table()
            self.lbl_counts.setText("Session reset.")
            self.refresh_map()
            log.info("session reset")
            self.tabs.setCurrentIndex(0)

        def closeEvent(self, ev):
            if len(self.vault) and QtWidgets.QMessageBox.question(
                    self, "Quit", f"The session map ({len(self.vault)} tokens) will be destroyed and pending AI "
                    "responses can no longer be restored. Quit?") != QtWidgets.QMessageBox.StandardButton.Yes:
                ev.ignore()
                return
            log.removeHandler(self._log_handler)
            ev.accept()

    class _LogEmitter(QtCore.QObject):
        line = QtCore.pyqtSignal(str)

    class _QtLogHandler(logging.Handler):
        """Thread-safe: records from worker threads are marshalled to the GUI thread via a signal."""

        def __init__(self, widget):
            super().__init__()
            self.emitter = _LogEmitter()
            self.emitter.line.connect(widget.appendPlainText)

        def emit(self, record):
            try:
                self.emitter.line.emit(self.format(record))
            except Exception:
                pass


# ===========================================================================
# 9. Entry point
# ===========================================================================
def _ensure_dirs():
    for d in (LOCAL_RULES_DIR, REMOTE_RULES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def cli_validate(path: str) -> int:
    root = Path(path).resolve()
    rs = load_rules_dir(root)
    print(f"{APP_NAME} rule validation: {root}")
    for f in rs.files:
        print(f"  OK    {f}")
    for e in rs.errors:
        print("  ERROR " + e.replace("\n", "\n        "))
    for w in rs.warnings:
        print("  WARN  " + w)
    print(f"{len(rs.rules)} recognizers, {rs.pattern_count} patterns/wordlists, "
          f"{len(rs.allow_list)} allow-list values, {len(rs.errors)} error(s)")
    if PRESIDIO_OK and not rs.errors:
        try:
            for r in rs.rules:  # prove Presidio accepts every recognizer
                if r.patterns:
                    PatternRecognizer(supported_entity=r.entity, name=r.name,
                                      patterns=[Pattern(p.name, p.regex, p.score) for p in r.patterns],
                                      global_regex_flags=r.flags)
                if r.deny_list:
                    PatternRecognizer(supported_entity=r.entity, name=r.name, deny_list=r.deny_list)
        except Exception as exc:
            print(f"  ERROR Presidio rejected a recognizer: {exc}")
            return 1
    return 1 if rs.errors else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pii_sanitizer", description=f"{APP_NAME} - local PII sanitizer")
    ap.add_argument("--validate-rules", metavar="DIR", help="validate a rules folder and exit (for CI)")
    ap.add_argument("--self-test", action="store_true", help="load the NLP engine, analyze a sample and exit")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--log-file", metavar="FILE", help="write console output to FILE (the .exe has no console)")
    args = ap.parse_args(argv)
    streams = sys.stdout, sys.stderr
    out = open(args.log_file, "a", encoding="utf-8") if args.log_file else None
    if out or sys.stdout is None or sys.stderr is None:
        # the windowed .exe starts with no stdout/stderr; logging to None would fail on every record
        out = out or open(os.devnull, "w", encoding="utf-8")
        sys.stdout = sys.stdout if sys.stdout is not None and not args.log_file else out
        sys.stderr = sys.stderr if sys.stderr is not None and not args.log_file else out
    try:
        return _main(args, argv)
    finally:
        if out:
            root = logging.getLogger()
            for h in [h for h in root.handlers if getattr(h, "stream", None) is out]:
                root.removeHandler(h)
            sys.stdout, sys.stderr = streams
            out.close()


def _main(args, argv=None) -> int:
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr, force=True)
    if args.self_test:
        ok, lines = self_test()
        print("\n".join(lines))
        return 0 if ok else 1
    if args.version:
        print(f"{APP_NAME} {__version__}")
        return 0
    if args.validate_rules:
        return cli_validate(args.validate_rules)
    if not QT_OK:
        print(f"PyQt6 is required for the GUI: {QT_ERR}\n  pip install PyQt6", file=sys.stderr)
        return 2
    install_network_guard()
    _ensure_dirs()
    app = QtWidgets.QApplication(sys.argv if argv is None else [sys.argv[0]])
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    win = MainWindow(AppConfig())
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
