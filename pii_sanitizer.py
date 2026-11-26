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

__version__ = "1.7.1"
APP_NAME = "PII Shield"
APP_ID = "pii-shield"

import os

# Hard-disable any accidental model hub traffic from optional NLP back-ends.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

import argparse
import base64
import bisect
import contextvars
import copy
import ctypes
import datetime as _dt
import hashlib
import json
import logging
import math
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unicodedata
import uuid
from collections import OrderedDict, defaultdict
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, quote

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None

try:
    import onnxruntime as ort  # Hebrew NER runtime (optional, full build)
except ImportError:  # pragma: no cover
    ort = None

try:
    from tokenizers import Tokenizer as HfTokenizer  # Hebrew NER tokenizer (optional)
except ImportError:  # pragma: no cover
    HfTokenizer = None

try:
    import pypdfium2 as pdfium  # PDF text extraction + page rendering (optional)
except ImportError:  # pragma: no cover
    pdfium = None

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

HEBREW_MODEL_DIRNAME = "dictabert-ner"
HEBREW_MODEL_FILES = ("config.json", "tokenizer.json", "model_quantized.onnx")


def bundle_dir() -> Path:
    """Folder that holds the build's own files: PyInstaller's unpack folder, else next to this script."""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent


def bundled_model_dir() -> Path:
    return bundle_dir() / "models" / HEBREW_MODEL_DIRNAME


def _model_dir_error(d: Path) -> Optional[str]:
    """The OSError text when the model folder cannot be read (no permission), else None."""
    try:
        for name in HEBREW_MODEL_FILES:
            (d / name).is_file()
    except OSError as exc:
        return f"{d}: {exc}"
    return None


def _model_dir_valid(d: Path) -> bool:
    """True when d holds all model files. A folder that cannot be read is not valid."""
    try:
        return all((d / name).is_file() for name in HEBREW_MODEL_FILES)
    except OSError:
        return False


def _hebrew_model_dirs() -> Tuple[Path, Path]:
    return bundled_model_dir(), APP_DIR / "models" / HEBREW_MODEL_DIRNAME


def find_hebrew_model() -> Optional[Path]:
    """First valid Hebrew model folder: the bundled one, then APP_DIR/models/."""
    for d in _hebrew_model_dirs():
        if _model_dir_valid(d):
            return d
    return None


def hebrew_model_read_error() -> Optional[str]:
    """The error of the first model folder that cannot be read, else None."""
    for d in _hebrew_model_dirs():
        err = _model_dir_error(d)
        if err:
            return err
    return None


def hebrew_runtime_ok() -> bool:
    """True when the onnxruntime and tokenizers packages are present."""
    return ort is not None and HfTokenizer is not None


def is_full_build() -> bool:
    """True only when the model ships inside the build. Loads nothing."""
    return _model_dir_valid(bundled_model_dir())


def hebrew_status_suffix(status: str, model_present: bool) -> str:
    """Text for the end of the engine status label. A Hebrew model that is installed (or a
    folder that cannot be read) but did not load must show, else the user trusts a detection
    that does not run."""
    if status == "loaded":
        return "  \u00b7  Hebrew NER"
    if status == "off":
        return ""
    if model_present or status.startswith("failed"):
        return "  \u00b7  Hebrew NER: failed (see Log)"
    return ""
RULES_DIR = APP_DIR / "rules"
LOCAL_RULES_DIR = RULES_DIR / "local"
REMOTE_RULES_DIR = RULES_DIR / "remote"
BACKUP_DIR = APP_DIR / "backups"
CONFIG_PATH = APP_DIR / "config.json"
MANUAL_RULES_FILE = LOCAL_RULES_DIR / "promoted_rules.yaml"
ALLOW_LIST_FILE = LOCAL_RULES_DIR / "allow_list.yaml"
SYNC_MANIFEST = ".sync_manifest.json"

RULE_EXTENSIONS = {".yaml", ".yml", ".json"}
OVERRIDES_FILE_NAME = "overrides.yaml"   # local/overrides.yaml holds the rules manager's markers and copies
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
        "score_threshold": 0.85,
        "builtin_entities": list(DEFAULT_BUILTIN_ENTITIES),
        "detect_organizations": True,   # spaCy ORG: some false positives, but safer to over-detect
        "skip_ner_on_logs": False,      # drop spaCy PERSON/ORG/LOCATION findings when the input looks like a log
        "check_presidio_updates": True,  # ask PyPI at startup; reports only, never installs
        "hebrew_ner": True,             # DictaBERT NER on Hebrew lines (needs the Hebrew model files)
    },
    "behavior": {
        "token_format": "<{entity}_{n}>",
        "propagate_values": True,        # mask every literal occurrence of a detected value
        "case_insensitive_values": True,  # "SRV-DC01" and "srv-dc01" share a token
        "lenient_restore": True,         # also restore HOSTNAME_1, [HOSTNAME_1], &lt;HOSTNAME_1&gt;
        "clipboard_clear_seconds": 0,    # 0 = never auto-clear
        "offline_mode": False,           # True = no network at all: no GitHub sync, no update checks
        "git_scan_last_repo": "",        # last folder used in Scan Git Repo
        "split_chars": 50000,            # part size for Split in the Sanitize tab
        "split_headers": True,           # each part starts with "--- Part i of n ---"
        "group_values": True,            # review table: one row per value, with a Count column
    },
    "pdf": {
        "ocr_enabled": True,             # read scanned pages with Tesseract
        "tesseract_path": "",            # empty = look in the bundle, then on PATH
        "ocr_languages": "heb+eng",
        "ocr_dpi": 300,
        "ocr_timeout": 120,              # seconds per page
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


# ---- validators usable from YAML: `validator: luhn | israeli_id | ipv4 | private_ipv4 | high_entropy | not_well_known`
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


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = defaultdict(int)
    for c in text:
        counts[c] += 1
    n = len(text)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def _v_high_entropy(text: str) -> bool:
    """Random-looking hex (32+) or base64 (40+) blob. Base64 also needs a letter and a digit or + /."""
    if re.fullmatch(r"[A-Fa-f0-9]{32,}", text):
        return _shannon_entropy(text) > 3.5
    if re.fullmatch(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        return (_shannon_entropy(text) > 3.5 and bool(re.search(r"[A-Za-z]", text))
                and bool(re.search(r"[0-9+/]", text)))
    return False


# Built-in accounts, groups, profile folders and SIDs that identify no person or company.
WELL_KNOWN_NAMES = {
    "root", "system", "daemon", "nobody", "www-data", "nginx", "apache", "sshd", "syslog", "local",
    "network", "anonymous", "local service", "network service", "nt authority", "builtin",
    "public", "default", "default user", "all users", "shared", ".", "..",
    "users", "computers", "configuration", "schema", "domain users", "domain admins",
    "domain computers", "enterprise admins", "administrators",
}
_WELL_KNOWN_SID_RE = re.compile(r"S-1-(?:[0-4]-\d+|5-\d{1,2}|5-32-\d+|5-80-[\d-]+|15-[\d-]+|16-\d+)", re.I)


def _v_not_well_known(text: str) -> Optional[bool]:
    """False for a well-known account or SID, else None (the pattern score stays)."""
    value = text.strip()
    if value.casefold() in WELL_KNOWN_NAMES or _WELL_KNOWN_SID_RE.fullmatch(value):
        return False
    return None


# A validator returns True (score 1.0), False (drop the match) or None (keep the pattern score).
VALIDATORS: Dict[str, Callable[[str], Optional[bool]]] = {
    "luhn": _v_luhn,
    "israeli_id": _v_israeli_id,
    "ipv4": _v_ipv4,
    "private_ipv4": _v_private_ipv4,
    "high_entropy": _v_high_entropy,
    "not_well_known": _v_not_well_known,
}

# A pattern with a (?P<value>...) group masks only that group, e.g. password=(?P<value>\S+).
VALUE_GROUP = "value"


def value_span(m) -> Tuple[int, int]:
    """Span to mask for a regex match: the 'value' group if the pattern has one, else the whole match.
    (-1, -1) when the group did not take part in the match."""
    if VALUE_GROUP in m.re.groupindex:
        return m.span(VALUE_GROUP)
    return m.span()


JSON_KEY_RE = re.compile(r"^[A-Za-z0-9_.\- $@]{1,64}$")


def _json_key_regex(key: str) -> str:
    """Key matcher that ignores case and the separators - _ . and space: userName = user_name = USER-NAME."""
    chars = re.sub(r"[-_. ]", "", key).lower()
    return r"[-_. ]?".join(re.escape(c) for c in chars)


def json_key_patterns(keys: Sequence[str], contains: Sequence[str]) -> List[Tuple[str, str]]:
    """(name, regex) pairs that mask the value of a JSON or Python-dict field by its key name.
    Strings need 2+ characters and numbers 3+ digits; booleans, null, "" and "-" are never masked."""
    alts = sorted({_json_key_regex(k) for k in keys if _json_key_regex(k)}, key=len, reverse=True)
    frags = sorted({_json_key_regex(k) for k in contains if _json_key_regex(k)}, key=len, reverse=True)
    parts = list(alts)
    if frags:
        parts.insert(0, r"[\w.\- $@]*?(?:" + "|".join(frags) + r")[\w.\- $@]*")
    key = "(?:" + "|".join(parts) + ")"
    return [
        ("json_string", r'"' + key + r'"\s*:\s*"(?!-?")(?P<value>(?:[^"\\\n]|\\.){2,})"'),
        ("json_escaped", r'\\"' + key + r'\\"\s*:\s*\\"(?!-?\\")(?P<value>[^"\\\n]{2,})\\"'),
        ("dict_string", r"'" + key + r"'\s*:\s*'(?!-?')(?P<value>[^'\\\n]{2,})'"),
        ("json_number", r"""["']""" + key + r"""["']\s*:\s*(?P<value>-?\d{3,}(?:\.\d+)?)(?![\w.])"""),
    ]



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
    json_keys: List[str] = field(default_factory=list)          # mask JSON / dict values by key name
    json_key_contains: List[str] = field(default_factory=list)
    enabled: bool = True
    raw: dict = field(default_factory=dict)            # deep copy of the recognizer mapping
    overrides: Optional["RuleDef"] = None              # the rule this one replaced or switched
    is_marker: bool = False                            # a local {name, enabled} entry
    broken: bool = False                               # a disabled rule that has errors

    @property
    def flags(self) -> int:
        f = re.DOTALL | re.MULTILINE
        return f if self.case_sensitive else f | re.IGNORECASE


@dataclass
class RuleSet:
    rules: List[RuleDef] = field(default_factory=list)       # active rules only
    all_rules: List[RuleDef] = field(default_factory=list)   # active and disabled, in load order
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


_FULL_RULE_KEYS = ("entity", "supported_entity", "patterns", "deny_list", "wordlist", "json_keys", "json_key_contains")


def is_marker_mapping(r: dict) -> bool:
    """A marker has a name and 'enabled' and nothing that defines what to match."""
    return "name" in r and "enabled" in r and not any(k in r for k in _FULL_RULE_KEYS)


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
        name = str(r.get("name", "")).strip()
        src = path.relative_to(root).as_posix() if root in path.parents else path.name
        name_ok = bool(name) and bool(RULE_NAME_RE.match(name))
        if is_marker_mapping(r):
            if not name_ok:
                if not r["enabled"]:    # a disabled entry was skipped silently before: keep it harmless
                    warnings.append(f"{path.name}:{name or i + 1}: disabled entry skipped: invalid or missing 'name'")
                else:
                    problems.append(f"{path.name}:{name or i + 1}: invalid or missing 'name'")
                continue
            rules.append(RuleDef(name=name, entity="", enabled=bool(r["enabled"]), is_marker=True,
                                 source_file=src, raw=copy.deepcopy(r)))
            continue
        disabled = r.get("enabled", True) is False
        rule_problems: List[str] = []      # a disabled rule's problems become a warning, not a file error
        entity = str(r.get("entity", r.get("supported_entity", ""))).strip().upper()
        where = f"{path.name}:{name or i + 1}"
        if not name_ok:
            if disabled:
                warnings.append(f"{where}: disabled entry skipped: invalid or missing 'name'")
                continue
            rule_problems.append(f"{where}: invalid or missing 'name'")
        if not ENTITY_NAME_RE.match(entity):
            rule_problems.append(f"{where}: invalid 'entity' (use UPPER_SNAKE_CASE, e.g. HOSTNAME)")
        try:
            score = float(r.get("score", 0.85))
            if not 0 < score <= 1:
                raise ValueError
        except (TypeError, ValueError):
            rule_problems.append(f"{where}: 'score' must be in (0, 1]")
            score = 0.85
        validator = r.get("validator")
        if validator and validator not in VALIDATORS:
            rule_problems.append(f"{where}: unknown validator '{validator}' (have: {', '.join(VALIDATORS)})")
        case_sensitive = bool(r.get("case_sensitive", False))
        rd = RuleDef(name=name, entity=entity, score=score, case_sensitive=case_sensitive,
                     validator=validator or None, description=str(r.get("description", "")),
                     context=[str(c) for c in _as_list(r.get("context"))],
                     source_file=src, enabled=not disabled, raw=copy.deepcopy(r))

        for j, p in enumerate(_as_list(r.get("patterns"))):
            if isinstance(p, str):
                p = {"regex": p}
            if not isinstance(p, dict) or "regex" not in p:
                rule_problems.append(f"{where}: pattern #{j + 1} needs a 'regex'")
                continue
            rx = str(p["regex"])
            try:
                compiled = re.compile(rx, rd.flags)
            except re.error as exc:
                rule_problems.append(f"{where}: pattern #{j + 1} invalid regex: {exc}")
                continue
            if compiled.search("") is not None and compiled.fullmatch("") is not None:
                rule_problems.append(f"{where}: pattern #{j + 1} matches the empty string")
                continue
            if _NESTED_QUANT_RE.search(rx):
                warnings.append(f"{where}: pattern #{j + 1} has nested quantifiers (possible ReDoS)")
            try:
                pscore = float(p.get("score", score))
                if not 0 < pscore <= 1:
                    raise ValueError
            except (TypeError, ValueError):
                rule_problems.append(f"{where}: pattern #{j + 1} score must be in (0, 1]")
                continue
            rd.patterns.append(PatternDef(str(p.get("name", f"{name}_{j + 1}")), rx, pscore))

        deny = [str(x).strip() for x in _as_list(r.get("deny_list")) if str(x).strip()]
        for wl in _as_list(r.get("wordlist")):
            try:
                wl_path = _safe_child(path.parent, str(wl), root)
                if not wl_path.exists():
                    rule_problems.append(f"{where}: wordlist not found: {wl}")
                    continue
                deny.extend(_read_wordlist(wl_path))
            except RuleError as exc:
                rule_problems.append(f"{where}: {exc}")
        rd.deny_list = sorted(set(deny), key=lambda s: (-len(s), s))

        rd.json_keys = [str(k).strip() for k in _as_list(r.get("json_keys")) if str(k).strip()]
        rd.json_key_contains = [str(k).strip() for k in _as_list(r.get("json_key_contains")) if str(k).strip()]
        bad_keys = [k for k in rd.json_keys + rd.json_key_contains if not JSON_KEY_RE.match(k)]
        if bad_keys:
            rule_problems.append(f"{where}: invalid JSON key names {bad_keys} (letters, digits, - _ . $ @ and space)")
        elif rd.json_keys or rd.json_key_contains:
            for pname, rx in json_key_patterns(rd.json_keys, rd.json_key_contains):
                rd.patterns.append(PatternDef(f"{name}_{pname}", rx, score))

        if not rd.patterns and not rd.deny_list:
            rule_problems.append(f"{where}: needs at least one of 'patterns', 'deny_list', 'wordlist', 'json_keys'")
        if disabled:
            if rule_problems:
                warnings.append(f"disabled rule '{name}' in {src} has errors: {'; '.join(rule_problems)}")
                rd.patterns, rd.deny_list, rd.broken = [], [], True
        else:
            problems.extend(rule_problems)
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
        rs.files.append(label + f.relative_to(root).as_posix())
        rs.warnings.extend(label + w for w in warns)
        rs.allow_list |= allow
        for r in rules:
            r.source_file = label + r.source_file
            old = by_name.pop(r.name, None)
            if r.is_marker:
                if old is None:
                    rs.warnings.append(f"marker '{r.name}' in {r.source_file} has no rule to change")
                elif r.enabled and old.broken:
                    rs.warnings.append(f"cannot switch on '{r.name}': the rule has errors")
                    by_name[r.name] = old
                else:
                    by_name[r.name] = dataclasses.replace(
                        old, enabled=r.enabled, is_marker=True, raw=r.raw,
                        source_file=r.source_file, overrides=old)
                continue
            r.overrides = old
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
        local_overrides = root / "local" / OVERRIDES_FILE_NAME
        files.sort(key=lambda p: (0 if remote in p.parents else 2 if p == local_overrides else 1, str(p)))
        _load_rule_files(root, files, rs, by_name)
    rs.all_rules = list(by_name.values())
    rs.rules = [r for r in rs.all_rules if r.enabled]
    if strict and rs.errors:
        raise RuleError("\n".join(rs.errors))
    return rs


# Default rules embedded in the script: active on a fresh install, updated with the app,
# and overridden by any remote or local rule with the same name.
BUNDLED_LABEL = "bundled/"
# BEGIN BUNDLED RULES (generated by tools/bundle_rules.py from github-repo-template/rules/ - do not edit)
BUNDLED_RULES: Dict[str, str] = {
    "hosts.yaml": r"""# Host names in log lines: syslog host field, host= pairs, Kerberos SPNs, default Windows names.
# Many patterns are adapted from socprime/logtotal-sanitizer (Apache-2.0). See NOTICE in the app repo.
version: 1

recognizers:

  - name: SyslogHost
    entity: HOSTNAME
    description: The host field of a syslog line - "Oct 12 10:01:02 webgw01 sshd[311]:". Log levels such as INFO are skipped.
    score: 0.9
    patterns:
      - name: bsd_syslog
        regex: '\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?!(?:TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRIT|CRITICAL|FATAL|ALERT|EMERG)\b)(?P<value>(?=[\w.-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)(?=\s+[A-Za-z][\w.@/-]*(?:\[\d+\])?:)'
      - name: iso_syslog
        regex: '\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?!(?:TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRIT|CRITICAL|FATAL|ALERT|EMERG)\b)(?P<value>(?=[\w.-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*)(?=\s+[A-Za-z][\w.@/-]*(?:\[\d+\])?:)'

  - name: HostKeyValue
    entity: HOSTNAME
    description: Values of host=, hostname=, computer= and similar log fields
    score: 0.85
    patterns:
      - name: host_kv
        regex: '\b(?:host|hostname|host_name|computer|computer_?name|workstation|shost|dhost|server)\s*=\s*["'']?(?P<value>(?=[\w.-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)'

  - name: KerberosSpnHost
    entity: HOSTNAME
    description: The host part of a Kerberos SPN - HTTP/web01.acme.com@ACME.COM (the realm must be UPPERCASE)
    score: 0.9
    patterns:
      - name: spn
        regex: '\b[A-Za-z][A-Za-z0-9]*/(?P<value>[A-Za-z0-9][A-Za-z0-9.-]*)(?::\d+)?(?=@(?-i:[A-Z0-9-]+(?:\.[A-Z0-9-]+)+)\b)'

  - name: WindowsDefaultNames
    entity: HOSTNAME
    description: Default Windows computer names - WIN-4F7K2LQ9PZ1, DESKTOP-8HD2KQ1, LAPTOP-1A2B3C4D
    score: 0.85
    case_sensitive: true
    patterns:
      - {name: default_name, regex: '\b(?:WIN|DESKTOP|LAPTOP)-(?=[A-Z]*\d)[A-Z0-9]{7,12}\b'}

  - name: InventoryHosts
    entity: HOSTNAME
    description: Inventory-style names that end in a number - web-prod-01, srv-app-07, node-pool-12
    score: 0.85
    patterns:
      - {name: inventory, regex: '(?<![\w.-])(?:srv|web|db|app|host|node|pod|vm|k8s)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-\d+(?![\w-])'}

  - name: EnvironmentNames
    entity: HOSTNAME
    description: >-
      Name + environment suffix - acme-prod, billing-dev, acme-test, shop-uat-02. Skips common words
      that look the same - unit-test, load-test, e2e-test, pen-test, a-b-test, pre-prod, non-prod, web-dev.
    score: 0.85
    patterns:
      - name: env_suffix
        regex: '(?<![\w.-])(?!(?:(?:unit|load|smoke|stress|perf|performance|e2e|pen|integration|regression|acceptance|a-b|ab|self|re|speed|field|user|beta|alpha|crash)-test|(?:non|pre|post)-prod(?:uction)?|web-dev)(?:-\d+)?(?![\w-]))[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-(?:prod|production|dev|develop|test|qa|uat|stg|staging|preprod|sandbox)(?:-\d+)?(?![\w-])'
""",
    "identity.yaml": r"""# Accounts and identifiers in logs: SIDs, LDAP, cloud principals, log user fields, home folders.
# Many patterns are adapted from socprime/logtotal-sanitizer (Apache-2.0). See NOTICE in the app repo.
# validator not_well_known skips built-in names such as root, SYSTEM, Public and S-1-5-18.
version: 1

recognizers:

  - name: WindowsSID
    entity: SID
    description: Windows security identifiers. Well-known SIDs such as S-1-5-18 and S-1-5-32-544 are skipped.
    score: 0.9
    validator: not_well_known
    case_sensitive: true
    patterns:
      - {name: sid, regex: '\bS-1-(?:\d+-){1,14}\d+\b'}

  - name: DirectoryUsers
    entity: USERNAME
    description: LDAP uid= and sAMAccountName= values and cn= names
    score: 0.85
    validator: not_well_known
    patterns:
      - {name: ldap_uid, regex: '\b(?:uid|sAMAccountName)=(?P<value>[\w.@+-]*[A-Za-z][\w.@+-]*)'}
      - {name: ldap_cn,  regex: '\bcn=(?P<value>[A-Za-z0-9.''-]+(?: [A-Za-z0-9.''-]+){0,3})'}

  - name: CloudPrincipals
    entity: USERNAME
    description: AWS IAM users, AWS assumed-role session names and Kubernetes service accounts
    score: 0.85
    patterns:
      - {name: aws_iam_user,     regex: '\barn:aws[\w-]*:iam::\d*:user/(?:[\w+=,.@-]+/)*(?P<value>[\w+=,.@-]+)'}
      - {name: aws_role_session, regex: '\barn:aws[\w-]*:sts::\d*:assumed-role/[\w+=,.@-]+/(?P<value>[\w+=,.@-]+)'}
      - {name: k8s_service_acct, regex: '\bsystem:serviceaccount:[a-z0-9-]+:(?P<value>[a-z0-9-]+)'}

  - name: LogUserFields
    entity: USERNAME
    description: User names in sshd, PAM and sudo lines and in user=value pairs. System accounts such as root and ARN values (principal=arn:aws:...) are skipped.
    score: 0.85
    validator: not_well_known
    patterns:
      - {name: sshd_login,   regex: '\b(?:Accepted|Failed) \w+ for (?:invalid user |illegal user )?(?P<value>[A-Za-z0-9._-]+) from\b'}
      - {name: sshd_invalid, regex: '\b(?:Invalid|Illegal) user (?P<value>[A-Za-z0-9._-]+) from\b'}
      - {name: sudo,         regex: '\bsudo:\s+(?P<value>[A-Za-z0-9._-]+)(?=\s+:)'}
      - {name: user_kv,      regex: '\b(?:user|username|user_name|ruser|suser|duser|logname|login|account|owner|actor|principal|requester|created_?by|modified_?by|assignee|operator)\s*=\s*["'']?(?!arn:)(?P<value>[\w.@+-]*[A-Za-z][\w.@+-]*)'}

  - name: HomeDirectoryUser
    entity: USERNAME
    description: The user name in home and profile paths - /home/dlevi, /Users/dlevi, C:\Users\dlevi. The rest of the path stays visible.
    score: 0.85
    validator: not_well_known
    patterns:
      - {name: unix_home,       regex: '(?<![\w.-])(?:/export|/usr|/var)?/home/(?P<value>[^/\\\s"''<>|]+)'}
      - {name: mac_users,       regex: '(?<![\w.:-])(?:/mnt/[A-Za-z])?(?-i:/Users/)(?P<value>[^/\\\s"''<>|]+)'}
      - {name: windows_profile, regex: '\b[A-Za-z]:[\\/]{1,2}(?:Users|Documents and Settings)[\\/]{1,2}(?P<value>[^/\\\s"''<>|]+)'}
      - {name: wsl_home,        regex: '//wsl\$/[\w.-]+/home/(?P<value>[^/\\\s"''<>|]+)'}
""",
    "json_fields.yaml": r"""# Mask JSON and Python-dict values by their key name: {"userName": "dlevi"} -> {"userName": "<USERNAME_1>"}.
# Key matching ignores case and the separators - _ . and space, so userName = user_name = USER-NAME.
# json_keys must match the whole key. json_key_contains matches any key that contains the text.
# Key lists are adapted from socprime/logtotal-sanitizer (Apache-2.0). See NOTICE in the app repo.
version: 1

recognizers:

  - name: JsonSecretFields
    entity: SECRET
    score: 0.9
    json_keys: [password, passwd, pwd, pass, token, authorization, apiKey, xApiKey, secret, accessToken,
                refreshToken, idToken, clientSecret, privateKey, secretKey, apiSecret, credentials,
                accessKey, secretAccessKey, awsSecretAccessKey, awsSessionToken, xAmzSecurityToken,
                signature, bearerToken, authToken, authKey, apiToken, appSecret, consumerSecret,
                oauthToken, oauthTokenSecret, masterKey, encryptionKey, sharedKey, sharedSecret,
                webhookSecret, signingSecret, signingKey, connectionString, connStr, passwordHash,
                pwdHash, otp, totp, mfaCode, oneTimePassword, verificationCode, recoveryCode, sshKey,
                subscriptionKey, ocpApimSubscriptionKey, xAuthToken, xAccessToken, proxyAuthorization,
                sasToken, vaultToken, xVaultToken, jwt, samlResponse, samlAssertion, pinBlock,
                sessionId, sid, cookie, cookies, setCookie, jsessionid, phpsessid, csrfToken, xsrfToken,
                xCsrfToken, csrf, sessionToken, sessionKey, sessionCookie, session, rememberToken, authCookie]
    json_key_contains: [password, passwd, secret, apikey, accesstoken, refreshtoken, idtoken, authtoken,
                        bearertoken, privatekey, credential, passphrase, connectionstring, sessionid,
                        sessiontoken, cookie, csrf, xsrf]

  - name: JsonUserFields
    entity: USERNAME
    score: 0.9
    validator: not_well_known
    json_keys: [user, username, login, account, accountName, samAccountName, userPrincipalName, upn,
                actor, principal, owner, createdBy, modifiedBy, updatedBy, deletedBy, requestedBy,
                submittedBy, approvedBy, userId, uid, usr, loginName, loginId, logonName, userSid,
                author, committer, reporter, assignee, impersonatedUser, effectiveUser, sudoUser, ruser,
                suser, duser, employeeId, employeeNumber, staffId, studentId, gecos, distinguishedName,
                userDn, targetUserName, subjectUserName, initiator]
    json_key_contains: [username, principalname, loginname, accountname]

  - name: JsonPersonFields
    entity: PERSON
    score: 0.9
    json_keys: [firstName, lastName, fullName, displayName, userDisplayName, givenName, surname,
                middleName, nickname, maidenName, familyName, legalName, realName, customerName,
                contactName]
    json_key_contains: [firstname, lastname, fullname]

  - name: JsonHostFields
    entity: HOSTNAME
    score: 0.9
    json_keys: [host, hostname, fqdn, computer, computerName, serverName, nodeName, dnsName, machineName,
                targetHost, remoteHost, sourceHost, destinationHost, srcHost, dstHost, shost, dhost,
                clientHost, hostFqdn, workstation, workstationName, deviceName, deviceHostname, sni,
                serverNameIndication, tlsServerName, virtualHost, vhost, httpHost, xForwardedHost,
                qname, queryName, smtpHost, mailServer]
    json_key_contains: [computer, hostname, fqdn, workstation]

  - name: JsonDomainFields
    entity: DOMAIN
    score: 0.9
    json_keys: [domain, domainName, dnsDomain, targetDomainName, subjectDomainName]
    json_key_contains: [domainname]
""",
    "patterns.json": r"""{
  "version": 1,
  "recognizers": [
    {
      "name": "TicketIDs",
      "entity": "TICKET_ID",
      "description": "Internal ticketing references (JSON format example)",
      "score": 0.85,
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
#       patterns:        list of {name, regex, score}  (Python 're' syntax). A (?P<value>...) group
#                        masks only that part: 'password=(?P<value>\S+)' -> password=<SECRET_1>
#       deny_list:       list of literal values (whole-word match)
#       wordlist:        path(s) to .txt files, one value per line, relative to this file
#       json_keys:       JSON / Python-dict key names whose values are masked (case and - _ . ignored)
#       json_key_contains: key fragments; any key that contains one is masked
#       context:         words that boost the score when found near a match (Presidio)
#       score:           0-1, default for patterns and the score for deny_list/wordlist hits
#       case_sensitive:  default false
#       validator:       optional: luhn | israeli_id | ipv4 | private_ipv4 | high_entropy | not_well_known
#       enabled:         default true
#   A rule needs at least one of: patterns, deny_list, wordlist, json_keys, json_key_contains.
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
    score: 0.85
    patterns:
      - name: prefix_2_3_digits
        regex: '(?<![\w.-])(?:host|server|srv|svr|dc|ws|pc|lt|vm|sql|db|fs|nas|fw|rtr|esx|hv|vdi|rds|exch|web|app)\d{2,3}[a-z]?(?![\w-])'
    context: [server, host, hostname, machine, computer, endpoint, device]

  - name: NetworkAppliances
    entity: HOSTNAME
    description: Vendor + model appliance host names - fortigate40d, FGT-60F, asa5506, synology918 (no space, so "FortiGate 40D" prose is skipped)
    score: 0.85
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

  - name: UNCPath
    entity: UNC_PATH
    description: UNC paths such as \\server\share. Backslashes inside a path such as C:\\Users\\x are skipped.
    score: 0.85
    patterns:
      - name: unc
        regex: '(?<![\w\\:$.-])\\\\[A-Za-z0-9._$-]+\\[^\s"''<>|]+'

  - name: CustomerNames
    entity: CUSTOMER
    score: 0.95
    wordlist: wordlists/customers.txt

  # ---------------------------------------------------------------- cloud / EDR identifiers
  - name: AzureGuidInContext
    entity: TENANT_ID
    description: GUIDs only flagged when tenant/subscription/client context is nearby (base score below threshold)
    score: 0.55
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
    description: key=value credentials in configs and logs. Only the value is masked - password=<SECRET_1>. A pwd value that starts with / is a working directory (sudo PWD=/home/x), so it is skipped.
    score: 0.85
    patterns:
      - name: kv_secret
        regex: '(?:password|passwd|pwd(?!["'']?\s*[:=]\s*["'']?/)|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|signing[_-]?key|token)["'']?\s*[:=]\s*["'']?(?P<value>[^\s"'',;}]{6,})'

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
    score: 0.55
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
    score: 0.85
    patterns:
      - name: il_phone
        regex: '(?<![\d+])(?:\+972[-\s]?|0)(?:5\d|[23489]|7\d)[-\s]?\d{3}[-\s]?\d{4}(?!\d)'
""",
    "secrets.yaml": r"""# Tokens, credentials and session cookies.
# Many patterns are adapted from socprime/logtotal-sanitizer (Apache-2.0). See NOTICE in the app repo.
# A (?P<value>...) group masks only that part of the match: "Bearer <SECRET_1>".
version: 1

recognizers:

  - name: ApiTokens
    entity: SECRET
    description: Vendor API keys with a fixed prefix - OpenAI, Anthropic, Google, Stripe, npm, SendGrid, Slack webhooks, Twilio
    score: 0.95
    case_sensitive: true
    patterns:
      - {name: openai_project, regex: '\bsk-proj-[A-Za-z0-9_-]{16,}'}
      - {name: anthropic,      regex: '\bsk-ant-[A-Za-z0-9_-]{20,}'}
      - {name: openai,         regex: '\bsk-[A-Za-z0-9]{20,}\b'}
      - {name: google_api,     regex: '\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])'}
      - {name: stripe,         regex: '\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b'}
      - {name: npm,            regex: '\bnpm_[A-Za-z0-9]{36,}\b'}
      - {name: sendgrid,       regex: '\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'}
      - {name: slack_webhook,  regex: 'hooks\.slack\.com/services/[A-Za-z0-9/_-]{16,}'}
      - {name: aws_key_id,     regex: '\b(?:ABIA|ACCA)[0-9A-Z]{16}\b'}
      - {name: twilio,         regex: '\b(?:AccountSid|AuthToken|Sid)\s*[=:]\s*(?P<value>(?:AC|SK)[0-9a-fA-F]{32})\b'}

  - name: AuthHeaders
    entity: SECRET
    description: Bearer and Basic credentials and AWS secret keys. Only the credential is masked. Outside an Authorization header the credential must contain a digit, so "Bearer authentication" is skipped.
    score: 0.9
    patterns:
      - {name: bearer_header, regex: '\bAuthorization\s*[:=]\s*["'']?Bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})'}
      - {name: basic_header,  regex: '\bAuthorization\s*[:=]\s*["'']?Basic\s+(?P<value>[A-Za-z0-9+/]{8,}={0,2})'}
      - {name: bearer,        regex: '\bBearer\s+(?P<value>(?=[A-Za-z._~+/=-]*\d)[A-Za-z0-9._~+/=-]{8,})'}
      - {name: basic,         regex: '\bBasic\s+(?P<value>(?=[A-Za-z]*[0-9+/=])[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])'}
      - {name: aws_secret,    regex: '\baws_secret_access_key\s*[=:]\s*["'']?(?P<value>[A-Za-z0-9/+=]{30,})'}

  - name: UrlCredentials
    entity: SECRET
    description: user:password inside a URL - https://admin:<SECRET_1>@git.example.com (the host stays visible)
    score: 0.95
    patterns:
      - {name: url_userinfo, regex: '\b[a-z][a-z0-9+.-]{1,15}://(?P<value>[^/@\s:]+:[^/@\s]+)@'}

  - name: CommandLineSecrets
    entity: SECRET
    description: Values of --password, --token, --api-key and similar command-line flags
    score: 0.9
    patterns:
      - {name: cli_flag, regex: '--(?:password|passwd|secret|token|api-key|apikey|access-token|client-secret)(?:\s+|=)["'']?(?P<value>[^\s"'']{4,})'}

  - name: SessionCookies
    entity: SECRET
    description: Session and CSRF cookie values - JSESSIONID, PHPSESSID, ASP.NET_SessionId, csrftoken (the cookie name stays visible; sid=S-1-... is left to WindowsSID)
    score: 0.9
    patterns:
      - name: session_cookie
        regex: '(?<![\w-])(?:session_?id|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID[A-Z0-9]*|connect\.sid|laravel_session|_session_id|csrftoken|csrf_token|XSRF-TOKEN|remember_token|S?SESS[a-f0-9]{32}|sid)=(?!S-1-\d)(?P<value>[^;\s]{8,})'

  - name: HighEntropyBlobs
    entity: SECRET
    enabled: false
    description: >-
      Random-looking hex (32+) or base64 (40+) strings. Off by default because it also masks file
      hashes. To turn it on, copy this rule to rules/local/ and set enabled to true.
    score: 0.85
    validator: high_entropy
    case_sensitive: true
    patterns:
      - {name: base64_blob, regex: '(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])'}
      - {name: hex_blob,    regex: '\b[A-Fa-f0-9]{32,}\b'}
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


SAVED_RULES_FILE_NAME = "promoted_rules.yaml"   # the rules manager's "saved" rules (local/)


def rule_kind(rule: RuleDef) -> str:
    """Where a rule lives: bundled, remote, saved, override, or hand-edited (read only)."""
    src = rule.source_file.replace("\\", "/")
    if src.startswith(BUNDLED_LABEL):
        return "bundled"
    if src.startswith("remote/"):
        return "remote"
    if src == f"local/{SAVED_RULES_FILE_NAME}":
        return "saved"
    if src == f"local/{OVERRIDES_FILE_NAME}":
        return "override"
    return "hand-edited"


def raw_fingerprint(raw: dict) -> str:
    """12 hex chars that identify the content of a rule mapping."""
    text = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def override_status(rule: RuleDef) -> Optional[str]:
    """For a copy of another rule: None (original unchanged), "changed" or "removed"."""
    if rule_kind(rule) != "override" or rule.is_marker:
        return None
    sha = (rule.raw.get("metadata") or {}).get("original_sha")
    if not sha:
        return None
    if rule.overrides is None:
        return "removed"
    return None if sha == raw_fingerprint(rule.overrides.raw) else "changed"


def update_rule_file(path: Path, rules_root: Path, change: Callable[[List[dict]], List[dict]]) -> None:
    """Apply `change` to the recognizer list of a writable rule file. Validates the whole new
    document, then replaces the file atomically. Raises RuleError and leaves the file as it was
    on bad existing YAML or a failed validation."""
    path, rules_root = Path(path), Path(rules_root)
    if path.name not in (SAVED_RULES_FILE_NAME, OVERRIDES_FILE_NAME) \
            or path.parent.resolve() != (rules_root / "local").resolve():
        raise RuleError(f"{path.name}: the app does not write this file")
    doc: dict = {"version": 1, "recognizers": []}
    if path.exists():
        if yaml is None:
            raise RuleError("PyYAML is not installed")
        try:
            loaded = yaml.safe_load(path.read_text("utf-8-sig"))
        except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
            raise RuleError(f"{path.name}: cannot read ({exc.__class__.__name__}); file left unchanged")
        if isinstance(loaded, list):
            loaded = {"version": 1, "recognizers": loaded}
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise RuleError(f"{path.name}: top level must be a mapping; file left unchanged")
            doc = loaded
    recs = doc.get("recognizers") or []
    if not isinstance(recs, list):
        raise RuleError(f"{path.name}: 'recognizers' must be a list; file left unchanged")
    doc = dict(doc)
    doc["recognizers"] = list(change(copy.deepcopy(recs)))
    parse_rule_document(doc, path, rules_root)  # raises RuleError before anything is written
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    tmp = path.with_suffix(".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, "utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        raise RuleError(f"{path.name}: cannot write ({exc}); file left unchanged") from exc
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _upsert(recs: List[dict], entry: dict) -> List[dict]:
    """Replace the entry with the same name in place, or append."""
    for i, r in enumerate(recs):
        if isinstance(r, dict) and r.get("name") == entry["name"]:
            recs[i] = entry
            return recs
    return recs + [entry]


def _without(recs: List[dict], name: str) -> List[dict]:
    return [r for r in recs if not (isinstance(r, dict) and r.get("name") == name)]


def _saved_path(rules_root: Path) -> Path:
    return Path(rules_root) / "local" / SAVED_RULES_FILE_NAME


def _overrides_path(rules_root: Path) -> Path:
    return Path(rules_root) / "local" / OVERRIDES_FILE_NAME


def set_rule_enabled(rules_root: Path, rule: RuleDef, enabled: bool) -> None:
    kind = rule_kind(rule)
    if kind == "hand-edited":
        raise RuleError("hand-edited rule")
    if kind == "saved":
        def change(recs):
            for r in recs:
                if isinstance(r, dict) and r.get("name") == rule.name:
                    r["enabled"] = enabled
            return recs
        update_rule_file(_saved_path(rules_root), rules_root, change)
    else:  # bundled, remote or override: decide from the overrides.yaml entry, not from `rule`,
        # which can be stale (the entry may have become a copy, or gone, since the rules loaded).
        if kind == "override":
            original = rule.overrides
        else:
            original = rule        # its own state; rule.overrides may be a bundled rule it replaced
        own_state = None if original is None else original.raw.get("enabled", True) is not False

        def change(recs):
            entries = [r for r in recs if isinstance(r, dict) and r.get("name") == rule.name]
            if not entries:
                if own_state is None or enabled == own_state:
                    return recs        # a marker would change nothing
                return recs + [{"name": rule.name, "enabled": enabled}]
            if own_state is not None and enabled == own_state and all(is_marker_mapping(r) for r in entries):
                return _without(recs, rule.name)
            for r in entries:
                r["enabled"] = enabled    # keeps the user's edits in a copy
            return recs
        update_rule_file(_overrides_path(rules_root), rules_root, change)


def override_copy(rule: RuleDef) -> dict:
    """An editable full copy of a bundled or remote rule (or of the original behind a marker)."""
    original = rule.overrides if rule.is_marker and rule.overrides is not None else rule
    out = copy.deepcopy(original.raw)
    if "wordlist" in out:
        del out["wordlist"]
        out["deny_list"] = list(rule.deny_list)
    meta = dict(out.get("metadata") or {})
    meta["original_sha"] = raw_fingerprint(original.raw)
    out["metadata"] = meta
    if rule.is_marker:
        out["enabled"] = rule.enabled
    return out


def save_rule(rules_root: Path, rule: RuleDef, new_raw: dict) -> None:
    kind = rule_kind(rule)
    if kind == "hand-edited":
        raise RuleError("hand-edited rule")
    new_raw = copy.deepcopy(new_raw)
    if kind in ("saved", "override") and not rule.is_marker:
        path = _saved_path(rules_root) if kind == "saved" else _overrides_path(rules_root)
    else:
        path = _overrides_path(rules_root)
        new_raw["name"] = rule.name
    # An edit must be a working rule even when it is off: parse_rule_document only warns about a
    # disabled rule's problems, so check the entry as if it were on. Raises before any write.
    parse_rule_document({"recognizers": [{**new_raw, "enabled": True}]}, path, Path(rules_root))
    if kind in ("saved", "override") and not rule.is_marker:
        new_name = new_raw.get("name", rule.name)
        if new_name != rule.name and kind == "override":
            raise RuleError("a copy of a rule must keep the name of the rule it replaces")

        def change(recs):
            if new_name != rule.name and any(isinstance(r, dict) and r.get("name") == new_name for r in recs):
                raise RuleError(f"a rule named '{new_name}' already exists in {path.name}")
            for i, r in enumerate(recs):
                if isinstance(r, dict) and r.get("name") == rule.name:
                    recs[i] = new_raw
                    return recs
            raise RuleError(f"rule '{rule.name}' not found in {path.name}")
        update_rule_file(path, rules_root, change)
    else:  # bundled, remote or marker: write the edited copy to overrides.yaml
        update_rule_file(path, rules_root, lambda recs: _upsert(recs, new_raw))


def build_edited_raw(base_raw: dict, *, entity: str, score: float, case_sensitive: bool,
                     manual: Optional[Tuple[str, str]] = None,
                     patterns: Sequence[str] = (), values: Sequence[str] = ()) -> dict:
    """The raw mapping for an edited rule. Fields the edit form does not show stay as they are."""
    if manual is not None:
        out = ManualRule(manual[0], manual[1], entity, not case_sensitive).to_rule_yaml()
        if "enabled" in base_raw:
            out["enabled"] = base_raw["enabled"]
        out["score"] = score
        for item in out.get("patterns") or []:
            if isinstance(item, dict):
                item["score"] = score
        return out
    out = copy.deepcopy(base_raw)
    out["entity"], out["score"], out["case_sensitive"] = entity, score, case_sensitive
    kept = {}
    for item in _as_list(base_raw.get("patterns")):
        if isinstance(item, dict) and isinstance(item.get("regex"), str):
            kept.setdefault(item["regex"], copy.deepcopy(item))
    if patterns:
        out["patterns"] = [kept.get(rx, rx) for rx in patterns]
    else:
        out.pop("patterns", None)
    if values:
        out["deny_list"] = list(values)
    else:
        out.pop("deny_list", None)
    return out


def delete_rule(rules_root: Path, rule: RuleDef) -> None:
    if rule_kind(rule) != "saved":
        raise RuleError("only a saved rule can be deleted")
    update_rule_file(_saved_path(rules_root), rules_root, lambda recs: _without(recs, rule.name))


def restore_original(rules_root: Path, rule: RuleDef) -> None:
    if rule_kind(rule) != "override":
        raise RuleError("only a copy or switch can be restored")
    update_rule_file(_overrides_path(rules_root), rules_root, lambda recs: _without(recs, rule.name))


def append_rule_to_file(path: Path, rule: Dict) -> None:
    """Persist a rule (e.g. a promoted manual rule) into local/promoted_rules.yaml."""
    update_rule_file(path, path.parent.parent, lambda recs: _without(recs, rule["name"]) + [rule])


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
    """SRV-*  -> SRV-DC01, SRV-DC01.corp.local ;  *.corp -> a.b.corp ;  ? = one char ;
    *acme* -> db.prod.acme.com, acme-labs.

    A '*' next to a literal '.' stands for one or more whole labels, so '*.corp' needs a
    label before the dot. Any other '*' is a glob: zero or more host characters, and it may
    cross dots. It never starts or ends the match on a dot, and never makes two dots."""
    H = _HOSTCHARS
    labels = H + r"+(?:\." + H + r"+)*"                 # one or more whole labels
    star_lead = r"(?:" + H + r"+\.)*" + H + r"*"         # may end on a dot before a literal
    star_tail = H + r"*(?:\." + H + r"+)*"               # may start after a literal's char
    star_mid = r"(?:" + H + r"|\.(?=" + H + r"))*"       # dots only between host chars
    pat = re.sub(r"\*+", "*", pattern.strip())
    out = []
    for i, ch in enumerate(pat):
        if ch == "*":
            prev = pat[i - 1] if i > 0 else ""
            nxt = pat[i + 1] if i + 1 < len(pat) else ""
            if pat == "*" or "." in (prev, nxt):
                out.append(labels)
            elif not prev:
                out.append(star_lead)
            elif not nxt:
                out.append(star_tail)
            else:
                out.append(star_mid)
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

    @property
    def rule_name(self) -> str:
        return f"manual_{self.entity.lower()}_{hashlib.sha1(self.pattern.encode()).hexdigest()[:8]}"

    def to_rule_yaml(self) -> Dict:
        name = self.rule_name
        rule = {"name": name, "entity": self.entity, "score": 0.95,
                "case_sensitive": not self.case_insensitive,
                "description": f"Promoted from manual {self.match_type} rule: {self.pattern}",
                "metadata": {"manual": {"match_type": self.match_type, "pattern": self.pattern}}}
        if self.match_type == "exact":
            rule["deny_list"] = [self.pattern]
        else:
            rx = wildcard_to_regex(self.pattern) if self.match_type == "wildcard" else self.pattern
            rule["patterns"] = [{"name": name, "regex": rx, "score": 0.95}]
        return rule


_PROMOTED_DESC_RE = re.compile(r"^Promoted from manual (exact|wildcard|regex) rule: (.+)$")


def manual_source(rule: RuleDef) -> Optional[Tuple[str, str]]:
    """(match_type, pattern) a saved manual rule came from, or None for any other rule."""
    meta = (rule.raw or {}).get("metadata")
    man = meta.get("manual") if isinstance(meta, dict) else None
    if isinstance(man, dict) and man.get("match_type") in ("exact", "wildcard", "regex") \
            and isinstance(man.get("pattern"), str) and man["pattern"]:
        return man["match_type"], man["pattern"]
    m = _PROMOTED_DESC_RE.match(rule.description or "")
    return (m.group(1), m.group(2)) if m else None


def rule_details(rule: RuleDef, max_values: int = 5) -> List[str]:
    """Lines that tell a person what a loaded rule matches (for the Rules manager window)."""
    out = [rule.description] if rule.description else []
    src = manual_source(rule)
    if src:
        out.append(f"{src[0]}: {src[1]}")
    elif rule.deny_list:
        shown = ", ".join(rule.deny_list[:max_values])
        more = len(rule.deny_list) - max_values
        out.append(f"values: {shown}" + (f" (+{more} more)" if more > 0 else ""))
    if not src:
        out += [f"regex: {p.regex}" for p in rule.patterns]
    keys = rule.json_keys + [f"*{k}*" for k in rule.json_key_contains]
    if keys:
        out.append("json keys: " + ", ".join(keys))
    return out


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


SOURCE_PRIORITY = {"manual": 3, "custom": 2, "session": 2, "presidio": 1, "hebrew_ner": 1, "propagated": 0}


def _overlap_rank(f: Finding) -> Tuple:
    return (-SOURCE_PRIORITY.get(f.source, 1), -f.length, -round(f.score, 3),
            f.recognizer in NER_RECOGNIZERS, f.start)


class _Coverage:
    """The union of character spans, as sorted disjoint (start, end) ranges. Overlap tests and
    the covered parts of a range take a binary search, not a scan of every span: a long text
    (a large PDF) has tens of thousands of findings."""

    def __init__(self, spans: Iterable[Tuple[int, int]] = ()):
        self.starts: List[int] = []
        self.ends: List[int] = []
        for s, e in sorted(spans):
            self.add(s, e)

    def add(self, s: int, e: int) -> None:
        if e <= s:
            return
        i = bisect.bisect_left(self.ends, s)      # first range that ends at or after s
        j = bisect.bisect_right(self.starts, e)   # ranges that start at or before e
        if i < j:
            s, e = min(s, self.starts[i]), max(e, self.ends[j - 1])
        self.starts[i:j] = [s]
        self.ends[i:j] = [e]

    def overlaps(self, s: int, e: int) -> bool:
        i = bisect.bisect_right(self.ends, s)     # first range that ends after s
        return i < len(self.starts) and self.starts[i] < e

    def within(self, s: int, e: int) -> List[Tuple[int, int]]:
        """The covered parts of [s, e), clipped to it."""
        out = []
        i = bisect.bisect_right(self.ends, s)
        while i < len(self.starts) and self.starts[i] < e:
            out.append((max(self.starts[i], s), min(self.ends[i], e)))
            i += 1
        return out


def resolve_overlaps(findings: List[Finding]) -> List[Finding]:
    """Greedy non-overlapping selection: manual > custom/session > presidio > propagated,
    then the longer span (fs01.corp.local beats corp.local), then the higher score, then a
    pattern match over an NER guess (spaCy sometimes tags a URL as PERSON)."""
    ranked = sorted(findings, key=_overlap_rank)
    taken = _Coverage()
    keep: List[Finding] = []
    for f in ranked:
        if f.length <= 0 or taken.overlaps(f.start, f.end):
            continue
        taken.add(f.start, f.end)
        keep.append(f)
    return sorted(keep, key=lambda f: f.start)


def resolve_keep_hebrew_coverage(findings: List[Finding], text: str,
                                 hebrew_copies: bool = False) -> List[Finding]:
    """resolve_overlaps, then give back the words of a dropped Hebrew NER span that no kept
    finding covers.

    A Hebrew span can lose to a higher-priority rule finding that covers only a part of it
    (rule "רחוב הרצל 12" inside PERSON "רחוב הרצל 12 תל אביב רונית שפירא"; the gap merge
    makes such long spans). Without this step the rest of the span, with the name, stays
    unmasked. Each uncovered piece (edges trimmed to word characters) becomes a finding with
    the dropped span's type and score.

    With hebrew_copies (the Hebrew model is loaded and on), a propagated copy with Hebrew
    letters gets the same treatment: ORGANIZATION "ז'אן-פייר" (kept) + PERSON "לוי" (under the
    threshold) beat the propagated copy "ז'אן-פייר לוי" of the same name found elsewhere, and
    "לוי" stayed unmasked. Findings of other sources, and propagated copies without Hebrew
    letters, are not changed.

    The dropped findings are processed in resolve_overlaps rank order, and each new piece
    counts as covered for the next one. Thus the pieces never overlap each other: sanitize runs
    resolve_overlaps again and would drop one of two overlapping pieces."""
    kept = resolve_overlaps(findings)
    taken = _Coverage((f.start, f.end) for f in kept)
    taken_keys = {(f.start, f.end) for f in kept}
    extra: List[Finding] = []
    for f in sorted(findings, key=_overlap_rank):
        if (f.start, f.end) in taken_keys or not (
                f.source == "hebrew_ner"
                or (hebrew_copies and f.source == "propagated"
                    and _HEBREW_LETTER_RE.search(f.text))):
            continue
        if not taken.overlaps(f.start, f.end):
            continue
        for a, b in _uncovered_pieces(text, f.start, f.end, taken):
            extra.append(Finding(a, b, text[a:b], f.entity, f.score, f.source, f.recognizer))
            taken.add(a, b)
            taken_keys.add((a, b))
    return sorted(kept + extra, key=lambda f: f.start) if extra else kept


def _uncovered_pieces(text: str, start: int, end: int, covered) -> List[Tuple[int, int]]:
    """The parts of text[start:end] that no span in `covered` overlaps, each trimmed to word
    characters at both ends. Coverage is per character: when a covered span stops inside a
    word ("אבו" in "אבו-סאלח"), the rest of the word stays in a piece."""
    if isinstance(covered, _Coverage):
        cuts = covered.within(start, end)
    else:
        cuts = sorted((max(s, start), min(e, end)) for s, e in covered if s < end and start < e)
    pieces: List[Tuple[int, int]] = []
    pos = start
    for s, e in cuts + [(end, end)]:
        a, b = pos, max(pos, s)
        while a < b and not _is_word_char(text[a]):
            a += 1
        while b > a and not _is_word_char(text[b - 1]):
            b -= 1
        if b > a:
            pieces.append((a, b))
        pos = max(pos, e)
    return pieces


def _uncovered_hebrew_pieces(text: str, start: int, end: int, covered) -> List[Tuple[int, int]]:
    """Pieces of a spaCy span on Hebrew text that no Hebrew NER span covers (_uncovered_pieces).
    Every piece is returned, also a piece without Hebrew letters: "John Smith" in the mixed
    span "John Smith מחיפה" is a name too."""
    return _uncovered_pieces(text, start, end, covered)


def find_literal(text: str, value: str, case_insensitive: bool) -> Iterable[Tuple[int, int]]:
    if not value.strip():
        return []
    rx = re.compile(literal_to_regex(value), re.IGNORECASE if case_insensitive else 0)
    return [(m.start(), m.end()) for m in rx.finditer(text)]


# Hebrew attaches the letters ו ב כ ל מ ש ה to the next word: "ישראל ישראלי" also occurs as
# "לישראל ישראלי" or "וכשישראל ישראלי". Python lookbehinds have a fixed width, so there is one
# lookbehind for each count of prefix letters (0 to 3), each with a word start before the letters.
_HEBREW_PREFIX_LETTERS = "[ובכלמשה]"
_HEBREW_PREFIX_START = "(?:(?<!\\w)|" + "|".join(
    f"(?<=(?<!\\w){_HEBREW_PREFIX_LETTERS}{{{k}}})" for k in (1, 2, 3)) + ")"


def find_propagated(text: str, value: str, case_insensitive: bool) -> Iterable[Tuple[int, int]]:
    """find_literal for value propagation. A value that starts with a Hebrew letter also matches
    after 1 to 3 Hebrew prefix letters; the match covers the value only, not the prefix. Other
    values match exactly as find_literal."""
    if not value.strip() or not _HEBREW_LETTER_RE.match(value):
        return find_literal(text, value, case_insensitive)
    post = r"(?!\w)" if value[-1:].isalnum() or value[-1:] == "_" else ""
    rx = re.compile(_HEBREW_PREFIX_START + re.escape(value) + post,
                    re.IGNORECASE if case_insensitive else 0)
    # Every find_literal match stays. A prefix match counts only where it does not overlap one:
    # in "ודן דן דן" the prefix match "דן דן" at 1 would take text from the plain match at 4.
    plain = list(find_literal(text, value, case_insensitive))
    prefixed = [(m.start(), m.end()) for m in rx.finditer(text)]
    return sorted(plain + [(a, b) for a, b in prefixed
                           if not any(a < e and s < b for s, e in plain)])


# A line is a log line when it starts with a timestamp, a syslog priority or a log level, holds a
# JSON object, or has two key=value pairs. spaCy NER reads such lines as prose and tags field
# names and values ("arn", "COMMAND=/bin/ls") as PERSON or ORGANIZATION.
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_LOG_LINE_START_RE = re.compile(
    r"^\s*(?:<\d{1,3}>\s*)?(?:"
    r"\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"                      # ISO 8601
    r"|" + _MONTH + r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"            # BSD syslog
    r"|\[?\d{1,2}/\d{1,2}/\d{2,4}[ ,]+\d{1,2}:\d{2}"             # 10/12/2024 10:01
    r"|\[?\d{10}(?:\.\d+|\d{3})?\b"                              # Unix epoch
    r"|\[?(?:TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRIT|CRITICAL|FATAL|ALERT|EMERG)\b[\]:]?"
    r"|\{.*\}\s*$)")
_LOG_LINE_ANY_RE = re.compile(r"\[\d{2}/" + _MONTH + r"/\d{4}:\d{2}:\d{2}:\d{2}")  # Apache access log
_KEY_VALUE_RE = re.compile(r"(?<![\w.-])[A-Za-z_][\w.-]{0,40}=(?=\S)")
LOG_LINE_RATIO = 0.6        # share of non-blank lines that must look like log lines
LOG_SAMPLE_LINES = 500


def is_log_line(line: str) -> bool:
    return bool(_LOG_LINE_START_RE.match(line) or _LOG_LINE_ANY_RE.search(line) or
                len(_KEY_VALUE_RE.findall(line)) >= 2)


def looks_like_log(text: str) -> bool:
    """True when most non-blank lines (of the first LOG_SAMPLE_LINES) are log lines."""
    lines = [ln for ln in text.splitlines() if ln.strip()][:LOG_SAMPLE_LINES]
    return bool(lines) and sum(map(is_log_line, lines)) >= LOG_LINE_RATIO * len(lines)


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


# ---- Save review / Load review ----

REVIEW_FORMAT = "pii-shield-review"
REVIEW_FORMAT_VERSION = 1
_FINDING_FIELDS = ("start", "end", "text", "entity", "score", "source", "recognizer", "enabled",
                   "token", "token_edited")


def review_to_dict(text: str, findings: Sequence["Finding"], vault: "SessionVault",
                   threshold: float) -> Dict:
    """The analyzed text, every finding with the user's choices, the session map and the score
    limit, so the review can be loaded again without a new analysis. The result contains the
    original text and values in plain form."""
    return {"format": REVIEW_FORMAT, "format_version": REVIEW_FORMAT_VERSION, "app": APP_ID,
            "app_version": __version__, "saved": _dt.datetime.now().isoformat(timespec="seconds"),
            "threshold": float(threshold), "text": text,
            "findings": [{k: getattr(f, k) for k in _FINDING_FIELDS} for f in findings],
            "session_map": vault.export()}


def review_from_dict(data: Dict) -> Tuple[str, List["Finding"], Dict, float]:
    """(text, findings, session map, threshold) from review_to_dict output. Raises ValueError for
    another kind of file, a newer format, or a finding that does not match the text."""
    if not isinstance(data, dict) or data.get("format") != REVIEW_FORMAT:
        raise ValueError("This is not a PII Shield review file.")
    if int(data.get("format_version", 0)) > REVIEW_FORMAT_VERSION:
        raise ValueError("This review file comes from a newer PII Shield. Update the app to load it.")
    text = data.get("text")
    if not isinstance(text, str):
        raise ValueError("The review file has no text.")
    findings: List[Finding] = []
    for n, d in enumerate(data.get("findings") or [], 1):
        f = Finding(int(d["start"]), int(d["end"]), str(d["text"]), str(d["entity"]), float(d["score"]),
                    str(d["source"]), str(d.get("recognizer", "")), bool(d.get("enabled", True)),
                    str(d.get("token", "")), bool(d.get("token_edited", False)))
        if not (0 <= f.start < f.end <= len(text)) or text[f.start:f.end] != f.text:
            raise ValueError(f"Finding {n} does not match the text of the review file.")
        findings.append(f)
    session = data.get("session_map") or {"entries": []}
    return text, findings, session, float(data.get("threshold", 0.85))


def write_review_file(path: Path, data: Dict) -> None:
    """Write the review file in one step (a temporary file, then a rename), readable only by the
    user where the OS supports it: it holds the original text in plain form."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), "utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


# ===========================================================================
# 5. Detection engine (Presidio + spaCy, hot-reloadable)
# ===========================================================================
try:
    import regex as _regex  # Presidio's regex engine (supports a match timeout)
    from presidio_analyzer import (AnalyzerEngine, EntityRecognizer, Pattern, PatternRecognizer,
                                   RecognizerRegistry, RecognizerResult)
    from presidio_analyzer.pattern_recognizer import REGEX_TIMEOUT_SECONDS
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
    from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer

    class FastContextEnhancer(LemmaContextAwareEnhancer):
        """Presidio's context enhancer, with a binary search for the token of a finding.

        Presidio scans all tokens of the text for each finding, so the time grows with
        (findings x tokens): many minutes on a large PDF. The tokens are sorted and do not
        overlap, so their end offsets are sorted too, and the first token that ends after the
        finding's start is the same token that Presidio's scan finds."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._ends_for = None   # (tokens_indices list, end offsets) of the last text
            self._lock = threading.Lock()

        def _find_index_of_match_token(self, word, start, tokens, tokens_indices):
            with self._lock:
                cached = self._ends_for
                if cached is None or cached[0] is not tokens_indices or len(cached[1]) != len(tokens_indices):
                    ends = [i + len(t) for i, t in zip(tokens_indices, tokens)]
                    if any(b < a for a, b in zip(ends, ends[1:])):   # not sorted: use Presidio's scan
                        return LemmaContextAwareEnhancer._find_index_of_match_token(
                            word, start, tokens, tokens_indices)
                    cached = self._ends_for = (tokens_indices, ends)
            i = bisect.bisect_right(cached[1], start)
            if i > 0 and tokens_indices[i - 1] == start:   # an empty token at start
                i -= 1
            if i >= len(tokens_indices):
                raise ValueError("Did not find word '" + word + "' in the list of tokens although it "
                                 "is expected to be found")
            return i

    class ValidatedPatternRecognizer(PatternRecognizer):
        """PatternRecognizer with an optional checksum/semantic validator from VALIDATORS."""

        def __init__(self, *args, validator: Optional[str] = None, **kwargs):
            self._validator = VALIDATORS.get(validator) if validator else None
            super().__init__(*args, **kwargs)

        def validate_result(self, pattern_text: str) -> Optional[bool]:
            return self._validator(pattern_text) if self._validator else None

        def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
            """Presidio's pattern loop, except that a (?P<value>...) group limits the span and the
            validator to that group (password=Sup3r -> only Sup3r is masked)."""
            flags = regex_flags or self.global_regex_flags
            results = []
            for pattern in self.patterns:
                if not pattern.compiled_regex or pattern.compiled_with_flags != flags:
                    pattern.compiled_with_flags = flags
                    pattern.compiled_regex = _regex.compile(pattern.regex, flags=flags)
                try:
                    matches = list(pattern.compiled_regex.finditer(text, timeout=REGEX_TIMEOUT_SECONDS))
                except TimeoutError:
                    log.warning("rule %s: pattern %s timed out and was skipped", self.name, pattern.name)
                    continue
                for m in matches:
                    start, end = value_span(m)
                    if end <= start:
                        continue
                    valid = self.validate_result(text[start:end])
                    if valid is False:
                        continue
                    score = EntityRecognizer.MAX_SCORE if valid else pattern.score
                    explanation = self.build_regex_explanation(self.name, pattern.name, pattern.regex,
                                                               score, valid, flags)
                    results.append(RecognizerResult(
                        entity_type=self.supported_entities[0], start=start, end=end, score=score,
                        analysis_explanation=explanation,
                        recognition_metadata={RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                                              RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id}))
            return EntityRecognizer.remove_duplicates(results)


NER_RECOGNIZERS = ("SpacyRecognizer", "StanzaRecognizer", "TransformersRecognizer")
# Presidio's own scores sit below the 0.85 default threshold. Raise them so these entities stay
# detected. Only URL patterns that need a scheme are raised: "Non schema URL" also matches
# file names such as report.py, so it keeps Presidio's 0.5 and stays below the threshold.
BUILTIN_MIN_SCORES = {"IpRecognizer": 0.85, "UrlRecognizer": 0.85, "PhoneRecognizer": 0.85}


def _raise_builtin_scores(registry) -> None:
    for rec in registry.recognizers:
        floor = BUILTIN_MIN_SCORES.get(rec.__class__.__name__)
        if floor is None:
            continue
        if hasattr(rec, "SCORE"):                       # PhoneRecognizer: one score, no patterns
            rec.SCORE = max(rec.SCORE, floor)
        if getattr(rec, "patterns", None):              # copies: Presidio shares PATTERNS per class
            rec.patterns = [Pattern(p.name, p.regex, max(p.score, floor))
                            if rec.__class__.__name__ != "UrlRecognizer" or "https?://" in p.regex
                            else Pattern(p.name, p.regex, p.score) for p in rec.patterns]


# A page header line written by extract_pdf_text, for example "--- page 2 (OCR) ---".
# Skip reasons and OCR language names. The PDF extractor writes them into page headers, and
# PAGE_HEADER_RE is built from them, so the two cannot drift apart.
OCR_OFF_REASON = "OCR turned off"
OCR_NO_TESSERACT_REASON = "Tesseract not installed"
OCR_NO_LANG_REASON = "no OCR language data"
OCR_FAILED_REASON = "OCR failed"
OCR_TIMEOUT_REASON = "OCR timed out"
OCR_NO_TEXT_REASON = "OCR found no text"
_HDR_REASONS = (OCR_OFF_REASON, OCR_NO_TESSERACT_REASON, OCR_NO_LANG_REASON, OCR_FAILED_REASON,
                OCR_TIMEOUT_REASON, OCR_NO_TEXT_REASON)
_LANG_NAMES = {"heb": "Hebrew", "eng": "English"}

_HDR_REASON = "(?:" + "|".join(re.escape(r) for r in _HDR_REASONS) + ")"
# One language: a display name from _LANG_NAMES, or a Tesseract code such as chi_sim.
_HDR_LANG = "(?:" + "|".join(re.escape(n) for n in _LANG_NAMES.values()) + r"|[a-z]{3}(?:_[a-z]+)?)"
_HDR_LANGS = _HDR_LANG + "(?: and " + _HDR_LANG + ")*"
# Match only the header forms extract_pdf_text writes. Never accept free text in the parentheses:
# anything a header line matches goes out unmasked and is hidden from the leak check.
PAGE_HEADER_RE = re.compile(
    r"^--- page \d+"
    r"(?: \((?:OCR(?:, " + _HDR_LANGS + " only: " + _HDR_LANGS + r" language data missing)?"
    r"|(?:scanned, skipped|little text, image text not read|mostly image, image text not read"
    r"|unreadable text, not read): " + _HDR_REASON + r")\))?"
    r"(?: \(form fields or notes not read\))? ---$", re.M)


def page_header_spans(text: str) -> List[Tuple[int, int]]:
    """Return the (start, end) of each PDF page header line in text."""
    if "--- page " not in text:
        return []
    return [m.span() for m in PAGE_HEADER_RE.finditer(text)]


def _outside_spans(findings: List[Finding], spans: List[Tuple[int, int]]) -> List[Finding]:
    """Drop findings that lie inside a span (manual-rule findings are kept, as with the allow list)."""
    if not spans:
        return findings
    return [f for f in findings
            if f.source == "manual" or not any(s <= f.start and f.end <= e for s, e in spans)]


# spaCy refuses a text longer than nlp.max_length (1,000,000 characters) and needs about 1 GB of
# memory for each 100,000 characters. A long input (a large PDF) is analyzed in parts. The parts
# overlap, so a value that crosses a cut is found whole in the next part.
ANALYZE_PART_CHARS = 100_000
ANALYZE_PART_OVERLAP = 2_000
_WHITESPACE_RE = re.compile(r"\s")


def split_for_analysis(text: str, size: int, overlap: int) -> List[Tuple[int, str]]:
    """Cut text into (start, part) pieces of at most size characters. A cut falls after a line
    break, else after a space, in the second half of the part. Each part starts at a whitespace
    character inside the last overlap characters of the part before it."""
    if len(text) <= size:
        return [(0, text)]
    parts: List[Tuple[int, str]] = []
    start = 0
    while True:
        end = min(start + size, len(text))
        if end < len(text):
            low = start + size // 2
            cut = text.rfind("\n", low, end)
            if cut == -1:
                cut = max(text.rfind(" ", low, end), text.rfind("\t", low, end))
            if cut != -1:
                end = cut + 1
        parts.append((start, text[start:end]))
        if end >= len(text):
            return parts
        nxt = max(end - overlap, start + 1)
        m = _WHITESPACE_RE.search(text, nxt, end - 1)
        start = m.end() if m else nxt


# A token in the sanitized output, for example <PERSON_1>. A cut must never fall inside one.
_TOKEN_LIKE_RE = re.compile(r"<[^<>\s]{1,64}>")


def split_output(text: str, max_chars: int) -> List[str]:
    """Cut the sanitized output into parts of at most max_chars characters, to paste into an LLM
    one by one. A cut falls after a blank line, else after a line break, else after a space, in the
    second half of the part. A hard cut (no whitespace) never falls inside a token. The parts
    joined give the text back unchanged."""
    if len(text) <= max_chars:
        return [text]
    parts: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            low = start + max_chars // 2
            for sep in ("\n\n", "\n", " "):
                cut = text.rfind(sep, low, end)
                if cut != -1:
                    end = cut + len(sep)
                    break
            else:
                for m in _TOKEN_LIKE_RE.finditer(text, max(start, end - 64), min(len(text), end + 64)):
                    if m.start() < end < m.end():
                        end = m.start() if m.start() > start else m.end()
                        break
        parts.append(text[start:end])
        start = end
    return parts


PART_HEADER = "--- Part {i} of {n} ---\n"


def with_part_headers(parts: List[str]) -> List[str]:
    """Add a "--- Part i of n ---" line at the start of each part (not for a single part)."""
    if len(parts) < 2:
        return list(parts)
    return [PART_HEADER.format(i=i, n=len(parts)) + p for i, p in enumerate(parts, 1)]


def part_file_names(n: int) -> List[str]:
    """File names for exported parts. They hold only numbers, never text from the document."""
    width = len(str(n))
    return [f"sanitized_part_{i:0{width}d}_of_{n}.txt" for i in range(1, n + 1)]


def format_time_left(seconds: float) -> str:
    """Short, rounded time-left text for the status bar."""
    if seconds < 60:
        return "less than 1 min"
    return f"about {round(seconds / 60)} min"


def analyze_in_parts(analyzer, text: str, progress: Optional[Callable[[str], None]] = None,
                     **kwargs) -> list:
    """analyzer.analyze over the parts of a long text, with offsets moved back into text. A part
    normally ends and starts at whitespace. At a hard cut (no whitespace found), a result that
    touches the cut can be cut short, so it is dropped: the overlap finds it whole. The same
    result from two parts is kept once, with the higher score."""
    parts = split_for_analysis(text, ANALYZE_PART_CHARS, ANALYZE_PART_OVERLAP)
    if len(parts) == 1:
        return analyzer.analyze(text=text, **kwargs)
    best: Dict[Tuple[int, int, str, str], object] = {}
    began = time.monotonic()
    for i, (start, part) in enumerate(parts):
        if progress is not None:
            msg = f"Analyzing part {i + 1} of {len(parts)}"
            if i:
                left = (time.monotonic() - began) / i * (len(parts) - i)
                msg += f" · {format_time_left(left)} left"
            progress(msg)
        last = i == len(parts) - 1
        cut_before = i > 0 and not text[start - 1].isspace()     # a hard cut: no whitespace found
        cut_after = not last and not text[start + len(part) - 1].isspace()
        for r in analyzer.analyze(text=part, **kwargs):
            if (cut_after and r.end >= len(part)) or (cut_before and r.start <= 0):
                continue
            r.start += start
            r.end += start
            key = (r.start, r.end, r.entity_type, (r.recognition_metadata or {}).get("recognizer_name", ""))
            if key not in best or r.score > best[key].score:
                best[key] = r
    return sorted(best.values(), key=lambda r: (r.start, r.end))


class DetectionEngine:
    """Owns the (expensive) NLP engine once; recognizer registries are rebuilt on hot reload."""

    def __init__(self, config: AppConfig, rules_root: Path = RULES_DIR):
        self.config = config
        self.rules_root = rules_root
        self.lock = threading.RLock()
        # Serializes reload_rules() so an older ruleset can never be assigned after a newer one.
        # Lock order: _reload_lock before lock (initialize() follows it too).
        self._reload_lock = threading.Lock()
        self.nlp_engine = None
        self.analyzer = None
        self.model_name: Optional[str] = None
        self.mode = "uninitialized"       # presidio+spacy | presidio-regex-only | lite
        self.ruleset = RuleSet()
        self.builtin_supported: List[str] = []
        self.last_ner_skipped = False     # True when the last analyze() dropped NER findings on log input
        self.hebrew_model: Optional["HebrewNerModel"] = None
        self.hebrew_status = "off"        # loaded | not installed | off | failed: <reason>

    @property
    def ready(self) -> bool:
        """True once initialize() has picked a mode. Before that, reload_rules() can block on the
        model load, so the GUI thread must not call it."""
        return self.mode != "uninitialized"

    # ---- lifecycle
    def initialize(self, progress: Callable[[str], None] = lambda s: None) -> str:
        with self._reload_lock, self.lock:
            if not PRESIDIO_OK:
                self.mode = "lite"
                progress(f"Presidio not available ({PRESIDIO_ERR}); regex-only lite mode")
                self._reload_rules_locked()
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
            self._load_hebrew(ecfg, progress)
            self._reload_rules_locked()
            return self.mode

    def _load_hebrew(self, ecfg, progress: Callable[[str], None]) -> None:
        """Load the Hebrew NER model once. A failure never stops the engine."""
        self.hebrew_model = None
        if not ecfg.get("hebrew_ner"):
            self.hebrew_status = "off"
            return
        try:
            folder = find_hebrew_model()
            err = hebrew_model_read_error() if folder is None else None
        except Exception as exc:  # discovery must never stop the engine
            folder, err = None, str(exc)
        if err:
            log.warning("Hebrew NER model folder cannot be read: %s", err)
            self.hebrew_status = f"failed: {err}"
            return
        if folder is None:
            self.hebrew_status = "not installed"
            return
        progress("Loading Hebrew NER model...")
        try:
            self.hebrew_model = load_hebrew_model(folder)
            self.hebrew_status = "loaded"
        except Exception as exc:
            log.warning("Hebrew NER model failed to load: %s", exc)
            self.hebrew_status = f"failed: {exc}"

    def _build_registry(self, rs: RuleSet):
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(languages=["en"], nlp_engine=self.nlp_engine)
        _raise_builtin_scores(registry)
        if self.mode == "presidio-regex-only":
            for rec in list(registry.recognizers):
                if rec.__class__.__name__ in NER_RECOGNIZERS:
                    registry.recognizers.remove(rec)
        if self.hebrew_model is not None and self.config["engine"].get("hebrew_ner"):
            registry.add_recognizer(HebrewNerRecognizer(
                self.hebrew_model, organizations=bool(self.config["engine"].get("detect_organizations"))))
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
        """Hot reload: re-read rule files and atomically swap the analyzer. One reload at a time."""
        with self._reload_lock:
            return self._reload_rules_locked()

    def _reload_rules_locked(self) -> RuleSet:
        """reload_rules() body; the caller holds _reload_lock."""
        rs = load_rules_dir(self.rules_root, bundled=True)
        if PRESIDIO_OK and self.nlp_engine is not None:
            registry = self._build_registry(rs)
            analyzer = AnalyzerEngine(registry=registry, nlp_engine=self.nlp_engine,
                                      supported_languages=["en"],
                                      context_aware_enhancer=FastContextEnhancer())
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
                    start, end = value_span(m)
                    if end <= start:
                        continue
                    valid = vfn(text[start:end]) if vfn else None
                    if valid is not False:
                        out.append(Finding(start, end, text[start:end], r.entity, 1.0 if valid else score,
                                           "custom", r.name))
        return out

    def analyze(self, text: str, manual_rules: Sequence[ManualRule], vault: SessionVault,
                threshold: Optional[float] = None, skip_ner: bool = False,
                progress: Optional[Callable[[str], None]] = None) -> List[Finding]:
        """progress, when given, gets short status texts during a long analysis (a long text is
        analyzed in parts, and the copies of each value are then found in the whole text)."""
        with self.lock:
            analyzer, rs = self.analyzer, self.ruleset
        ecfg, bcfg = self.config["engine"], self.config["behavior"]
        threshold = ecfg.get("score_threshold", 0.85) if threshold is None else threshold
        hebrew_on = self.hebrew_model is not None and bool(ecfg.get("hebrew_ner"))
        custom_names = {r.name for r in rs.rules} | {r.name + "_wordlist" for r in rs.rules}
        found: List[Finding] = []
        # (text, score) of the PERSON parts of joined Hebrew spans; they propagate as PERSON
        person_parts: List[Tuple[str, float]] = []

        log_skip = analyzer is not None and bool(ecfg.get("skip_ner_on_logs")) and looks_like_log(text)
        self.last_ner_skipped = log_skip
        skip_ner = skip_ner or log_skip   # the Git scan asks for no NER; log input can also turn it off
        if analyzer is not None:
            entities = sorted(set(ecfg.get("builtin_entities", [])) | set(rs.entities))
            # The Hebrew gap merge must know the threshold of this call (HEBREW_MERGE_CUTOFF).
            cutoff = HEBREW_MERGE_CUTOFF.set(threshold)
            try:
                results = analyze_in_parts(analyzer, text, progress=progress, language="en",
                                           entities=entities or None, score_threshold=threshold)
            finally:
                HEBREW_MERGE_CUTOFF.reset(cutoff)
            # The English spaCy model reads Hebrew as junk and gives long spans ("אברהמי מחברת
            # אורנים" as LOCATION). Such a span can beat a Hebrew PERSON span in resolve_overlaps
            # and leave part of the name unmasked. With the Hebrew model on, a spaCy finding with
            # Hebrew letters keeps only the Hebrew words that no Hebrew NER finding overlaps: the
            # Hebrew model misses some surnames in long text ("משפחת אזולאי").
            hebrew_spans = _Coverage((r.start, r.end) for r in results
                                     if (r.recognition_metadata or {}).get("recognizer_name") == HEBREW_RECOGNIZER)
            for r in results:
                rname = (r.recognition_metadata or {}).get("recognizer_name", "")
                if skip_ner and (rname in NER_RECOGNIZERS or rname == HEBREW_RECOGNIZER):
                    continue
                if rname == HEBREW_RECOGNIZER:
                    person_parts.extend((p, float(r.score)) for p in
                                        (r.recognition_metadata or {}).get(HEBREW_PERSON_PARTS_KEY, ()))
                if (hebrew_on and rname in NER_RECOGNIZERS
                        and _HEBREW_LETTER_RE.search(text, r.start, r.end)):
                    for a, b in _uncovered_hebrew_pieces(text, r.start, r.end, hebrew_spans):
                        found.append(Finding(a, b, text[a:b], r.entity_type, float(r.score),
                                             "presidio", rname))
                    continue
                src = ("custom" if rname in custom_names
                       else "hebrew_ner" if rname == HEBREW_RECOGNIZER else "presidio")
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
                start, end = value_span(m)
                if end > start:
                    found.append(Finding(start, end, text[start:end], mr.entity, 1.0, "manual",
                                         f"manual:{mr.rid}"))

        # allow-list (never applies to manual rules)
        allow = rs.allow_list
        found = [f for f in found if f.source == "manual" or f.text.strip().casefold() not in allow]
        # PDF page header lines hold no PII; NER tags words such as "OCR" in them.
        headers = page_header_spans(text)
        found = resolve_keep_hebrew_coverage(_outside_spans(found, headers), text)

        # propagation: every literal occurrence of a detected value or a value already in the session map
        if bcfg.get("propagate_values", True):
            ci = bcfg.get("case_insensitive_values", True)
            # value key -> (text, entity, score); a copy inherits the best score of its source hits
            values: Dict[str, Tuple[str, str, float]] = {}
            for f in found:
                k = vault.key(f.text)
                prev = values.get(k)
                if prev is None:
                    values[k] = (f.text, f.entity, f.score)
                elif f.score > prev[2]:
                    values[k] = (prev[0], prev[1], f.score)
            # A PERSON part of a joined Hebrew span propagates alone too (HebrewNerModel._merge_gaps).
            for p, score in person_parts:
                if p.strip().casefold() in allow:
                    continue
                k = vault.key(p)
                prev = values.get(k)
                if prev is None:
                    values[k] = (p, "PERSON", score)
                elif score > prev[2]:
                    values[k] = (prev[0], prev[1], score)
            extra: List[Finding] = []
            # Hebrew prefix letters (find_propagated) only with the Hebrew model on: the small
            # build and the setting off keep the plain literal match.
            find = find_propagated if hebrew_on else find_literal
            # On a long text this loop scans the whole text once for each value, so it reports.
            report = progress if progress is not None and len(text) > ANALYZE_PART_CHARS else None
            step = max(1, len(values) // 20)
            for n, (k, (v, ent, score)) in enumerate(values.items()):
                if report is not None and n % step == 0:
                    report(f"Finding repeated values: {n} of {len(values)}")
                for s, e in find(text, v, ci):
                    extra.append(Finding(s, e, text[s:e], ent, score, "propagated", "value-propagation"))
            for tok, v in vault.active_tokens.items():
                if v.casefold() in allow:
                    continue
                for s, e in find(text, v, ci):
                    extra.append(Finding(s, e, text[s:e], vault.token_entity.get(tok, "CUSTOM"), 0.99,
                                         "session", "session-map"))
            found = resolve_keep_hebrew_coverage(_outside_spans(found + extra, headers), text,
                                                 hebrew_on)

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
    # 3) replace: the findings do not overlap (resolve_overlaps), so one pass builds the output.
    # Presidio's anonymizer gave the same text, but its time grew with the square of the
    # number of findings and froze the window on a large PDF.
    return splice(text, enabled), enabled


def splice(text: str, findings: Sequence[Finding]) -> str:
    parts, pos = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        parts.append(text[pos:f.start])
        parts.append(f.token)
        pos = f.end
    parts.append(text[pos:])
    return "".join(parts)


# Send to Sanitize runs in the background above these sizes, so the window does not freeze.
SANITIZE_BACKGROUND_FINDINGS = 5000
SANITIZE_BACKGROUND_CHARS = 200_000


def sanitize_with_leak_check(text: str, findings: Sequence[Finding],
                             vault: SessionVault) -> Tuple[str, List[Finding], List[str]]:
    """sanitize, then leak_check on its output: (output, findings used, leaked values)."""
    out, used = sanitize(text, findings, vault)
    return out, used, leak_check(out, vault)


def leak_check(output: str, vault: SessionVault, extra_values: Iterable[str] = ()) -> List[str]:
    """Return raw values (len>=3) from the session that still appear in the sanitized output."""
    values = {v for v in list(vault.token_to_value.values()) + list(extra_values) if len(v.strip()) >= 3}
    tokens = set(vault.token_to_value)
    # analyze() never masks PDF page header lines, so a session value such as "OCR" in a
    # header is not a leak. Blank the header lines (same length) before the search.
    if page_header_spans(output):
        output = PAGE_HEADER_RE.sub(lambda m: " " * len(m.group()), output)
    # A plain search in the casefolded output rejects most values fast. Only a value found
    # there gets the exact word-boundary regex. casefold(output) contains casefold(v) whenever
    # the case-insensitive regex matches, so the fast step never hides a leak. A regex scan
    # of the whole output for each value took minutes on a large PDF.
    folded = output.casefold()
    leaks = []
    for v in sorted(values, key=len, reverse=True):
        if v in tokens or v.casefold() not in folded:
            continue
        if find_literal(output, v, True):
            leaks.append(v)
    return leaks


# ===========================================================================
# 6b. Git branch scan (leak check of what a push sends; it reports and changes nothing)
# ===========================================================================
GIT_COMMIT_MARK = "\x1ePIISHIELD-COMMIT "   # git format: %x1ePIISHIELD-COMMIT %H
GIT_MSG_END = "\x1fPIISHIELD-END"            # git format: %x1fPIISHIELD-END
GIT_LOG_FORMAT = "--format=%x1ePIISHIELD-COMMIT %H%n%B%x1fPIISHIELD-END"
COMMIT_MESSAGE_FILE = "(commit message)"
GIT_SCAN_MAX_BYTES = 1_000_000    # untracked file or one chunk of added text
GIT_BINARY_SNIFF = 8192           # a NUL byte in the first 8 KB means binary
_HUNK_RE = re.compile(r"^(@{2,}) (.*?) @{2,}")
_BINARY_RE = re.compile(r"^Binary files (.*) and (.*) differ$")
_GIT_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


@dataclass
class AddedChunk:
    source: str                       # short SHA (10 chars), "uncommitted" or "untracked"
    file: str                         # repo-relative path, or COMMIT_MESSAGE_FILE
    lines: List[Tuple[int, str]] = field(default_factory=list)   # (1-based line in the new file, text)


def _git_unquote(path: str) -> str:
    """Undo git's C-style path quoting. Octal escapes are the UTF-8 bytes of the name."""
    if not (len(path) >= 2 and path[0] == '"' and path[-1] == '"'):
        return path
    s, out, i = path[1:-1], bytearray(), 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            if re.match(r"[0-7]{3}", s[i + 1:i + 4]):
                out.append(int(s[i + 1:i + 4], 8))
                i += 4
                continue
            nxt = s[i + 1]
            out += bytes([_GIT_ESCAPES[nxt]]) if nxt in _GIT_ESCAPES else nxt.encode("utf-8")
            i += 2
            continue
        out += c.encode("utf-8")
        i += 1
    return out.decode("utf-8", "replace")


def _git_path(spec: str) -> Optional[str]:
    """'b/dir/x.txt', '"b/a\\tb"' or '/dev/null' -> repo path (None for /dev/null)."""
    quoted = spec.startswith('"')
    p = _git_unquote(spec) if quoted else spec.rstrip("\t")   # git adds a TAB after names with spaces
    if p == "/dev/null":
        return None
    return p[2:] if p[:2] in ("a/", "b/") else p


def _header_path(line: str) -> str:
    if line.startswith("diff --cc ") or line.startswith("diff --combined "):
        return _git_unquote(line.split(" ", 2)[2])
    rest = line[len("diff --git "):]
    if rest.endswith('"'):
        q = rest.rfind(' "')
        return _git_path(rest[q + 1:]) or ""
    k = rest.rfind(" b/")
    return rest[k + 3:] if k >= 0 else rest


def parse_unified_diff(text: str, source: str) -> Tuple[List[AddedChunk], List[Tuple[str, str]]]:
    """Added lines of a unified or combined (--cc) diff made with --unified=0.

    A body line has one prefix column per parent. It is in the new file when no column is '-',
    and it is added when it is in the new file and a column is '+'. Hunk line counts tell where
    a hunk ends, so an added line that starts with '+++' is not read as a file header."""
    chunks: List[AddedChunk] = []
    skipped: List[Tuple[str, str]] = []
    cur: Optional[AddedChunk] = None
    header = ""
    in_hunk = False
    nparents, lineno, new_left, old_left = 1, 0, 0, [0]

    def flush():
        if cur is not None and cur.lines:
            chunks.append(cur)

    for raw in text.split("\n"):
        if in_hunk:
            if raw.startswith("\\"):            # "\ No newline at end of file"
                continue
            if raw == "":
                raw = " " * nparents            # a blank context line can lose its prefix column
            cols, content = raw[:nparents], raw[nparents:]
            in_new = "-" not in cols
            for i, c in enumerate(cols):
                if c != "+":
                    old_left[i] -= 1
            if in_new:
                new_left -= 1
                if "+" in cols and cur is not None:
                    cur.lines.append((lineno, content[:-1] if content.endswith("\r") else content))
                lineno += 1
            if new_left <= 0 and all(o <= 0 for o in old_left):
                in_hunk = False
            continue
        line = raw.rstrip("\r")
        if line.startswith(("diff --git ", "diff --cc ", "diff --combined ")):
            flush()
            header, cur = _header_path(line), None
            continue
        if line.startswith("+++ "):
            flush()
            path = _git_path(line[4:])
            cur = AddedChunk(source, path) if path is not None else None
            continue
        m = _BINARY_RE.match(line)
        if m or line == "Binary files differ":
            path = (_git_path(m.group(2)) or _git_path(m.group(1))) if m else None
            skipped.append((path or header, "binary"))
            continue
        m = _HUNK_RE.match(line)
        if m:
            nparents = len(m.group(1)) - 1
            ranges = m.group(2).split()

            def count(r: str) -> int:
                return int(r.split(",")[1]) if "," in r else 1
            old_left = [count(r) for r in ranges[:-1]]
            new_left = count(ranges[-1])
            lineno = int(ranges[-1][1:].split(",")[0])
            if new_left == 0:
                lineno += 1     # "+c,0" names the line before the gap; nothing is added anyway
            in_hunk = new_left > 0 or any(o > 0 for o in old_left)
    flush()
    return chunks, skipped


def parse_git_log(text: str) -> Tuple[List[AddedChunk], List[Tuple[str, str]], int]:
    """Output of `git log -p --cc GIT_LOG_FORMAT` -> (chunks, skipped, number of commits)."""
    chunks: List[AddedChunk] = []
    skipped: List[Tuple[str, str]] = []
    parts = text.split(GIT_COMMIT_MARK)[1:]
    for part in parts:
        sha, _, rest = part.partition("\n")
        short = sha.strip()[:10]
        msg, _, diff = rest.partition(GIT_MSG_END)
        lines = [ln.rstrip("\r") for ln in msg.split("\n")]
        while lines and not lines[-1].strip():
            lines.pop()
        if lines:
            chunks.append(AddedChunk(short, COMMIT_MESSAGE_FILE, [(i + 1, ln) for i, ln in enumerate(lines)]))
        c, s = parse_unified_diff(diff, short)
        chunks += c
        skipped += s
    return chunks, skipped, len(parts)


class GitScanError(Exception):
    """A Git scan cannot run. The message is safe to show to the user."""


class GitNotFound(GitScanError):
    pass


@dataclass
class GitFinding:
    source: str          # short SHA, "uncommitted" or "untracked"
    file: str
    line: int
    entity: str
    value: str
    recognizer: str
    score: float


@dataclass
class GitScanResult:
    repo: Path
    range_desc: str
    commits: int
    threshold: float
    findings: List[GitFinding]
    skipped: List[Tuple[str, str]]    # (path, "binary" | "too large" | "symlink" | "unreadable")


# An inherited GIT_DIR or GIT_WORK_TREE would make git read another repo than the folder picked.
_GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")
# Pin every option that changes the diff format, so repo config cannot hide added lines:
# --text stops .gitattributes "-diff"/"binary" from hiding text (real binaries are found by NUL);
# fixed prefixes beat diff.noprefix/mnemonicPrefix; --no-relative beats diff.relative.
_GIT_DIFF_OPTS = ("--no-color", "--no-ext-diff", "--no-textconv", "--text", "--unified=0",
                  "--inter-hunk-context=0", "--no-relative", "--src-prefix=a/", "--dst-prefix=b/", "-M")
_GIT_FIXED_CONFIG = ("core.fsmonitor=false", "core.quotepath=off", "diff.suppressBlankEmpty=false")
LFS_POINTER_FIRST_LINE = "version https://git-lfs.github.com/spec/v1"


def _git_env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    return env


def run_git(repo: Path, *args: str, timeout: float = 120, input: bytes = b"",
            config: Sequence[str] = ()) -> bytes:
    """Run one local git command. No shell, no prompts, no repo-configured fsmonitor program.
    `config` adds more `-c key=value` overrides (the scan uses it to switch off filter drivers)."""
    import subprocess
    cmd = ["git"]
    for kv in (*_GIT_FIXED_CONFIG, *config):
        cmd += ["-c", kv]
    cmd += list(args)
    try:
        r = subprocess.run(cmd, cwd=str(repo), env=_git_env(), input=input, capture_output=True,
                           timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        raise GitNotFound("git was not found on PATH") from None
    except subprocess.TimeoutExpired:
        raise GitScanError("git timed out") from None
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        raise GitScanError(f"git {args[0]} failed: {err[0] if err else f'exit code {r.returncode}'}")
    return r.stdout


def git_repo_root(path: Path) -> Path:
    """Root of the working tree that holds `path`. Works in linked worktrees, where .git is a file."""
    if not Path(path).is_dir():
        raise GitScanError(f"Not a Git working tree: {path}")
    try:
        out = run_git(Path(path), "rev-parse", "--show-toplevel")
    except GitNotFound:
        raise
    except GitScanError:
        raise GitScanError(f"Not a Git working tree: {path}") from None
    root = out.decode("utf-8", "replace").strip()
    if not root:
        raise GitScanError(f"Not a Git working tree: {path}")
    return Path(root)


def _untracked_chunk(root: Path, name: str, skipped: List[Tuple[str, str]]) -> Optional[AddedChunk]:
    p = root / name
    try:
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            skipped.append((name, "symlink"))
            return None
        if not stat.S_ISREG(st.st_mode):
            skipped.append((name, "unreadable"))
            return None
        if st.st_size > GIT_SCAN_MAX_BYTES:
            skipped.append((name, "too large"))
            return None
        data = p.read_bytes()
    except OSError:
        skipped.append((name, "unreadable"))
        return None
    if b"\x00" in data[:GIT_BINARY_SNIFF]:
        skipped.append((name, "binary"))
        return None
    lines = data.decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return AddedChunk("untracked", name, [(i + 1, ln[:-1] if ln.endswith("\r") else ln)
                                          for i, ln in enumerate(lines)])


def scan_git_repo(repo: Path, engine: "DetectionEngine", threshold: float, use_ner: bool = False,
                  progress: Callable[[str], None] = lambda s: None) -> GitScanResult:
    """Find PII and secrets in what a push of the current branch sends, plus local work.

    Reads the added lines of every commit that no remote-tracking ref has (merge resolutions
    and messages included), staged and unstaged changes, and untracked files that Git does not
    ignore. Changes nothing in the repo and never touches the session map."""
    root = git_repo_root(Path(repo))

    # Filter drivers (git-lfs, git-crypt, custom clean/smudge) run programs when git hashes a
    # worktree file. Switch every configured driver off for this scan.
    overrides: List[str] = []
    try:
        cfg = run_git(root, "config", "--get-regexp", r"^filter\.").decode("utf-8", "replace")
    except GitNotFound:
        raise
    except GitScanError:
        cfg = ""                 # exit code 1: no filter configured
    for name in sorted({ln.split(" ", 1)[0][len("filter."):].rsplit(".", 1)[0]
                        for ln in cfg.splitlines() if ln.startswith("filter.")}):
        overrides += [f"filter.{name}.clean=", f"filter.{name}.smudge=", f"filter.{name}.process=",
                      f"filter.{name}.required=false"]

    def git(*args: str, **kw) -> str:
        return run_git(root, *args, config=overrides, **kw).decode("utf-8", "replace")

    try:
        git("rev-parse", "--verify", "-q", "HEAD")
        has_head = True
    except GitNotFound:
        raise
    except GitScanError:
        has_head = False         # a new repo with no commits yet
    has_remotes = bool(git("remote").strip())
    range_desc = ("commits not on any remote (remote refs as of the last fetch)" if has_remotes
                  else "all commits (this repo has no remotes)")

    chunks: List[AddedChunk] = []
    skipped: List[Tuple[str, str]] = []
    commits = 0
    if has_head:
        progress("Reading commits...")
        c, s, commits = parse_git_log(git("log", "-p", "--cc", "--root", "--no-show-signature",
                                          *_GIT_DIFF_OPTS, GIT_LOG_FORMAT, "HEAD", "--not", "--remotes"))
        chunks += c
        skipped += s
        base = "HEAD"
    else:
        base = git("hash-object", "-t", "tree", "--stdin").strip()   # the empty tree, in this repo's hash
    progress("Reading uncommitted changes...")
    c, s = parse_unified_diff(git("diff", *_GIT_DIFF_OPTS, base), "uncommitted")
    chunks += c
    skipped += s

    progress("Reading untracked files...")
    for name in git("ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if name:
            ch = _untracked_chunk(root, name, skipped)
            if ch is not None and ch.lines:
                chunks.append(ch)

    progress(f"Analyzing {len(chunks)} chunks...")
    findings: List[GitFinding] = []
    for ch in chunks:
        texts = [t for _, t in ch.lines]
        text = "\n".join(texts)
        if "\x00" in text[:GIT_BINARY_SNIFF]:
            if (ch.file, "binary") not in skipped:
                skipped.append((ch.file, "binary"))
            continue
        if texts and texts[0].strip() == LFS_POINTER_FIRST_LINE:
            skipped.append((ch.file, "LFS object (not scanned)"))   # the push uploads the real object
            continue
        if len(text.encode("utf-8")) > GIT_SCAN_MAX_BYTES:
            skipped.append((ch.file, "too large"))
            continue
        starts, off = [], 0
        for t in texts:
            starts.append(off)
            off += len(t) + 1
        for f in engine.analyze(text, [], SessionVault(), threshold=threshold, skip_ner=not use_ner):
            i = bisect.bisect_right(starts, f.start) - 1
            findings.append(GitFinding(ch.source, ch.file, ch.lines[i][0], f.entity, f.text,
                                       f.recognizer, float(f.score)))
    log.info("Git scan: %s; %d commits, %d findings, %d skipped", range_desc, commits, len(findings),
             len(skipped))
    return GitScanResult(root, range_desc, commits, threshold, findings, skipped)


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


def update_zip_fields(info: Dict, full: bool) -> Tuple[str, str]:
    """(url, sha256) of the release zip for this install: the full zip for a full build, else the small one."""
    if full:
        url = str(info.get("windows_full_zip_url") or "")
        sha = str(info.get("windows_full_zip_sha256") or "").lower()
        if not url or not sha:
            raise SyncError("No full build is available for this version.")
        return url, sha
    return str(info.get("windows_zip_url") or ""), str(info.get("windows_zip_sha256") or "").lower()


def download_windows_build(info: Dict, config, app_dir: Optional[Path] = None, pid: Optional[int] = None,
                           progress: Callable[[str], None] = lambda s: None) -> Path:
    """Download the release zip named in version.json, verify its SHA-256, extract it under
    <app_dir>/updates/<version>/ and write the updater script. Returns the script path.
    The download is unauthenticated: the GitHub token never leaves the API host."""
    app_dir = app_dir or APP_DIR
    full = is_full_build()
    url, expected = update_zip_fields(info, full)
    url_field = "windows_full_zip_url" if full else "windows_zip_url"
    if not url or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SyncError("version.json has no Windows build (windows_zip_url and windows_zip_sha256) - "
                        "download the new release manually")
    if urlparse(url).scheme != "https":
        raise SyncError(f"{url_field} must use https")
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


HEBREW_SELF_TEST_TEXT = "דנה כהן נפגשה עם משה לוי בחיפה."


def self_test(engine: Optional[DetectionEngine] = None,
              require_hebrew: bool = False) -> Tuple[bool, List[str]]:
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
        if engine.hebrew_status == "loaded":
            he = engine.analyze(HEBREW_SELF_TEST_TEXT, [], SessionVault())
            checks.append(("PERSON (Hebrew NER)",
                           any(f.entity == "PERSON" and f.source == "hebrew_ner" for f in he)))
        if require_hebrew:
            checks.append(("Hebrew model loaded", engine.hebrew_status == "loaded"))
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
        start, end = value_span(m)
        if end > start:
            new.append(Finding(start, end, text[start:end], rule.entity, 1.0, "manual", f"manual:{rule.rid}"))
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


_ASTRAL_RE = re.compile("[\U00010000-\U0010FFFF]")
_qt_index_cache: Tuple[Optional[str], List[int]] = (None, [])
_qt_index_lock = threading.Lock()


def py_to_qt_index(text: str, idx: int) -> int:
    """Qt positions count UTF-16 code units; Python counts code points. A character above
    U+FFFF (an emoji) is two UTF-16 units. The positions of such characters are found once per
    text and then looked up with a binary search: the review highlights call this twice for
    each finding, and a scan of text[:idx] for each call froze the window for hours on a large
    PDF (findings x text length)."""
    global _qt_index_cache
    with _qt_index_lock:
        cached_text, astral = _qt_index_cache
        if cached_text is not text:
            astral = [m.start() for m in _ASTRAL_RE.finditer(text)]
            _qt_index_cache = (text, astral)
    return idx + bisect.bisect_left(astral, idx)


_line_cache: Tuple[Optional[str], List[int]] = (None, [])
_line_lock = threading.Lock()


def line_and_context(text: str, start: int, end: int, width: int = 60) -> Tuple[int, str]:
    """(1-based line number, preview) for text[start:end]. The preview has up to width
    characters on each side, the value in [brackets], line breaks as "↵", and "…" where text
    was cut. Line starts are found once per text, then looked up with a binary search."""
    global _line_cache
    with _line_lock:
        cached, breaks = _line_cache
        if cached is not text:
            breaks = [m.start() for m in re.finditer("\n", text)]
            _line_cache = (text, breaks)
    line = bisect.bisect_left(breaks, start) + 1
    a, b = max(0, start - width), min(len(text), end + width)
    snippet = (("…" if a > 0 else "") + text[a:start] + "[" + text[start:end] + "]" + text[end:b]
               + ("…" if b < len(text) else ""))
    return line, snippet.replace("\r", "").replace("\n", "↵")


# ---- PDF ingest ----

BIDI_CONTROLS = "\u200e\u200f\u061c\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_BIDI_RE = re.compile(f"[{BIDI_CONTROLS}]")
_HE = "\u05d0-\u05ea"
_HE_WORD_RE = re.compile(f"[{_HE}]+")
_RUN_RE = re.compile(rf"[A-Za-z0-9](?:[^{_HE}]*[A-Za-z0-9])?|[{_HE}]+|.", re.S)
_HE_FINALS = "\u05da\u05dd\u05df\u05e3\u05e5"


def clean_bidi(text: str) -> str:
    """Remove bidi control characters and normalize line endings to \\n."""
    return _BIDI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")


def is_visual_order(line: str) -> bool:
    """True when Hebrew words look reversed (final letters at word starts, not ends)."""
    starts = ends = 0
    for w in _HE_WORD_RE.findall(line):
        if w[0] in _HE_FINALS:
            starts += 1
        if w[-1] in _HE_FINALS:
            ends += 1
    return starts > ends


def fix_visual_order(line: str) -> str:
    """Turn a visual-order line into logical order; other lines are returned unchanged."""
    if not is_visual_order(line):
        return line
    runs = _RUN_RE.findall(line)
    he = re.compile(f"[{_HE}]+")
    return "".join(r[::-1] if he.fullmatch(r) else r for r in reversed(runs))


def _is_readable_char(c: str) -> bool:
    """A letter, digit, punctuation mark or symbol in any script; not private-use, surrogate or U+FFFD."""
    if c == "\ufffd":
        return False
    cat = unicodedata.category(c)
    return cat[0] in "LNPS" and cat not in ("Co", "Cs")


def is_readable(text: str) -> bool:
    """False when most non-space characters are private-use, replacement or control characters.

    Any script counts as readable (Hebrew, Latin, Cyrillic, Arabic and so on). A broken
    font map gives private-use or U+FFFD characters, which do not count.
    """
    chars = [c for c in text if not c.isspace()]
    if not chars:
        return True
    good = sum(1 for c in chars if _is_readable_char(c))
    return good / len(chars) >= 0.5


class PdfError(Exception):
    """A PDF cannot be read. The message is safe to show to the user."""


@dataclass
class OcrSettings:
    enabled: bool = True
    tesseract_path: str = ""
    languages: str = "heb+eng"
    dpi: int = 300
    timeout: int = 120

    @classmethod
    def from_config(cls, cfg: "AppConfig") -> "OcrSettings":
        d = DEFAULT_CONFIG["pdf"]
        c = cfg.data.get("pdf") or {}
        g = lambda k: c.get(k, d[k])  # noqa: E731

        def num(k: str) -> int:
            # Called from a GUI slot: a bad value ("abc", null) must not raise. Use the default.
            try:
                return int(g(k))
            except (TypeError, ValueError):
                log.warning("Config pdf.%s is not a number; using %s", k, d[k])
                return int(d[k])
        return cls(enabled=bool(g("ocr_enabled")), tesseract_path=str(g("tesseract_path") or ""),
                   languages=str(g("ocr_languages")), dpi=num("ocr_dpi"), timeout=num("ocr_timeout"))


@dataclass
class PdfPage:
    number: int
    method: str  # "text" | "ocr" | "skipped" | "partial"
    reason: str = ""
    text: str = ""
    header: str = ""


@dataclass
class PdfExtraction:
    pages: List[PdfPage]
    text: str

    @property
    def ocr_count(self) -> int:
        return sum(1 for p in self.pages if p.method == "ocr")

    @property
    def skipped_count(self) -> int:
        return sum(1 for p in self.pages if p.method in ("skipped", "partial"))

    @property
    def all_skipped(self) -> bool:
        return not any(p.text.strip() for p in self.pages)


def classify_page(text: str, image_ratio: float) -> str:
    """Return "scanned", "mostly_image", "unreadable" or "text" (in that priority)."""
    if sum(1 for c in text if not c.isspace()) < 20:
        return "scanned"
    if image_ratio >= 0.5:
        return "mostly_image"
    if not is_readable(text):
        return "unreadable"
    return "text"


def _finish_page(number: int, layer_text: str, kind: str, ocr_text: Optional[str],
                 reason: str, ocr_note: str = "") -> PdfPage:
    """Build a PdfPage with the right method and header from the class and the OCR result."""
    if ocr_text is not None and ocr_text.strip():
        note = f", {ocr_note}" if ocr_note else ""
        return PdfPage(number, "ocr", "", ocr_text, f"--- page {number} (OCR{note}) ---")
    if kind == "text":
        return PdfPage(number, "text", "", layer_text, f"--- page {number} ---")
    if kind == "scanned":
        if layer_text.strip():
            # Keep the little text the page has (a stamp, a footer); say that the image was not read.
            return PdfPage(number, "partial", reason, layer_text,
                           f"--- page {number} (little text, image text not read: {reason}) ---")
        return PdfPage(number, "skipped", reason, "", f"--- page {number} (scanned, skipped: {reason}) ---")
    label = "mostly image, image text not read" if kind == "mostly_image" else "unreadable text, not read"
    method = "partial" if layer_text.strip() else "skipped"
    return PdfPage(number, method, reason, layer_text, f"--- page {number} ({label}: {reason}) ---")


def _image_ratio(page) -> float:
    """Share of the page area covered by images, from 0.0 to 1.0.

    get_bounds() gives unrotated user-space coordinates, so clip against the crop box
    (which falls back to the media box) in that same space, not against get_size().
    For an image inside a Form XObject, get_bounds() is in the form's space: apply the
    matrix of each parent form object to get page space.
    """
    box_l, box_b, box_r, box_t = page.get_cropbox()
    area = (box_r - box_l) * (box_t - box_b)
    if area <= 0:
        return 0.0
    covered = 0.0
    for obj in page.get_objects(filter=[pdfium.raw.FPDF_PAGEOBJ_IMAGE], max_depth=5):
        left, bottom, right, top = obj.get_bounds()
        form = obj.container
        if form is not None:
            m = form.get_matrix()
            form = form.container
            while form is not None:
                m = m.multiply(form.get_matrix())  # inner form first, then its parent
                form = form.container
            left, bottom, right, top = m.on_rect(left, bottom, right, top)
        w = min(right, box_r) - max(left, box_l)
        h = min(top, box_t) - max(bottom, box_b)
        if w > 0 and h > 0:
            covered += w * h
    return min(covered / area, 1.0)


def _layer_text(page) -> str:
    textpage = page.get_textpage()
    try:
        raw = clean_bidi(textpage.get_text_bounded())
    finally:
        textpage.close()
    return "\n".join(fix_visual_order(line) for line in raw.split("\n")).rstrip()


FORM_NOTES_LINE = "[form fields and notes]"
FORM_NOTES_FAILED = " (form fields or notes not read)"


def _utf16_value(fn, *args) -> str:
    """Call a pdfium getter that fills a UTF-16LE buffer (size query first, then the read)."""
    size = fn(*args, None, 0)
    if size <= 2:
        return ""
    buf = ctypes.create_string_buffer(size)
    fn(*args, ctypes.cast(buf, ctypes.POINTER(pdfium.raw.FPDF_WCHAR)), size)
    return buf.raw[:size].decode("utf-16-le", "replace").rstrip("\x00")


# Widget types whose value is a state name, not text the user typed.
_NON_TEXT_FIELDS = {1, 2, 3, 7}  # push button, check box, radio button, signature


def _annot_values(page, formenv=None) -> List[str]:
    """Return the form-field values and annotation notes on a page, in annotation order.

    pdfium's text page reads only the page content, so a filled form field (/V) and a
    note such as a FreeText "Fill & Sign" entry (/Contents) are not in the text layer.
    """
    raw = pdfium.raw
    values: List[str] = []
    for i in range(raw.FPDFPage_GetAnnotCount(page.raw)):
        annot = raw.FPDFPage_GetAnnot(page.raw, i)
        if not annot:
            raise PdfError("cannot read annotation")
        try:
            subtype = raw.FPDFAnnot_GetSubtype(annot)
            if subtype == raw.FPDF_ANNOT_POPUP:
                continue  # a popup repeats the note of its parent annotation
            if subtype == raw.FPDF_ANNOT_WIDGET:
                if formenv is not None:
                    if raw.FPDFAnnot_GetFormFieldType(formenv.raw, annot) in _NON_TEXT_FIELDS:
                        continue
                    # Reads /V also when the widget inherits it from a parent field.
                    value = _utf16_value(raw.FPDFAnnot_GetFormFieldValue, formenv.raw, annot)
                else:
                    value = _utf16_value(raw.FPDFAnnot_GetStringValue, annot, b"V")
            else:
                value = _utf16_value(raw.FPDFAnnot_GetStringValue, annot, b"Contents")
        finally:
            raw.FPDFPage_CloseAnnot(annot)
        value = clean_bidi(value).strip()
        if value and value not in values:
            values.append(value)
    return values


def _add_annot_values(done: PdfPage, values: List[str], failed: bool) -> PdfPage:
    """Append form-field values and notes under the page text; mark the header if they were not read."""
    if values:
        block = FORM_NOTES_LINE + "\n" + "\n".join(values)
        done.text = (done.text.rstrip() + "\n" + block) if done.text.strip() else block
    if failed:
        done.header = done.header[:-len(" ---")] + FORM_NOTES_FAILED + " ---"
    return done


def find_tesseract(configured: str = "") -> Optional[Path]:
    """Find the Tesseract program: configured path, bundled copy, PATH, then the Windows default."""
    if configured and Path(configured).is_file():
        return Path(configured)
    bundled = bundle_dir() / "tesseract" / ("tesseract.exe" if os.name == "nt" else "tesseract")
    if bundled.is_file():
        return bundled
    found = shutil.which("tesseract")
    if found:
        return Path(found)
    if os.name == "nt":
        default = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        if default.is_file():
            return default
    return None


def _run_tesseract(args: List[str], timeout: int, data: Optional[bytes] = None) -> "subprocess.CompletedProcess[bytes]":
    # With no data, give Tesseract an empty stdin so it never waits on the app's console.
    stdin = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
    return subprocess.run(args, capture_output=True, timeout=timeout, shell=False,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), **stdin)


def tesseract_info(exe: Path) -> Tuple[str, Set[str]]:
    """Return the Tesseract version line and the set of installed language codes."""
    try:
        v = _run_tesseract([str(exe), "--version"], 30)
        l = _run_tesseract([str(exe), "--list-langs"], 30)
    except (OSError, subprocess.SubprocessError):
        return "", set()
    version = (v.stdout or v.stderr).decode("utf-8", "replace").strip().splitlines()
    # Old Tesseract versions print the list to stderr, new ones to stdout.
    lines = l.stdout.decode("utf-8", "replace").splitlines()[1:]
    if not any(x.strip() for x in lines):
        lines = l.stderr.decode("utf-8", "replace").splitlines()[1:]
    return (version[0].strip() if version else ""), {x.strip() for x in lines if x.strip()}


def ocr_image(exe: Path, image: bytes, languages: str, timeout: int, dpi: int = 300) -> str:
    """Run Tesseract on one image (PGM bytes, sent on stdin) and return the cleaned text.

    Raises PdfError("OCR failed") or PdfError("OCR timed out"). The message goes into the
    page header and so to the LLM, so the detail (it can hold a user path) goes to the log only.
    No temp file is written: Windows Tesseract builds mishandle non-ASCII temp paths.
    PGM carries no resolution, so --dpi tells Tesseract the render DPI.
    """
    try:
        r = _run_tesseract([str(exe), "stdin", "stdout", "--dpi", str(dpi), "-l", languages], timeout, image)
    except subprocess.TimeoutExpired as exc:
        log.warning("OCR timed out after %s s", timeout)
        raise PdfError(OCR_TIMEOUT_REASON) from exc
    except OSError as exc:
        log.warning("OCR failed: %s", exc)
        raise PdfError(OCR_FAILED_REASON) from exc
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip().splitlines()
        log.warning("OCR failed: %s", err[0].strip() if err else f"exit code {r.returncode}")
        raise PdfError(OCR_FAILED_REASON)
    return clean_bidi(r.stdout.decode("utf-8", "replace"))


def _ocr_languages(wanted: str, installed: Set[str]) -> Tuple[str, str]:
    """Return (languages to use, note). Languages is "" when none is installed."""
    codes = [c for c in wanted.split("+") if c]
    have = [c for c in codes if c in installed]
    if not have:
        return "", ""
    if len(have) == len(codes):
        return "+".join(have), ""
    missing = " and ".join(_LANG_NAMES.get(c, c) for c in codes if c not in installed)
    used = " and ".join(_LANG_NAMES.get(c, c) for c in have)
    return "+".join(have), f"{used} only: {missing} language data missing"


def _render_pgm(page, dpi: int) -> bytes:
    """Render a page to binary PGM bytes in memory."""
    bitmap = page.render(scale=dpi / 72, grayscale=True)
    try:
        w, h, stride = bitmap.width, bitmap.height, bitmap.stride
        buf = memoryview(bitmap.buffer).cast("B")
        out = bytearray(f"P5 {w} {h} 255\n".encode("ascii"))
        for y in range(h):
            out += buf[y * stride:y * stride + w]
        return bytes(out)
    finally:
        bitmap.close()


def _prepare_ocr(ocr: OcrSettings) -> Tuple[Optional[Path], str, str, str]:
    """Find Tesseract and pick languages. Returns (exe, languages, note, skip reason)."""
    exe = find_tesseract(ocr.tesseract_path)
    if exe is None:
        return None, "", "", OCR_NO_TESSERACT_REASON
    _version, installed = tesseract_info(exe)
    langs, note = _ocr_languages(ocr.languages, installed)
    if not langs:
        return exe, "", "", OCR_NO_LANG_REASON
    return exe, langs, note, ""


def extract_pdf_text(path: Path, ocr: OcrSettings, progress: Optional[Callable[[str], None]] = None,
                     cancel: Optional[Callable[[], bool]] = None) -> PdfExtraction:
    """Read a PDF page by page. Pages with no usable text layer go through Tesseract when OCR is on."""
    if pdfium is None:
        raise PdfError("PDF support needs the pypdfium2 package.")
    try:
        doc = pdfium.PdfDocument(str(path))
    except pdfium.PdfiumError as exc:
        if getattr(exc, "err_code", None) == pdfium.raw.FPDF_ERR_PASSWORD:
            raise PdfError("This PDF is password protected. PII Shield cannot open it.") from exc
        raise PdfError(f"Cannot open this PDF: {exc}") from exc
    pages: List[PdfPage] = []
    engine = None  # (exe, languages, note, reason), set at the first page that needs OCR
    try:
        try:
            # Before any page loads: rendered pages for OCR then show the form fields.
            doc.init_forms()
        except Exception as exc:  # noqa: BLE001 - a PDF without usable forms still reads
            log.warning("PDF forms not loaded: %s", exc)
        total = len(doc)
        for i in range(total):
            if cancel and cancel():
                break
            n = i + 1
            page = doc[i]
            ocr_text, ocr_note, reason = None, "", ""
            try:
                try:
                    values, values_failed = _annot_values(page, getattr(doc, "formenv", None)), False
                except Exception as exc:  # noqa: BLE001 - never fail the page for its annotations
                    values, values_failed = [], True
                    log.warning("PDF page %d: form fields or notes not read: %s", n, type(exc).__name__)
                layer = _layer_text(page)
                kind = classify_page(layer, _image_ratio(page))
                needs_ocr = kind != "text"
                if progress:
                    progress(f"PDF: page {n} of {total}" + (" (OCR)" if needs_ocr and ocr.enabled else ""))
                if not needs_ocr:
                    pass
                elif not ocr.enabled:
                    reason = OCR_OFF_REASON
                else:
                    if engine is None:
                        engine = _prepare_ocr(ocr)
                    exe, langs, ocr_note, reason = engine
                    if exe is not None and langs:
                        try:
                            ocr_text = ocr_image(exe, _render_pgm(page, ocr.dpi), langs, ocr.timeout, ocr.dpi)
                            if not ocr_text.strip():
                                reason = OCR_NO_TEXT_REASON
                        except PdfError as exc:
                            reason = str(exc)
            finally:
                page.close()
            done = _add_annot_values(_finish_page(n, layer, kind, ocr_text, reason, ocr_note), values, values_failed)
            pages.append(done)
            log.info("PDF page %d: %s%s", n, done.method, f" ({done.reason})" if done.reason else "")
    except pdfium.PdfiumError as exc:
        raise PdfError(f"Cannot read this PDF: {exc}") from exc
    finally:
        doc.close()
    text = "\n\n".join(p.header + "\n" + p.text for p in pages)
    return PdfExtraction(pages, text)


# ---- Hebrew NER ----
HEBREW_LABEL_MAP = {"PER": "PERSON", "ORG": "ORGANIZATION", "GPE": "LOCATION",
                    "LOC": "LOCATION", "FAC": "LOCATION"}
_HEBREW_LETTER_RE = re.compile("[\u05d0-\u05ea]")


@dataclass
class HebrewSpan:
    start: int
    end: int
    entity: str
    score: float
    # (start, end) of each PERSON part that the gap merge joined into this span (_merge_gaps)
    parts: List[Tuple[int, int]] = field(default_factory=list, compare=False)


def _hebrew_groups(text: str) -> List[Tuple[int, int]]:
    """(start, end) of runs of consecutive lines that contain a Hebrew letter."""
    groups: List[Tuple[int, int]] = []
    pos, open_group = 0, None
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if _HEBREW_LETTER_RE.search(body):
            if open_group is None:
                open_group = pos
            last_end = pos + len(body)
        elif open_group is not None:
            groups.append((open_group, last_end))
            open_group = None
        pos += len(line)
    if open_group is not None:
        groups.append((open_group, last_end))
    return groups


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or unicodedata.category(ch).startswith("M")


def _extend_to_words(text: str, spans: List[HebrewSpan]) -> List[HebrewSpan]:
    """Grow each span edge to the whole word (the model labels sub-word tokens, so a span can
    stop inside a word). Same-type spans that overlap after growing are merged."""
    grown: List[HebrewSpan] = []
    for sp in spans:
        start, end = sp.start, sp.end
        while start > 0 and _is_word_char(text[start - 1]):
            start -= 1
        while end < len(text) and _is_word_char(text[end]):
            end += 1
        grown.append(HebrewSpan(start, end, sp.entity, sp.score))
    merged: List[HebrewSpan] = []
    for sp in sorted(grown, key=lambda x: (x.entity, x.start, x.end)):
        last = merged[-1] if merged else None
        if last is not None and last.entity == sp.entity and sp.start < last.end:
            last.end = max(last.end, sp.end)
            last.score = max(last.score, sp.score)
        else:
            merged.append(sp)
    return sorted(merged, key=lambda x: x.start)


# Window size. The plan said 400, but with the real int8 model a 400-token window missed 4 of 48
# person names that 128, 200, 256 and 300-token windows all found. Smaller windows cost no speed.
HEBREW_WINDOW_TOKENS = 256
# One of these characters between two spans can join them (HebrewNerModel._merge_gaps).
HEBREW_SPAN_GAPS = frozenset(" -\u05be'\u05f3")
# The gap merge joins two spans only when one of them scores under the score threshold of the
# analyze call: a weak half would be dropped. Two strong spans are two whole names.
# DetectionEngine.analyze sets HEBREW_MERGE_CUTOFF to its threshold around the Presidio call (a
# context variable, so that two threads with different thresholds do not mix). Other callers get
# HEBREW_MERGE_BELOW, the default engine score threshold.
HEBREW_MERGE_BELOW = 0.85
HEBREW_MERGE_CUTOFF: "contextvars.ContextVar[float]" = contextvars.ContextVar(
    "hebrew_merge_cutoff", default=HEBREW_MERGE_BELOW)
HEBREW_WINDOW_OVERLAP = 50


class HebrewNerModel:
    def __init__(self, tokenizer, session, id2label: Dict[int, str],
                 max_tokens: int = HEBREW_WINDOW_TOKENS, overlap: int = HEBREW_WINDOW_OVERLAP):
        self.tokenizer = tokenizer
        self.session = session
        self.id2label = id2label
        self.max_tokens = max_tokens
        self.overlap = min(overlap, max_tokens - 1)
        self._input_names = {i.name for i in session.get_inputs()}

    def predict(self, text: str, wanted: Optional[Iterable[str]] = None) -> List[HebrewSpan]:
        """Entity spans in text. wanted: the entity types the caller keeps (None: all). A union
        of overlapping spans takes a wanted type when one of its parts has it, so that an
        unwanted best part cannot drop the wanted part with it."""
        wanted = None if wanted is None else set(wanted)
        spans: List[HebrewSpan] = []
        # One model call per group, so that each group keeps only its own context and the 8-bit
        # scores do not depend on other lines (batching lines shifted scores by up to 0.12).
        for g_start, g_end in _hebrew_groups(text):
            spans.extend(self._predict_group(text[g_start:g_end], g_start))
        out = self._merge_gaps(text, self._dedupe(_extend_to_words(text, spans), wanted), wanted)
        return out if wanted is None else [sp for sp in out if sp.entity in wanted]

    def _predict_group(self, group: str, base: int) -> List[HebrewSpan]:
        enc = self.tokenizer.encode(group, add_special_tokens=False)
        ids, offsets = list(enc.ids), list(enc.offsets)
        cls_id = self.tokenizer.token_to_id("[CLS]")
        sep_id = self.tokenizer.token_to_id("[SEP]")
        step = self.max_tokens - self.overlap
        spans: List[HebrewSpan] = []
        for lo in range(0, max(len(ids), 1), step):
            hi = min(lo + self.max_tokens, len(ids))
            if hi <= lo:
                break
            probs = self._run([cls_id] + ids[lo:hi] + [sep_id])[1:-1]
            spans.extend(self._spans(probs, offsets[lo:hi], base))
            if hi >= len(ids):
                break
        return spans

    def _run(self, ids: List[int]):
        import numpy as np
        arr = np.array([ids], dtype=np.int64)
        feeds = {"input_ids": arr, "attention_mask": np.ones_like(arr)}
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = np.zeros_like(arr)
        logits = np.asarray(self.session.run(None, feeds)[0][0], dtype=np.float64)
        e = np.exp(logits - logits.max(axis=-1, keepdims=True))
        return e / e.sum(axis=-1, keepdims=True)

    def _spans(self, probs, offsets, base: int) -> List[HebrewSpan]:
        spans: List[HebrewSpan] = []
        cur = None  # [start, end, type, [scores]]

        def close():
            nonlocal cur
            if cur is not None:
                entity = HEBREW_LABEL_MAP.get(cur[2])
                if entity:
                    spans.append(HebrewSpan(base + cur[0], base + cur[1], entity,
                                            sum(cur[3]) / len(cur[3])))
            cur = None

        for row, (s, e) in zip(probs, offsets):
            if (s, e) == (0, 0):
                continue
            idx = int(row.argmax())
            label = self.id2label.get(idx, "O")
            score = float(row[idx])
            if label == "O" or "-" not in label:
                close()
                continue
            prefix, kind = label.split("-", 1)
            if prefix == "I" and cur is not None and cur[2] == kind:
                cur[1] = e
                cur[3].append(score)
            else:
                close()
                cur = [s, e, kind, [score]]
        close()
        return spans

    @staticmethod
    def _dedupe(spans: List[HebrewSpan], wanted: Optional[Set[str]] = None) -> List[HebrewSpan]:
        """Merge every group of overlapping spans, of any type, into one union span.

        Overlaps come from the 50-token window overlap (one window saw less context and gave
        other labels) and from word extension (PERSON "ז'" grows to "ז'אן" and touches an
        ORGANIZATION "אן-פייר"). resolve_overlaps keeps only one of two overlapping findings, so
        a partial overlap would leave part of a name unmasked. The union never loses coverage.
        Type: PERSON if any part is PERSON, else the type of the highest-scoring part. With a
        wanted set, only the parts of a wanted type choose the type (when there is one).
        Score: the highest part score."""
        merged: List[HebrewSpan] = []
        group: List[HebrewSpan] = []

        def close():
            if not group:
                return
            best = max(group, key=lambda x: x.score)
            typed = [g for g in group if wanted is None or g.entity in wanted] or group
            entity = ("PERSON" if any(g.entity == "PERSON" for g in typed)
                      else max(typed, key=lambda x: x.score).entity)
            merged.append(HebrewSpan(min(g.start for g in group), max(g.end for g in group),
                                     entity, best.score))
            group.clear()

        end = -1
        for sp in sorted(spans, key=lambda x: (x.start, x.end)):
            if group and sp.start >= end:
                close()
            group.append(sp)
            end = max(end, sp.end) if len(group) > 1 else sp.end
        close()
        return merged


    @staticmethod
    def _merge_gaps(text: str, spans: List[HebrewSpan],
                    wanted: Optional[Set[str]] = None) -> List[HebrewSpan]:
        """Join two spans that one gap character (space, '-', maqaf, geresh) separates when one
        of them scores under the cutoff (HEBREW_MERGE_CUTOFF).

        The model often splits a name into two spans: PERSON "ז'אן-פייר" at 0.52 and PERSON
        "לוי" at 0.92, or ORGANIZATION "ז'אן-פייר" at 0.94 and PERSON "לוי" at 0.6. The engine
        threshold applies per span, so it would drop the weak half and leave part of the name
        unmasked. One span with the best score keeps the name whole. The types of the two
        spans can differ. Type: PERSON if a part is PERSON, else the type of the higher-scoring
        part (with a wanted set, only wanted parts choose, when there is one).
        Two spans that both score at or over the cutoff stay separate ("נועה גולן" + "ויעל רוזן",
        "משה לוי" + "בחיפה"): both pass the threshold, and each must propagate alone.
        Score: the highest part score. Input spans do not overlap (_dedupe runs first).
        parts: the (start, end) of each PERSON part of a joined span. The engine propagates these
        parts too: "יוסי אברהמי" + "מחברת אורנים" is one span, and a later bare "יוסי אברהמי"
        must still be masked."""
        below = HEBREW_MERGE_CUTOFF.get()
        merged: List[HebrewSpan] = []
        for sp in sorted(spans, key=lambda x: (x.start, x.end)):
            last = merged[-1] if merged else None
            if (last is not None and sp.start - last.end == 1
                    and text[last.end] in HEBREW_SPAN_GAPS
                    and min(last.score, sp.score) < below):
                if wanted is None or "PERSON" in wanted:
                    # last.parts is empty only when last is one model span or a join of
                    # non-PERSON spans (then its type is not PERSON)
                    if not last.parts and last.entity == "PERSON":
                        last.parts.append((last.start, last.end))
                    if sp.entity == "PERSON":
                        last.parts.append((sp.start, sp.end))
                parts = [p for p in (last, sp) if wanted is None or p.entity in wanted] or [last, sp]
                last.entity = ("PERSON" if any(p.entity == "PERSON" for p in parts)
                               else max(parts, key=lambda x: x.score).entity)
                last.end = sp.end
                last.score = max(last.score, sp.score)
            else:
                merged.append(HebrewSpan(sp.start, sp.end, sp.entity, sp.score))
        return merged


def load_hebrew_model(model_dir: Path) -> HebrewNerModel:
    if ort is None or HfTokenizer is None:
        raise RuntimeError("Hebrew NER needs the onnxruntime and tokenizers packages. "
                           "Install them or use the full build.")
    model_dir = Path(model_dir)
    cfg = json.loads((model_dir / "config.json").read_text(encoding="utf-8"))
    id2label = {int(k): v for k, v in cfg["id2label"].items()}
    tokenizer = HfTokenizer.from_file(str(model_dir / "tokenizer.json"))
    # tokenizer.json may enable truncation (512) or padding. Text past the cut would never reach
    # the model, so a name there would leak. HebrewNerModel does its own windowing.
    tokenizer.no_truncation()
    tokenizer.no_padding()
    missing = [t for t in ("[CLS]", "[SEP]") if tokenizer.token_to_id(t) is None]
    if missing:
        raise RuntimeError("Hebrew NER tokenizer has no " + " or ".join(missing)
                           + " token. The tokenizer.json file does not match the model.")
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 1
    session = ort.InferenceSession(str(model_dir / "model_quantized.onnx"), sess_options=opts,
                                   providers=["CPUExecutionProvider"])
    return HebrewNerModel(tokenizer, session, id2label)


HEBREW_RECOGNIZER = "HebrewNerRecognizer"
HEBREW_PERSON_PARTS_KEY = "hebrew_person_parts"   # recognition_metadata: PERSON part texts

if PRESIDIO_OK:
    class HebrewNerRecognizer(EntityRecognizer):
        """Presidio recognizer over HebrewNerModel. It sits in the English registry; the model
        only reads lines that hold Hebrew letters, so English text is left to spaCy."""

        def __init__(self, model: "HebrewNerModel", organizations: bool = True):
            entities = ["PERSON", "LOCATION"] + (["ORGANIZATION"] if organizations else [])
            super().__init__(supported_entities=entities, supported_language="en", name=HEBREW_RECOGNIZER)
            self.model = model

        def load(self) -> None:  # the model arrives ready; nothing to load
            pass

        def analyze(self, text, entities, nlp_artifacts=None):
            wanted = set(entities or self.supported_entities) & set(self.supported_entities)
            results = []
            for sp in self.model.predict(text, wanted):
                if sp.entity not in wanted:
                    continue
                meta = {RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id}
                if sp.parts:  # DetectionEngine.analyze propagates these texts too
                    meta[HEBREW_PERSON_PARTS_KEY] = [text[a:b] for a, b in sp.parts]
                results.append(RecognizerResult(
                    entity_type=sp.entity, start=sp.start, end=sp.end, score=float(sp.score),
                    recognition_metadata=meta))
            return results


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
                "session": "Session map", "hebrew_ner": "Hebrew NER"}

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
                self.signals.error.emit(f"{exc.__class__.__name__}: {exc}" if not isinstance(exc, (SyncError, RuleError, TokenCollision, GitScanError, PdfError)) else str(exc))

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
    class RuleEditDialog(QtWidgets.QDialog):
        """Edit one rule. The only write goes through save_rule()."""

        def __init__(self, parent, rule: RuleDef, rules_root: Path, entities: Sequence[str]):
            super().__init__(parent)
            self.setWindowTitle(f"Edit rule: {rule.name}")
            self.resize(560, 560)
            self.rule, self.rules_root = rule, rules_root
            kind = rule_kind(rule)
            self._manual = manual_source(rule) if kind == "saved" else None
            is_copy = kind in ("bundled", "remote") or rule.is_marker
            self.base_raw = override_copy(rule) if is_copy else copy.deepcopy(rule.raw)
            source_raw = rule.overrides.raw if rule.is_marker and rule.overrides is not None else rule.raw
            dropped_wordlist = is_copy and "wordlist" in (source_raw or {})

            form = QtWidgets.QFormLayout()
            self.warning_label = QtWidgets.QLabel(
                "This copy no longer follows changes to the original word list." if dropped_wordlist else "")
            self.warning_label.setWordWrap(True)
            self.warning_label.setVisible(dropped_wordlist)
            self.ed_entity = QtWidgets.QComboBox()
            self.ed_entity.setEditable(True)
            cur_entity = str(self.base_raw.get("entity", rule.entity))
            self.ed_entity.addItems([e for e in dict.fromkeys(list(entities) + [cur_entity]) if e])
            self.ed_entity.setCurrentText(cur_entity)
            self.ed_score = QtWidgets.QDoubleSpinBox()
            self.ed_score.setRange(0.01, 1.0)
            self.ed_score.setSingleStep(0.05)
            self.ed_score.setDecimals(2)
            self.ed_score.setValue(float(self.base_raw.get("score", rule.score)))
            self.ed_case = QtWidgets.QCheckBox("Case sensitive")
            self.ed_case.setChecked(bool(self.base_raw.get("case_sensitive", rule.case_sensitive)))
            self.ed_name = QtWidgets.QLabel(rule.name)
            self.ed_name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            form.addRow("Name", self.ed_name)
            form.addRow("Entity", self.ed_entity)
            form.addRow("Score", self.ed_score)
            form.addRow("", self.ed_case)
            if self._manual is not None:
                self.ed_type = QtWidgets.QComboBox()
                for key, label in (("exact", "Exact Match"), ("wildcard", "Wildcard"), ("regex", "Custom Regex")):
                    self.ed_type.addItem(label, key)
                self.ed_type.setCurrentIndex(self.ed_type.findData(self._manual[0]))
                self.ed_pattern = QtWidgets.QLineEdit(self._manual[1])
                form.addRow("Match type", self.ed_type)
                form.addRow("Pattern", self.ed_pattern)
                self.name_hint = QtWidgets.QLabel(
                    "Changing the pattern or entity gives this rule a new name.")
                self.name_hint.setWordWrap(True)
                form.addRow("", self.name_hint)
            else:
                pats = []
                for item in _as_list(self.base_raw.get("patterns")):
                    rx = item.get("regex") if isinstance(item, dict) else item
                    if isinstance(rx, str):
                        pats.append(rx)
                self.ed_patterns = _text_box("One regular expression per line")
                self.ed_patterns.setPlainText("\n".join(pats))
                self.ed_values = _text_box("One exact value per line")
                self.ed_values.setPlainText("\n".join(str(v) for v in _as_list(self.base_raw.get("deny_list"))))
                form.addRow("Patterns", self.ed_patterns)
                form.addRow("Values", self.ed_values)
            self.ed_sample = _text_box("Type sample text to test the rule")
            self.ed_sample.setMaximumHeight(80)
            self.ed_result = QtWidgets.QLabel("")
            self.ed_result.setWordWrap(True)
            form.addRow("Test text", self.ed_sample)
            form.addRow("Matches", self.ed_result)

            self.btn_save = _button("Save", primary=True)
            self.btn_cancel = _button("Cancel")
            row = QtWidgets.QHBoxLayout()
            row.addStretch(1)
            row.addWidget(self.btn_cancel)
            row.addWidget(self.btn_save)
            lay = QtWidgets.QVBoxLayout(self)
            lay.addWidget(self.warning_label)
            lay.addLayout(form)
            lay.addLayout(row)

            self.btn_cancel.clicked.connect(self.reject)
            self.btn_save.clicked.connect(self._save)
            self.ed_sample.textChanged.connect(self._run_test)
            self.ed_case.toggled.connect(self._run_test)
            if self._manual is not None:
                self.ed_pattern.textChanged.connect(self._run_test)
                self.ed_type.currentIndexChanged.connect(self._run_test)
            else:
                self.ed_patterns.textChanged.connect(self._run_test)
                self.ed_values.textChanged.connect(self._run_test)

        def _manual_value(self) -> Tuple[str, str]:
            return self.ed_type.currentData(), self.ed_pattern.text().strip()

        @staticmethod
        def _lines(box) -> List[str]:
            return [ln for ln in box.toPlainText().splitlines() if ln.strip()]

        def _build(self) -> dict:
            manual = self._manual is not None
            return build_edited_raw(
                self.base_raw, entity=self.ed_entity.currentText().strip(),
                score=round(self.ed_score.value(), 2), case_sensitive=self.ed_case.isChecked(),
                manual=self._manual_value() if manual else None,
                patterns=[] if manual else self._lines(self.ed_patterns),
                values=[] if manual else self._lines(self.ed_values))

        def _run_test(self, *_):
            text = self.ed_sample.toPlainText()
            flags = 0 if self.ed_case.isChecked() else re.IGNORECASE
            try:
                if self._manual is not None:
                    mt, pat = self._manual_value()
                    pats = [ManualRule(mt, pat, "X", not self.ed_case.isChecked()).compile()] if pat else []
                else:
                    pats = [re.compile(rx, flags) for rx in self._lines(self.ed_patterns)]
                    pats += [re.compile(literal_to_regex(v), flags) for v in self._lines(self.ed_values)]
            except re.error as exc:
                self.ed_result.setText(f"Regex error: {exc}")
                return
            found = [m.group(0) for rx in pats for m in rx.finditer(text) if m.group(0)]
            self.ed_result.setText(", ".join(found) if found else "No match")

        def _save(self):
            try:
                save_rule(self.rules_root, self.rule, self._build())
            except RuleError as exc:
                QtWidgets.QMessageBox.warning(self, "Save rule", str(exc))
                return
            self.accept()

    class RulesManagerDialog(QtWidgets.QDialog):
        """All rules in one table: switch on or off, edit, delete, restore. Writes only through the
        rule file helpers; every change reloads the rules and refreshes the table."""

        COLUMNS = ["On", "Entity", "Name", "Source", "Matches", "Actions"]
        SOURCES = ["All", "saved", "override", "bundled", "remote", "hand-edited"]
        CHANGED_MSG = "Rules changed. Re-analyze to apply them to the current text."

        def __init__(self, parent):
            super().__init__(parent)
            self.win = parent
            self.setWindowTitle("Rules")
            self.resize(980, 560)
            self._rows: List[RuleDef] = []
            engine = parent.engine
            if not engine.ready:
                # The engine is still loading its model; reload_rules() would block the GUI.
                # Show the files from disk; the engine reads them itself when it is ready.
                self.ruleset = load_rules_dir(engine.rules_root, bundled=True)
            else:
                if not engine.ruleset.all_rules and not engine.ruleset.files:
                    parent._update_rules_badge(engine.reload_rules())
                self.ruleset = engine.ruleset

            self.filter_text = QtWidgets.QLineEdit()
            self.filter_text.setPlaceholderText("Filter by entity, name or matches")
            self.filter_text.setClearButtonEnabled(True)
            self.filter_source = QtWidgets.QComboBox()
            self.filter_source.addItems(self.SOURCES)
            top = QtWidgets.QHBoxLayout()
            top.addWidget(self.filter_text, 1)
            top.addWidget(QtWidgets.QLabel("Source"))
            top.addWidget(self.filter_source)

            self.table = QtWidgets.QTableWidget(0, len(self.COLUMNS))
            self.table.setHorizontalHeaderLabels(self.COLUMNS)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.verticalHeader().setVisible(False)
            hdr = self.table.horizontalHeader()
            hdr.setStretchLastSection(False)
            hdr.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.Stretch)
            for col in (0, 1, 2, 3, 5):
                hdr.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
            self.notes = _text_box(read_only=True)
            self.notes.setMaximumHeight(110)
            lay = QtWidgets.QVBoxLayout(self)
            lay.addLayout(top)
            lay.addWidget(self.table, 1)
            lay.addWidget(self.notes)

            self.filter_text.textChanged.connect(lambda _t: self.refresh())
            self.filter_source.currentIndexChanged.connect(lambda _i: self.refresh())
            self.table.itemChanged.connect(self._on_item_changed)
            self.refresh()

        @staticmethod
        def _matches(rule: RuleDef) -> Tuple[str, str]:
            """(cell text, tooltip) for the Matches column."""
            lines = rule_details(rule)
            tip = "\n".join(lines)
            if rule.broken:
                return "(has errors)", tip
            body = [ln for ln in lines if ln != rule.description]
            return (body[0] if body else ""), tip

        @staticmethod
        def _source_text(rule: RuleDef) -> str:
            kind = rule_kind(rule)
            if kind != "override":
                return kind
            text = "override" + (f" of {rule_kind(rule.overrides)}" if rule.overrides is not None else "")
            status = override_status(rule)
            return text + {"changed": " (original changed)", "removed": " (original removed)"}.get(status, "")

        def refresh(self):
            rs = self.ruleset
            needle = self.filter_text.text().strip().casefold()
            want = self.filter_source.currentText()
            self._rows = []
            self.table.blockSignals(True)
            try:
                self.table.setRowCount(0)
                for rule in rs.all_rules:
                    kind = rule_kind(rule)
                    if want != "All" and kind != want:
                        continue
                    match, tip = self._matches(rule)
                    if needle and needle not in f"{rule.entity} {rule.name} {match}".casefold():
                        continue
                    row = self.table.rowCount()
                    self.table.insertRow(row)
                    self._rows.append(rule)
                    on = QtWidgets.QTableWidgetItem()
                    flags = Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled
                    if kind == "hand-edited":
                        flags = Qt.ItemFlag.NoItemFlags
                        on.setToolTip(f"Edit this file by hand: {rule.source_file}")
                    on.setFlags(flags)
                    on.setCheckState(Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked)
                    self.table.setItem(row, 0, on)
                    for col, text in ((1, rule.entity), (2, rule.name), (3, self._source_text(rule)), (4, match)):
                        item = QtWidgets.QTableWidgetItem(text)
                        item.setToolTip(tip if col == 4 else
                                        (f"Edit this file by hand: {rule.source_file}" if kind == "hand-edited" else ""))
                        self.table.setItem(row, col, item)
                    actions = self._action_widget(rule, kind)
                    if actions is not None:
                        self.table.setCellWidget(row, 5, actions)
            finally:
                self.table.blockSignals(False)
            notes = []
            if rs.errors:
                notes += ["ERRORS (file skipped):"] + ["  " + e for e in rs.errors]
            if rs.warnings:
                notes += ["Warnings:"] + ["  " + w for w in rs.warnings]
            self.notes.setPlainText("\n".join(notes))
            self.notes.setVisible(bool(notes))

        def _action_widget(self, rule: RuleDef, kind: str):
            specs = {"saved": [("Edit", "act_edit", self._edit), ("Delete", "act_delete", self._delete)],
                     "bundled": [("Edit copy", "act_edit", self._edit)],
                     "remote": [("Edit copy", "act_edit", self._edit)],
                     "override": [("Edit", "act_edit", self._edit),
                                  ("Restore original", "act_restore", self._restore)]}.get(kind)
            if not specs:
                return None
            box = QtWidgets.QWidget()
            h = QtWidgets.QHBoxLayout(box)
            h.setContentsMargins(4, 0, 4, 0)
            for label, name, fn in specs:
                b = QtWidgets.QPushButton(label)
                b.setObjectName(name)
                b.clicked.connect(lambda _c=False, r=rule, f=fn: f(r))
                h.addWidget(b)
            return box

        def _changed(self):
            """Reload the rules after a write, then refresh the table and the chip."""
            engine = self.win.engine
            try:
                if engine.ready:
                    self.ruleset = engine.reload_rules()
                    self.win._update_rules_badge(self.ruleset)
                else:       # display only; the engine loads the new files when it is ready
                    self.ruleset = load_rules_dir(engine.rules_root, bundled=True)
            except Exception as exc:    # an exception in a Qt slot would abort the app
                log.exception("rules reload after a change failed")
                QtWidgets.QMessageBox.warning(self, "Rules", f"The change was saved, but reloading the rules "
                                              f"failed: {exc.__class__.__name__}: {exc}")
                return
            self.refresh()
            self.win.statusBar().showMessage(self.CHANGED_MSG)

        def _write(self, action: Callable[[], None]) -> bool:
            try:
                action()
            except RuleError as exc:
                QtWidgets.QMessageBox.warning(self, "Rules", str(exc))
                return False
            self._changed()
            return True

        def _on_item_changed(self, item):
            if item.column() != 0 or not 0 <= item.row() < len(self._rows):
                return
            rule = self._rows[item.row()]
            enabled = item.checkState() == Qt.CheckState.Checked
            if not self._write(lambda: set_rule_enabled(self.win.engine.rules_root, rule, enabled)):
                self.refresh()      # put the checkbox back

        def _edit(self, rule: RuleDef):
            entities = [self.win.m_entity.itemText(i) for i in range(self.win.m_entity.count())]
            dlg = RuleEditDialog(self, rule, self.win.engine.rules_root, entities)
            if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                self._changed()

        def _confirm(self, title: str, text: str) -> bool:
            Btn = QtWidgets.QMessageBox.StandardButton
            return QtWidgets.QMessageBox.question(self, title, text, Btn.Yes | Btn.No, Btn.No) == Btn.Yes

        def _delete(self, rule: RuleDef):
            if self._confirm("Delete rule", f"Delete the saved rule '{rule.name}'?"):
                self._write(lambda: delete_rule(self.win.engine.rules_root, rule))

        def _restore(self, rule: RuleDef):
            text = ("Delete your copy and use the original rule?" if rule.overrides is not None
                    else "The original rule no longer exists. This deletes the rule.")
            if self._confirm("Restore original", text):
                self._write(lambda: restore_original(self.win.engine.rules_root, rule))

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
            self.threshold.setValue(float(e.get("score_threshold", 0.85)))
            self.orgs = QtWidgets.QCheckBox("Detect ORGANIZATION names with spaCy NER (noisy)")
            self.orgs.setChecked(bool(e.get("detect_organizations")))
            self.skip_ner_logs = QtWidgets.QCheckBox("Turn off spaCy NER (names, organizations, places) "
                                                     "when the input looks like log lines")
            self.skip_ner_logs.setChecked(bool(e.get("skip_ner_on_logs")))
            # The model folder without onnxruntime or tokenizers cannot load: not installed.
            model_found = find_hebrew_model() is not None
            self.has_hebrew_model = model_found and hebrew_runtime_ok()
            label = "Hebrew name detection (DictaBERT NER)"
            if model_found and not self.has_hebrew_model:
                label += " \u2014 Hebrew model not installed (onnxruntime or tokenizers is missing)"
            elif not model_found:
                label += " \u2014 Hebrew model not installed"
            self.chk_hebrew = QtWidgets.QCheckBox(label)
            self.chk_hebrew.setToolTip("Model: DictaBERT NER by Dicta, CC BY 4.0.")
            self.chk_hebrew.setChecked(bool(e.get("hebrew_ner")))
            self.chk_hebrew.setEnabled(self.has_hebrew_model)
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
            f1.addRow("", self.skip_ner_logs)
            f1.addRow("", self.chk_hebrew)
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

            # pdf
            w3 = QtWidgets.QWidget()
            f3 = QtWidgets.QFormLayout(w3)
            pdf = config["pdf"]
            self.chk_ocr = QtWidgets.QCheckBox("OCR scanned pages (Tesseract)")
            self.chk_ocr.setChecked(bool(pdf.get("ocr_enabled", True)))
            self.ed_tesseract = QtWidgets.QLineEdit(pdf.get("tesseract_path", ""))
            self.ed_tesseract.setPlaceholderText("Empty = find Tesseract automatically")
            btn_tess = QtWidgets.QPushButton("Browse...")
            btn_tess.clicked.connect(self._browse_tesseract)
            row_tess = QtWidgets.QHBoxLayout()
            row_tess.addWidget(self.ed_tesseract)
            row_tess.addWidget(btn_tess)
            self.lbl_tesseract = QtWidgets.QLabel()
            self.ed_tesseract.editingFinished.connect(self._update_tesseract_label)
            f3.addRow("", self.chk_ocr)
            f3.addRow("Tesseract program", row_tess)
            f3.addRow("", self.lbl_tesseract)
            tabs.addTab(w3, "PDF")
            self._update_tesseract_label()

            bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok |
                                            QtWidgets.QDialogButtonBox.StandardButton.Cancel)
            bb.accepted.connect(self._accept)
            bb.rejected.connect(self.reject)
            lay = QtWidgets.QVBoxLayout(self)
            lay.addWidget(tabs)
            lay.addWidget(bb)
            self.needs_engine_restart = False

        def _browse_tesseract(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Tesseract program", self.ed_tesseract.text())
            if p:
                self.ed_tesseract.setText(p)
                self._update_tesseract_label()

        def _update_tesseract_label(self, *_):
            try:
                exe = find_tesseract(self.ed_tesseract.text().strip())
                if exe is None:
                    raise FileNotFoundError("tesseract")
                version, langs = tesseract_info(exe)
                if not version:
                    raise FileNotFoundError("tesseract does not run")
                version = re.sub(r"^tesseract\s+", "", version, flags=re.I)
                yn = lambda ok: "yes" if ok else "no"
                text = f"Tesseract {version}: Hebrew {yn('heb' in langs)}, English {yn('eng' in langs)}"
            except Exception:
                text = "Tesseract not found"
            self.lbl_tesseract.setText(text)

        def _accept(self):
            tf = self.token_format.text().strip()
            if "{entity}" not in tf or "{n}" not in tf:
                QtWidgets.QMessageBox.warning(self, "Token format", "Token format must contain {entity} and {n}.")
                return
            e, b = self.config["engine"], self.config["behavior"]
            model = self.model.currentText()
            self.needs_engine_restart = (model != e.get("spacy_model") or
                                         self.orgs.isChecked() != bool(e.get("detect_organizations")) or
                                         (self.has_hebrew_model and
                                          self.chk_hebrew.isChecked() != bool(e.get("hebrew_ner"))))
            e["spacy_model"] = model
            e["score_threshold"] = round(self.threshold.value(), 2)
            e["detect_organizations"] = self.orgs.isChecked()
            e["skip_ner_on_logs"] = self.skip_ner_logs.isChecked()
            if self.has_hebrew_model:       # a disabled box must not erase the saved choice
                e["hebrew_ner"] = self.chk_hebrew.isChecked()
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
            self.config["pdf"].update(ocr_enabled=self.chk_ocr.isChecked(),
                                      tesseract_path=self.ed_tesseract.text().strip())
            self.config.save()
            self.accept()

    # -----------------------------------------------------------------------
    class GitScanDialog(QtWidgets.QDialog):
        """Scan Git Repo: report PII and secrets in what a push of the branch sends, plus local work."""
        HEADERS = ("Source", "File", "Line", "Entity", "Value", "Recognizer")

        def __init__(self, config: AppConfig, engine: DetectionEngine,
                     threshold: Callable[[], float], parent=None):
            super().__init__(parent)
            self.config, self.engine, self.threshold = config, engine, threshold
            self._task = None
            self._result: Optional[GitScanResult] = None
            self.allow_list_path = ALLOW_LIST_FILE
            self.setWindowTitle("Git Scan")
            self.setModal(False)
            self.resize(1000, 620)
            lay = QtWidgets.QVBoxLayout(self)

            row = QtWidgets.QHBoxLayout()
            self.path_edit = QtWidgets.QLineEdit(config["behavior"].get("git_scan_last_repo", ""))
            self.path_edit.setPlaceholderText("Repo folder (a linked worktree also works)")
            self.path_edit.returnPressed.connect(self.start_scan)
            self.btn_browse = _button("Browse...")
            self.btn_browse.clicked.connect(self._browse)
            row.addWidget(QtWidgets.QLabel("Repo:"))
            row.addWidget(self.path_edit, 1)
            row.addWidget(self.btn_browse)
            lay.addLayout(row)

            row = QtWidgets.QHBoxLayout()
            self.chk_ner = QtWidgets.QCheckBox("Find names with spaCy (more noise)")
            self.chk_ner.setChecked(False)
            self.btn_scan = _button("Scan", primary=True)
            self.btn_scan.clicked.connect(self.start_scan)
            row.addWidget(self.chk_ner)
            row.addStretch(1)
            row.addWidget(self.btn_scan)
            lay.addLayout(row)

            self.lbl_status = QtWidgets.QLabel("Scans the commits this branch would push, plus uncommitted "
                                               "and untracked files. Nothing in the repo changes.")
            self.lbl_status.setWordWrap(True)
            lay.addWidget(self.lbl_status)
            self.lbl_note = QtWidgets.QLabel()
            self.lbl_note.setWordWrap(True)
            set_note(self.lbl_note, "", "okmsg")
            lay.addWidget(self.lbl_note)

            self.table = QtWidgets.QTableWidget(0, len(self.HEADERS))
            self.table.setHorizontalHeaderLabels(self.HEADERS)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.verticalHeader().setVisible(False)
            hdr = self.table.horizontalHeader()
            hdr.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Interactive)
            hdr.setStretchLastSection(True)
            for col, width in enumerate((100, 300, 60, 130, 220)):
                self.table.setColumnWidth(col, width)
            self.table.setSortingEnabled(True)
            self.table.cellDoubleClicked.connect(self._copy_location)
            self.table.setToolTip("Double-click a row to copy file:line. Right-click for more.")
            self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._table_menu)
            self._menu = QtWidgets.QMenu(self)
            self.a_allow = self._menu.addAction("Add to permanent allow-list (never flag again)", self.allow_selected)
            self._menu.addSeparator()
            self.a_copy_value = self._menu.addAction("Copy value", self._copy_selected_values)
            self.a_copy_loc = self._menu.addAction(
                "Copy file:line", lambda: self._copy_location(self.table.currentRow(), 0))
            lay.addWidget(self.table, 1)

            self.skipped_box = QtWidgets.QGroupBox("Skipped files (0)")
            self.skipped_box.setCheckable(True)
            self.skipped_box.setChecked(False)
            sb = QtWidgets.QVBoxLayout(self.skipped_box)
            self.skipped_list = QtWidgets.QListWidget()
            self.skipped_list.setMaximumHeight(120)
            self.skipped_list.setVisible(False)
            sb.addWidget(self.skipped_list)
            self.skipped_box.toggled.connect(self.skipped_list.setVisible)
            lay.addWidget(self.skipped_box)

            row = QtWidgets.QHBoxLayout()
            self.btn_copy = _button("Copy Results")
            self.btn_copy.clicked.connect(lambda: QtWidgets.QApplication.clipboard().setText(self.results_tsv()))
            btn_close = _button("Close")
            btn_close.clicked.connect(self.close)
            row.addWidget(self.btn_copy)
            row.addStretch(1)
            row.addWidget(btn_close)
            lay.addLayout(row)

        def _browse(self):
            p = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose a Git repo folder", self.path_edit.text())
            if p:
                self.path_edit.setText(p)

        def start_scan(self) -> None:
            path = self.path_edit.text().strip()
            if not path:
                set_note(self.lbl_note, "Choose a repo folder.", "stale")
                return
            if not self.btn_scan.isEnabled():
                return
            self.config["behavior"]["git_scan_last_repo"] = path
            try:
                self.config.save()
            except OSError as exc:
                log.warning("Could not save config.json: %s", exc)
            thr = float(self.threshold())
            self.btn_scan.setEnabled(False)
            set_note(self.lbl_note, "", "okmsg")
            self.lbl_status.setText("Scanning...")
            t = Task(scan_git_repo, Path(path), self.engine, thr, use_ner=self.chk_ner.isChecked(),
                     wants_progress=True)
            t.signals.progress.connect(self.lbl_status.setText)
            t.signals.done.connect(self._scan_done)
            t.signals.error.connect(self._scan_error)
            self._task = t
            QtCore.QThreadPool.globalInstance().start(t)

        def _scan_done(self, result: GitScanResult):
            self.btn_scan.setEnabled(True)
            self.show_result(result)

        def _scan_error(self, msg: str):
            self.btn_scan.setEnabled(True)
            self.lbl_status.setText("The scan did not run.")
            set_note(self.lbl_note, msg, "leak")
            log.error("Git scan: %s", msg)

        def show_result(self, result: GitScanResult) -> None:
            self._result = result
            self._render()

        def _render(self) -> None:
            r = self._result
            self.lbl_status.setText(f"Range: {r.range_desc} · {r.commits} commits · {len(r.findings)} findings · "
                                    f"{len(r.skipped)} skipped · min score {r.threshold:.2f}")
            n = len(r.findings)
            if n:
                set_note(self.lbl_note, f"{n} findings. Fix them before you push.", "leak")
            elif r.skipped:
                set_note(self.lbl_note, f"No findings, but {len(r.skipped)} files were not scanned. "
                                        "See Skipped files.", "stale")
            elif r.commits:
                set_note(self.lbl_note, f"No findings in {r.commits} commits and the uncommitted changes.", "okmsg")
            else:
                set_note(self.lbl_note, "0 commits to push. No findings in the uncommitted changes.", "stale")
            self.table.setSortingEnabled(False)
            self.table.setRowCount(n)
            for i, f in enumerate(r.findings):
                for col, val in enumerate((f.source, f.file, f.line, f.entity, f.value, f.recognizer)):
                    item = QtWidgets.QTableWidgetItem()
                    item.setData(Qt.ItemDataRole.DisplayRole, val)   # an int sorts as a number
                    self.table.setItem(i, col, item)
            self.table.setSortingEnabled(True)
            self.skipped_box.setTitle(f"Skipped files ({len(r.skipped)})")
            self.skipped_list.clear()
            self.skipped_list.addItems([f"{p} — {why}" for p, why in r.skipped])

        def table_menu_actions(self) -> List[QtGui.QAction]:
            return [a for a in self._menu.actions() if not a.isSeparator()]

        def _table_menu(self, pos):
            if not self._selected_values():
                return
            self.a_allow.setEnabled(self.btn_scan.isEnabled())   # no rule reload while a scan runs
            self._menu.exec(self.table.viewport().mapToGlobal(pos))

        def _selected_values(self) -> List[str]:
            rows = sorted({i.row() for i in self.table.selectedIndexes()})
            items = [self.table.item(r, 4) for r in rows]
            return sorted({it.text().strip() for it in items if it is not None and it.text().strip()})

        def _copy_selected_values(self):
            QtWidgets.QApplication.clipboard().setText("\n".join(self._selected_values()))

        def allow_selected(self) -> None:
            vals = self._selected_values()
            if not vals:
                return
            if QtWidgets.QMessageBox.question(
                    self, "Allow-list", f"Add {len(vals)} value(s) to rules/local/allow_list.yaml?\n"
                    "They will never be flagged again (except by manual rules).\n"
                    "All rows with these values leave this list.") != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            self.allow_values(vals)

        def allow_values(self, values: List[str]) -> int:
            """Add values to the allow list, drop every row with one of them, and reload the rules.
            Matches like the allow list itself: trimmed and case-insensitive. Returns rows removed."""
            add_to_allow_list(values, self.allow_list_path)
            keys = {v.strip().casefold() for v in values}
            removed = 0
            if self._result is not None:
                keep = [f for f in self._result.findings if f.value.strip().casefold() not in keys]
                removed = len(self._result.findings) - len(keep)
                self._result.findings = keep
                self._render()
            parent = self.parent()
            if parent is not None and hasattr(parent, "reload_rules"):
                parent.reload_rules()
            else:
                self.engine.reload_rules()
            log.info("Git scan: %d value(s) added to the allow list; %d row(s) removed", len(keys), removed)
            return removed

        def _copy_location(self, row: int, _col: int):
            f, ln = self.table.item(row, 1), self.table.item(row, 2)
            if f is not None and ln is not None:
                QtWidgets.QApplication.clipboard().setText(f"{f.text()}:{ln.text()}")

        def results_tsv(self) -> str:
            out = ["\t".join(self.HEADERS)]
            for i in range(self.table.rowCount()):
                out.append("\t".join(self.table.item(i, c).text() if self.table.item(i, c) else ""
                                     for c in range(len(self.HEADERS))))
            return "\n".join(out)

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
            self.btn_load = _button("Load File...")
            self.btn_load.clicked.connect(self.load_file)
            btn_load = self.btn_load
            self.btn_save_review = _button("Save Review...", tip="Save the analyzed text, the findings "
                                           "and your choices, to load them later without a new analysis")
            self.btn_save_review.clicked.connect(self.save_review)
            self.btn_save_review.setEnabled(False)
            self.btn_load_review = _button("Load Review...", tip="Load a saved review: no new analysis")
            self.btn_load_review.clicked.connect(self.load_review)
            self.btn_git_scan = _button("Scan Git Repo...", tip="Scan the commits this branch would push, plus "
                                        "uncommitted and untracked files, for PII and secrets")
            self.btn_git_scan.clicked.connect(self.open_git_scan)
            self.btn_git_scan.setEnabled(False)
            self._git_scan_dialog = None
            self._pdf_task: Optional[Task] = None
            self._pdf_cancel = False
            self._closing = False
            btn_clear = _button("Clear", tip="Clear the input and the Step 2 review. The session map and "
                                             "temporary rules stay until Reset Session.")
            btn_clear.clicked.connect(self.clear_input_and_review)
            self.btn_send = _button("Send to Sanitize (Ctrl+G)", primary=True,
                                    tip="Generate the sanitized prompt and open tab 2")
            self.btn_send.clicked.connect(self.generate)
            self.btn_send.setEnabled(False)
            self.thr = QtWidgets.QDoubleSpinBox()
            self.thr.setRange(0.0, 1.0)
            self.thr.setSingleStep(0.05)
            self.thr.setValue(float(self.config["engine"].get("score_threshold", 0.85)))
            self.thr.setPrefix("min score ")
            self.lbl_stale = QtWidgets.QLabel()
            self.lbl_stale.setVisible(False)
            row.addWidget(self.btn_analyze)
            row.addWidget(self.thr)
            row.addWidget(btn_load)
            row.addWidget(self.btn_save_review)
            row.addWidget(self.btn_load_review)
            row.addWidget(self.btn_git_scan)
            row.addWidget(btn_clear)
            row.addWidget(self.btn_send)
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
            b_sel_on = _button("Enable selected", tip="Select rows with Ctrl+click or Shift+click. "
                                                       "Space switches the selected rows on or off.")
            b_sel_off = _button("Disable selected", tip="Select rows with Ctrl+click or Shift+click. "
                                                         "Space switches the selected rows on or off.")
            b_sel_on.clicked.connect(lambda: self._set_enabled_selected(True))
            b_sel_off.clicked.connect(lambda: self._set_enabled_selected(False))
            self.chk_group = QtWidgets.QCheckBox("Group same values")
            self.chk_group.setToolTip("One row per value, with a Count column. Changes in a row apply "
                                      "to every copy of the value. Clear it to change one copy only.")
            self.chk_group.setChecked(bool(self.config["behavior"].get("group_values", True)))
            self.chk_group.toggled.connect(self._on_group_toggled)
            self._jump = (None, 0)   # (first finding index of the row, copy number) for click-to-next
            frow.addWidget(self.search, 1)
            frow.addWidget(self.chk_group)
            frow.addWidget(self.type_filter)
            frow.addWidget(b_all)
            frow.addWidget(b_none)
            frow.addWidget(b_sel_on)
            frow.addWidget(b_sel_off)
            ll.addLayout(frow)
            self.table = QtWidgets.QTableWidget(0, len(COLS))
            self.table.setHorizontalHeaderLabels(COLS)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
            sc = QtGui.QShortcut(QtGui.QKeySequence(Qt.Key.Key_Space), self.table)
            sc.setContext(Qt.ShortcutContext.WidgetShortcut)
            sc.activated.connect(self._toggle_selected)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.DoubleClicked |
                                       QtWidgets.QAbstractItemView.EditTrigger.EditKeyPressed |
                                       QtWidgets.QAbstractItemView.EditTrigger.SelectedClicked)
            hh = self.table.horizontalHeader()
            # Every column is user-resizable. A Stretch column would ignore drags, so the last column
            # (Source) takes up the free space instead.
            hh.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Interactive)
            hh.setStretchLastSection(True)
            for c, w in ((C_EN, 60), (C_TEXT, 300), (C_ENT, 150), (C_TOK, 170), (C_START, 60), (C_END, 60),
                         (C_SCORE, 55), (C_SRC, 100)):
                self.table.setColumnWidth(c, w)
            self.table.setSortingEnabled(True)
            self.table.sortByColumn(C_START, Qt.SortOrder.AscendingOrder)
            self.table.itemChanged.connect(self._on_item_changed)
            self.table.itemSelectionChanged.connect(self._on_row_selected)
            self.table.cellClicked.connect(self._on_row_clicked)
            self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
            self.table.viewport().installEventFilter(self)
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
            l.addLayout(self._build_split_row())
            self._parts: List[str] = []
            self.output.textChanged.connect(self._on_output_changed)
            self._on_output_changed()
            lay.addWidget(g)
            return page

        def _build_split_row(self):
            """Split the sanitized output into parts, copy them one by one, export to .txt."""
            b = self.config["behavior"]
            row = QtWidgets.QHBoxLayout()
            row.addWidget(QtWidgets.QLabel("Split into parts of"))
            self.spin_split = QtWidgets.QSpinBox()
            self.spin_split.setRange(1000, 1_000_000)
            self.spin_split.setSingleStep(5000)
            self.spin_split.setGroupSeparatorShown(True)
            self.spin_split.setValue(int(b.get("split_chars", 50000)))
            row.addWidget(self.spin_split)
            row.addWidget(QtWidgets.QLabel("characters"))
            self.chk_split_headers = QtWidgets.QCheckBox("Part headers")
            self.chk_split_headers.setChecked(bool(b.get("split_headers", True)))
            self.chk_split_headers.setToolTip('Start each part with a line such as "--- Part 2 of 7 ---"')
            row.addWidget(self.chk_split_headers)
            self.btn_split = _button("Split")
            self.btn_split.clicked.connect(self.split_now)
            row.addWidget(self.btn_split)
            row.addWidget(QtWidgets.QLabel("Part:"))
            self.cmb_parts = QtWidgets.QComboBox()
            self.cmb_parts.setMinimumContentsLength(8)
            row.addWidget(self.cmb_parts)
            self.btn_copy_part = _button("Copy Part")
            self.btn_copy_part.setToolTip("Copy the selected part, then select the next part")
            self.btn_copy_part.clicked.connect(self.copy_part)
            row.addWidget(self.btn_copy_part)
            row.addStretch(1)
            self.btn_export_full = _button("Export Full Text…")
            self.btn_export_full.clicked.connect(self.export_full)
            self.btn_export_parts = _button("Export Parts…")
            self.btn_export_parts.clicked.connect(self.export_parts)
            row.addWidget(self.btn_export_full)
            row.addWidget(self.btn_export_parts)
            return row

        def _on_output_changed(self):
            """A new sanitized output makes old parts wrong, so they are cleared."""
            self._parts = []
            self.cmb_parts.clear()
            has_text = bool(self.output.toPlainText())
            self.btn_split.setEnabled(has_text)
            self.btn_export_full.setEnabled(has_text)
            self.btn_copy_part.setEnabled(False)
            self.btn_export_parts.setEnabled(False)

        def split_now(self):
            text = self.output.toPlainText()
            if not text:
                return
            size, headers = self.spin_split.value(), self.chk_split_headers.isChecked()
            self.config["behavior"]["split_chars"] = size
            self.config["behavior"]["split_headers"] = headers
            self.config.save()
            # leave room for the header line, so a part with its header stays near the size
            parts = split_output(text, max(500, size - 32) if headers else size)
            self._parts = with_part_headers(parts) if headers else parts
            self.cmb_parts.clear()
            self.cmb_parts.addItems([f"{i} of {len(self._parts)}" for i in range(1, len(self._parts) + 1)])
            self.btn_copy_part.setEnabled(True)
            self.btn_export_parts.setEnabled(True)
            self.statusBar().showMessage(f"Split into {len(self._parts)} part(s)", 5000)

        def copy_part(self):
            i = self.cmb_parts.currentIndex()
            if not 0 <= i < len(self._parts):
                return
            self.copy_text(self._parts[i])
            if i + 1 < len(self._parts):
                self.cmb_parts.setCurrentIndex(i + 1)

        def export_full(self):
            text = self.output.toPlainText()
            if not text:
                return
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Full Text", "sanitized.txt",
                                                            "Text (*.txt);;All (*)")
            if not path:
                return
            try:
                Path(path).write_text(text, "utf-8")
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Export Full Text", str(exc))
                return
            self.statusBar().showMessage(f"Exported the sanitized text to {Path(path).name}", 6000)

        def export_parts(self):
            if not self._parts:
                return
            folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Export Parts: select a folder")
            if not folder:
                return
            targets = [Path(folder) / n for n in part_file_names(len(self._parts))]
            existing = [t for t in targets if t.exists()]
            if existing and QtWidgets.QMessageBox.question(
                    self, "Export Parts", f"{len(existing)} part file(s) already exist in this folder. "
                    "Overwrite them?") != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            try:
                for target, part in zip(targets, self._parts):
                    target.write_text(part, "utf-8")
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Export Parts", str(exc))
                return
            self.statusBar().showMessage(f"Exported {len(targets)} part(s) to {folder}", 6000)

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
            self.map_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.map_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.map_table.customContextMenuRequested.connect(self._map_menu)
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
            """progress: False (none), True (engine label and log) or a bound method that gets
            each progress text. A bound method, not a lambda: Qt then drops a queued call when
            the window is deleted."""
            t = Task(fn, *args, wants_progress=bool(progress))
            t.signals.done.connect(done)
            t.signals.error.connect(error or self._task_error)
            if callable(progress):
                t.signals.progress.connect(progress)
            elif progress:
                t.signals.progress.connect(lambda m: (self.lbl_engine.setText(m), log.info(m)))
            self._tasks = [x for x in self._tasks if x is not None][-10:] + [t]
            QtCore.QThreadPool.globalInstance().start(t)

        def _task_error(self, msg):
            self.setCursor(Qt.CursorShape.ArrowCursor)
            self.btn_analyze.setEnabled(self.engine.mode != "uninitialized")
            self.btn_git_scan.setEnabled(self.engine.mode != "uninitialized")
            log.error(msg)
            QtWidgets.QMessageBox.critical(self, APP_NAME, msg)

        def _start_engine(self):
            self.btn_analyze.setEnabled(False)
            self.lbl_engine.setText("Engine: loading NLP model (first start can take ~10-20 s)...")

            def done(mode):
                desc = {"presidio+spacy": f"Presidio + spaCy {self.engine.model_name}",
                        "presidio-regex-only": "Presidio (regex only - no spaCy model installed)",
                        "lite": "Lite regex engine (Presidio not installed)"}.get(mode, mode)
                present = find_hebrew_model() is not None or is_full_build()
                self.lbl_engine.setText(f"Engine: {desc}  ·  offline"
                                        + hebrew_status_suffix(self.engine.hebrew_status, present))
                self.btn_analyze.setEnabled(True)
                self.btn_git_scan.setEnabled(True)
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

            self._run(check_package_updates, self._on_presidio_checked, self.config,
                      error=lambda m: log.warning("Presidio update check failed: %s", m))

        def _on_presidio_checked(self, res):
            """A newer Presidio goes to the Log tab only, not the status bar: the app updates
            Presidio with a tested release, so the user has nothing to do."""
            if res is None:
                return
            for r in res:
                log.info("%s: installed %s, latest %s", r["package"], r["installed"] or "(none)", r["latest"])
            newer = [r for r in res if r["newer"]]
            if newer:
                log.info("%s", presidio_update_hint(newer, is_frozen()))

        def reload_rules(self):
            # A bound method, not a lambda: Qt drops the queued call when the window is deleted.
            self._run(self.engine.reload_rules, self._on_rules_reloaded)

        def _on_rules_reloaded(self, rs: RuleSet):
            self._update_rules_badge(rs)
            self.statusBar().showMessage("Rules reloaded", 4000)

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
            self._rules_manager = RulesManagerDialog(self)
            self._rules_manager.exec()
            self._rules_manager.deleteLater()   # one window per open; free it after it closes

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
        def open_git_scan(self):
            if self._git_scan_dialog is None:
                self._git_scan_dialog = GitScanDialog(self.config, self.engine, self.thr.value, self)
            self._git_scan_dialog.show()
            self._git_scan_dialog.raise_()
            self._git_scan_dialog.activateWindow()

        def load_file(self):
            p, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Load file", "", "Text (*.txt *.log *.md *.json *.yaml *.yml *.csv *.xml *.ps1 *.py *.conf *.ini *.pdf);;"
                "PDF (*.pdf);;All (*)")
            if p:
                self.load_path(Path(p))

        def load_path(self, path: Path):
            if path.suffix.lower() == ".pdf":
                self._load_pdf(path)
                return
            try:
                text = path.read_text("utf-8", errors="replace")
                self.clear_review()
                self.input.setPlainText(text)
            except Exception as exc:
                QtWidgets.QMessageBox.warning(self, "Load file", str(exc))

        def _load_pdf(self, path: Path):
            if self._pdf_task is not None:
                self.statusBar().showMessage("A PDF is already loading")
                return
            self._pdf_cancel = False
            task = Task(extract_pdf_text, path, OcrSettings.from_config(self.config),
                        wants_progress=True, cancel=lambda: self._pdf_cancel)
            task.signals.progress.connect(self._on_pdf_progress)
            task.signals.done.connect(self._on_pdf_done)
            task.signals.error.connect(self._on_pdf_error)
            self._pdf_task = task
            self.btn_load.setEnabled(False)
            self.statusBar().showMessage("Loading PDF...")
            QtCore.QThreadPool.globalInstance().start(task)

        def _on_pdf_progress(self, msg: str):
            # Connect bound methods of the window, not lambdas: a lambda has no receiver object, so
            # Qt cannot drop a queued call when the window is deleted, and the call runs on a dead window.
            if not self._closing:
                self.statusBar().showMessage(msg)

        def _pdf_finished(self):
            self._pdf_task = None
            self._pdf_cancel = False
            self.btn_load.setEnabled(True)

        def _on_pdf_done(self, result: PdfExtraction):
            if self._closing:
                return
            self._pdf_finished()
            self.clear_review()
            self.input.setPlainText(result.text)
            self.statusBar().showMessage(f"PDF loaded: {len(result.pages)} page(s), {result.ocr_count} by OCR, "
                                         f"{result.skipped_count} skipped (see Log)", 8000)
            if result.all_skipped:
                lines = ["No text was found in this PDF."] + [
                    f"Page {pg.number}: {pg.reason}" for pg in result.pages]
                QtWidgets.QMessageBox.warning(self, "Load PDF", "\n".join(lines))

        def _on_pdf_error(self, msg: str):
            if self._closing:
                return
            self._pdf_finished()
            self.statusBar().clearMessage()
            QtWidgets.QMessageBox.warning(self, "Load PDF", msg)

        def clear_review(self):
            """Drop the Step 2 review: staged findings, table rows and highlights. Keeps the session map."""
            self.findings, self.analyzed_text = [], None
            self.input.setExtraSelections([])
            set_note(self.lbl_stale, "", "stale")
            self.populate_table()
            self.lbl_counts.setText("No analysis yet.")
            self._update_send_button()

        def clear_input_and_review(self):
            """Clear Step 1 and Step 2. If the session still holds values, offer to reset it too: those
            values are flagged again in every new analysis, whatever the min score."""
            n_vals, n_rules = len(self.vault), len(self.manual_rules)
            if n_vals or n_rules:
                SB = QtWidgets.QMessageBox.StandardButton
                mb = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Icon.Question, "Clear",
                                           f"The session map holds {n_vals} value(s) and {n_rules} temporary "
                                           f"rule(s). They are flagged again in every new analysis, whatever "
                                           f"the min score.\n\nReset the session too? Tokens in earlier AI "
                                           f"responses can then no longer be restored.",
                                           SB.Yes | SB.No | SB.Cancel, self)
                mb.button(SB.Yes).setText("Reset session too")
                mb.button(SB.No).setText("Keep session map")
                mb.setDefaultButton(SB.No)
                choice = mb.exec()
                if choice == SB.Cancel:
                    return
                if choice == SB.Yes:
                    self.reset_session(confirm=False)
                    return
            self.clear_review()
            self.input.clear()

        def _on_input_changed(self):
            text = self.input.toPlainText()
            self.lbl_input_stats.setText(f"{len(text):,} chars · {text.count(chr(10)) + (1 if text else 0):,} lines")
            if self.analyzed_text is not None and text != self.analyzed_text:
                set_note(self.lbl_stale, "Input changed since analysis — re-analyze before generating", "stale")
                self.input.setExtraSelections([])
            elif self.analyzed_text is not None:
                set_note(self.lbl_stale, "", "stale")
                self._highlight()
            self._update_send_button()

        def _update_send_button(self):
            """On only when the input is exactly the text that was analyzed and reviewed."""
            ready = self.analyzed_text is not None and self.input.toPlainText() == self.analyzed_text
            self.btn_send.setEnabled(ready)
            self.btn_save_review.setEnabled(ready and bool(self.findings))

        def save_review(self):
            if not self.findings or self.analyzed_text is None:
                return
            if QtWidgets.QMessageBox.warning(
                    self, "Save Review",
                    "The review file contains the ORIGINAL text and all sensitive values in plain form.\n"
                    "Store it only in a protected location and delete it when you are done.\n\nContinue?",
                    QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
            ) != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Save Review", f"pii_review_{_dt.datetime.now():%Y%m%d_%H%M}.json", "JSON (*.json)")
            if not path:
                return
            try:
                write_review_file(Path(path), review_to_dict(self.analyzed_text, self.findings, self.vault,
                                                             self.thr.value()))
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Save Review", str(exc))
                return
            self.statusBar().showMessage(f"Saved the review ({len(self.findings):,} findings) to "
                                         f"{Path(path).name}", 6000)

        def load_review(self):
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load Review", "", "JSON (*.json)")
            if not path:
                return
            try:
                text, findings, session, threshold = review_from_dict(json.loads(Path(path).read_text("utf-8")))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                QtWidgets.QMessageBox.warning(self, "Load Review", f"Cannot load this review file: {exc}")
                return
            try:   # check every token (session map and findings) before anything changes
                for e in session.get("entries", []):
                    if e.get("active", True):
                        self.vault.check(e["value"], e["token"])
                for f in findings:
                    if f.enabled and f.token:
                        self.vault.check(f.text, f.token)
            except (TokenCollision, KeyError, TypeError) as exc:
                QtWidgets.QMessageBox.warning(
                    self, "Load Review", f"Cannot load this review into the current session: {exc}.\n"
                    "Click Reset Session first, then load the review again.")
                return
            if (self.findings or self.input.toPlainText().strip()) and QtWidgets.QMessageBox.question(
                    self, "Load Review", "Replace the current input and review?") \
                    != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            self.vault.import_(session)
            self.clear_review()
            self.input.setPlainText(text)
            self.thr.setValue(threshold)
            self.findings = findings
            self.analyzed_text = text
            set_note(self.lbl_stale, "", "stale")
            if len(findings) > 5000:
                self._on_analyze_progress(f"Showing {len(findings):,} findings...")
                QtWidgets.QApplication.processEvents()
            self.populate_table()
            self._highlight()
            self._update_send_button()
            self.refresh_map()
            self.statusBar().showMessage(f"Loaded the review: {len(findings):,} findings, no new analysis", 6000)

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
                self.statusBar().clearMessage()
                if len(findings) > 5000:   # the table and highlights take some seconds for a large text
                    self._on_analyze_progress(f"Showing {len(findings):,} findings...")
                    QtWidgets.QApplication.processEvents()
                self.findings = findings
                self.analyzed_text = text
                set_note(self.lbl_stale, "", "stale")
                self._update_send_button()
                self.populate_table()
                self._highlight()
                log.info("analysis: %d detections, %d unique values", len(findings),
                         len({self.vault.key(f.text) for f in findings}))
                if self.engine.last_ner_skipped:
                    self.statusBar().showMessage("Input looks like log lines - spaCy NER findings skipped", 8000)
            self._run(self.engine.analyze, done, text, list(self.manual_rules), self.vault, thr,
                      progress=self._on_analyze_progress)

        def _on_analyze_progress(self, msg: str):
            """Progress of a long analysis: in the count label (where "Analyzing..." shows) and
            in the status bar."""
            self.lbl_counts.setText(msg)
            self.statusBar().showMessage(msg)

        def _table_rows(self) -> List[List[int]]:
            """Finding indices for each table row. Grouped: one row per value (the session-map key,
            so "SRV-DC01" and "srv-dc01" share a row), in order of the first copy."""
            if not self.chk_group.isChecked():
                return [[i] for i in range(len(self.findings))]
            groups: Dict[str, List[int]] = {}
            for i, f in enumerate(self.findings):
                groups.setdefault(self.vault.key(f.text), []).append(i)
            return sorted(groups.values(), key=lambda idxs: min(self.findings[i].start for i in idxs))

        def _on_group_toggled(self, on: bool):
            self.config["behavior"]["group_values"] = bool(on)
            self.config.save()
            self._jump = (None, 0)
            self.populate_table()

        def populate_table(self):
            self._updating = True
            self.table.setSortingEnabled(False)
            rows = self._table_rows()
            grouped = self.chk_group.isChecked()
            self.table.horizontalHeaderItem(C_END).setText("Count" if grouped else "End")
            self.table.setRowCount(len(rows))
            ents = sorted({f.entity for f in self.findings})
            color = {e: QtGui.QColor(ENTITY_COLORS[i % len(ENTITY_COLORS)]) for i, e in enumerate(ents)}
            for row, idxs in enumerate(rows):
                idxs = sorted(idxs, key=lambda i: self.findings[i].start)
                f = self.findings[idxs[0]]
                group = [self.findings[i] for i in idxs]
                n_on = sum(1 for x in group if x.enabled)
                state = (Qt.CheckState.Checked if n_on == len(group) else
                         Qt.CheckState.Unchecked if n_on == 0 else Qt.CheckState.PartiallyChecked)
                en = QtWidgets.QTableWidgetItem()
                en.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                en.setCheckState(state)
                en.setData(Qt.ItemDataRole.UserRole, idxs[0])
                en.setData(Qt.ItemDataRole.UserRole + 1, idxs)
                txt = QtWidgets.QTableWidgetItem(f.text.replace("\n", "↵"))
                txt.setFlags(txt.flags() & ~Qt.ItemFlag.ItemIsEditable)
                # the context tooltip is built on hover (eventFilter): building it for 100,000
                # rows added seconds to the table fill
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
                for val in (f.start, len(group) if grouped else f.end):
                    it = QtWidgets.QTableWidgetItem()
                    it.setData(Qt.ItemDataRole.DisplayRole, val)
                    items.append(it)
                sc = QtWidgets.QTableWidgetItem()
                sc.setData(Qt.ItemDataRole.DisplayRole, round(max(x.score for x in group), 2))
                sources = sorted({SOURCE_LABEL.get(x.source, x.source) for x in group})
                src = QtWidgets.QTableWidgetItem(sources[0] if len(sources) == 1 else "Mixed")
                src.setToolTip(", ".join(sources) if len(sources) > 1 else f.recognizer)
                items += [sc, src]
                for c in (C_START, C_END, C_SCORE, C_SRC):
                    items[c].setFlags(items[c].flags() & ~Qt.ItemFlag.ItemIsEditable)
                if n_on == 0:
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
            """Index of the row's first finding (all findings of a grouped row share the value)."""
            it = self.table.item(row, C_EN)
            return None if it is None else it.data(Qt.ItemDataRole.UserRole)

        def _row_indices(self, row: int) -> List[int]:
            """Indices of every finding in the row: one, or all copies of a grouped value."""
            it = self.table.item(row, C_EN)
            if it is None:
                return []
            idxs = it.data(Qt.ItemDataRole.UserRole + 1)
            return list(idxs) if idxs else [it.data(Qt.ItemDataRole.UserRole)]

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
                    for i in self._row_indices(row):
                        self.findings[i].enabled = on
            self._refresh_after_edit()

        def _set_enabled_selected(self, on: bool):
            """Enable or disable every finding in the selected rows (all copies of a grouped
            value). The same rows stay selected after the table refresh."""
            idxs = self._selected_indices()
            if not idxs:
                self.statusBar().showMessage("Select rows first (Ctrl+click or Shift+click)", 4000)
                return
            for i in idxs:
                self.findings[i].enabled = on
            firsts = {self._row_index(r) for r in {x.row() for x in self.table.selectedIndexes()}}
            self._refresh_after_edit()
            self._reselect(firsts)
            self.statusBar().showMessage(f"{'Enabled' if on else 'Disabled'} {len(idxs):,} finding(s)", 4000)

        def _toggle_selected(self):
            """Space: all selected findings on -> off; otherwise -> on."""
            idxs = self._selected_indices()
            if idxs:
                self._set_enabled_selected(not all(self.findings[i].enabled for i in idxs))

        def _reselect(self, first_indices):
            flags = QtCore.QItemSelectionModel.SelectionFlag
            sm = self.table.selectionModel()
            sm.blockSignals(True)          # no jump in the text for each reselected row
            try:
                for r in range(self.table.rowCount()):
                    if self._row_index(r) in first_indices:
                        sm.select(self.table.model().index(r, 0), flags.Select | flags.Rows)
            finally:
                sm.blockSignals(False)
            self.table.viewport().update()

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
                # A partly checked group goes to checked: one click turns every copy on.
                on = item.checkState() != Qt.CheckState.Unchecked
                for i in self._row_indices(item.row()):
                    self.findings[i].enabled = on
                self._updating = True
                if item.checkState() == Qt.CheckState.PartiallyChecked:
                    item.setCheckState(Qt.CheckState.Checked)
                color = QtGui.QColor("#9ca3af") if not on else self.palette().color(QtGui.QPalette.ColorRole.Text)
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
            return [i for r in rows for i in self._row_indices(r)]

        def _on_row_selected(self):
            rows = sorted({i.row() for i in self.table.selectedIndexes()})
            if len(rows) != 1:
                return
            idxs = self._row_indices(rows[0])
            if idxs:
                self._jump = (idxs[0], 0)
                self._show_finding(idxs[0])

        def _on_row_clicked(self, row: int, _col: int):
            """A click on the selected row of a grouped value shows its next copy in the text."""
            idxs = self._row_indices(row)
            if len(idxs) < 2:
                return
            first, n = self._jump
            if first != idxs[0]:
                self._jump = (idxs[0], 0)      # the selection change already showed copy 1
                return
            n = (n + 1) % len(idxs)
            self._jump = (first, n)
            self._show_finding(idxs[n])

        def _show_finding(self, idx: int):
            if self.analyzed_text is None or self.input.toPlainText() != self.analyzed_text:
                return
            f = self.findings[idx]
            cur = self.input.textCursor()
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.start))
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.end), QtGui.QTextCursor.MoveMode.KeepAnchor)
            self.input.setTextCursor(cur)
            self.input.ensureCursorVisible()

        def eventFilter(self, obj, event):
            """Show the context tooltip of an Original Text cell when the mouse rests on it."""
            if (event.type() == QtCore.QEvent.Type.ToolTip and hasattr(self, "table")
                    and obj is self.table.viewport()):
                item = self.table.itemAt(event.pos())
                if item is not None and item.column() == C_TEXT:
                    idxs = self._row_indices(item.row())
                    if idxs:
                        QtWidgets.QToolTip.showText(event.globalPos(), self._context_tooltip(idxs), obj)
                        return True
            return super().eventFilter(obj, event)

        def _context_tooltip(self, idxs: List[int]) -> str:
            """Line number and context of the first copies of a row, for its tooltip."""
            if self.analyzed_text is None:
                return self.findings[idxs[0]].text
            lines = []
            for i in idxs[:3]:
                f = self.findings[i]
                line, snippet = line_and_context(self.analyzed_text, f.start, f.end)
                lines.append(f"Line {line}: {snippet}")
            if len(idxs) > 3:
                lines.append(f"… and {len(idxs) - 3:,} more")
            return "\n".join(lines)

        def _show_in_text_label(self, idx: int) -> str:
            f = self.findings[idx]
            return f"Show in text (line {line_and_context(self.analyzed_text or '', f.start, f.end)[0]})"

        def _on_cell_double_clicked(self, row: int, col: int):
            """Start and Count/End cells cannot be edited, so a double-click there shows the
            finding in the text."""
            if col in (C_START, C_END):
                idxs = self._row_indices(row)
                if idxs:
                    self._show_in_text(idxs[0])

        def _show_in_text(self, idx: int):
            """Put the finding in the middle of the input box, mark it strongly for 2 seconds and
            move the keyboard focus there."""
            if self.analyzed_text is None or self.input.toPlainText() != self.analyzed_text:
                self.statusBar().showMessage("The input changed after the analysis. Re-analyze to show "
                                             "findings in the text.", 5000)
                return
            f = self.findings[idx]
            cur = self.input.textCursor()
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.start))
            cur.setPosition(py_to_qt_index(self.analyzed_text, f.end), QtGui.QTextCursor.MoveMode.KeepAnchor)
            self.input.setTextCursor(cur)
            self.input.centerCursor()
            mark = QtWidgets.QTextEdit.ExtraSelection()
            mark.cursor = QtGui.QTextCursor(cur)
            fmt = QtGui.QTextCharFormat()
            fmt.setBackground(QtGui.QColor("#f59e0b"))
            fmt.setForeground(QtGui.QColor("#000"))
            fmt.setFontWeight(QtGui.QFont.Weight.Bold)
            mark.format = fmt
            self.input.setExtraSelections(self.input.extraSelections() + [mark])
            QtCore.QTimer.singleShot(2000, self._highlight)
            self.input.setFocus()
            self.statusBar().showMessage(self._show_in_text_label(idx).replace("Show in text", "Shown in the text"),
                                         4000)

        def _table_menu(self, pos):
            idxs = self._selected_indices()
            if not idxs:
                return
            m = QtWidgets.QMenu(self)
            rows = sorted({i.row() for i in self.table.selectedIndexes()})
            a_show = None
            if len(rows) == 1:
                first, n = self._jump
                row_idxs = self._row_indices(rows[0])
                target = row_idxs[n] if first == row_idxs[0] and n < len(row_idxs) else row_idxs[0]
                a_show = m.addAction(self._show_in_text_label(target))
                m.addSeparator()
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
            if act is a_show:
                self._show_in_text(target)
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
                try:
                    for f in sel:
                        mr = ManualRule("exact", f.text, f.entity, True)
                        append_rule_to_file(self.engine.rules_root / "local" / SAVED_RULES_FILE_NAME,
                                            mr.to_rule_yaml())
                except RuleError as exc:
                    self.reload_rules()     # load any rules saved before the failure
                    QtWidgets.QMessageBox.warning(self, "Save as rule", str(exc))
                    return
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
                    append_rule_to_file(self.engine.rules_root / "local" / SAVED_RULES_FILE_NAME, r.to_rule_yaml())
            except Exception as exc:
                QtWidgets.QMessageBox.warning(self, "Save rules", str(exc))
                return
            self.reload_rules()
            QtWidgets.QMessageBox.information(self, "Save rules", f"Saved {len(rules)} rule(s) to "
                                              f"rules/local/{MANUAL_RULES_FILE.name}.\nConsider adding them to the "
                                              "shared GitHub rules repo so the whole team gets them.")

        # ================= Step 3
        def generate(self):
            if not self.btn_generate.isEnabled():     # a background run is going (Ctrl+G)
                return
            if self.analyzed_text is None:
                QtWidgets.QMessageBox.information(self, APP_NAME, "Analyze some text first (Step 1).")
                self.tabs.setCurrentIndex(0)
                return
            if self.input.toPlainText() != self.analyzed_text:
                QtWidgets.QMessageBox.warning(self, APP_NAME, "The input changed after analysis. Re-analyze first "
                                              "so that every span is reviewed.")
                self.tabs.setCurrentIndex(0)
                return
            findings = list(self.findings)
            if len(findings) <= SANITIZE_BACKGROUND_FINDINGS and len(self.analyzed_text) <= SANITIZE_BACKGROUND_CHARS:
                try:
                    result = sanitize_with_leak_check(self.analyzed_text, findings, self.vault)
                except TokenCollision as exc:
                    QtWidgets.QMessageBox.warning(self, "Token conflict", str(exc))
                    return
                self._show_sanitized(result)
                return
            # A large review: the replacement and the leak check take seconds, so they run in the
            # background. Send, Generate and Restore stay off, so nothing else uses the session map.
            self._set_generating(True)
            self.statusBar().showMessage(f"Sanitizing {len(findings):,} findings...")
            self._run(sanitize_with_leak_check, self._on_sanitized, self.analyzed_text, findings, self.vault,
                      error=self._on_sanitize_error)

        def _set_generating(self, on: bool):
            self.btn_generate.setEnabled(not on)
            self.btn_restore.setEnabled(not on)
            self.setCursor(Qt.CursorShape.BusyCursor if on else Qt.CursorShape.ArrowCursor)
            if on:
                self.btn_send.setEnabled(False)
            else:
                self._update_send_button()

        def _on_sanitized(self, result):
            if self._closing:
                return
            self._set_generating(False)
            self.statusBar().clearMessage()
            self._show_sanitized(result)

        def _on_sanitize_error(self, msg: str):
            if self._closing:
                return
            self._set_generating(False)
            self.statusBar().clearMessage()
            QtWidgets.QMessageBox.warning(self, "Token conflict" if "token" in msg.lower() else "Sanitize", msg)

        def _show_sanitized(self, result):
            out, used, leaks = result
            self.output.setPlainText(out)
            self.last_sanitized = out
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

        def _map_menu(self, pos):
            """Right-click on the session map: copy the raw value or the token of the selected rows."""
            clicked = self.map_table.itemAt(pos)
            if clicked is None:
                return
            if not self.map_table.item(clicked.row(), 0).isSelected():
                self.map_table.selectRow(clicked.row())
            rows = sorted({i.row() for i in self.map_table.selectedItems()})
            tokens = [self.map_table.item(r, 0).text() for r in rows]
            m = QtWidgets.QMenu(self)
            a_val = m.addAction("Copy original value" if len(tokens) == 1 else f"Copy {len(tokens)} original values")
            a_tok = m.addAction("Copy token" if len(tokens) == 1 else f"Copy {len(tokens)} tokens")
            act = m.exec(self.map_table.viewport().mapToGlobal(pos))
            if act is a_val:
                # the raw value from the vault, even while the table shows masked values
                self.copy_text("\n".join(self.vault.token_to_value.get(t, "") for t in tokens))
            elif act is a_tok:
                self.copy_text("\n".join(tokens))

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

        def reset_session(self, confirm: bool = True):
            if confirm and (len(self.vault) or self.findings) and QtWidgets.QMessageBox.question(
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
            self._update_send_button()
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
            self._closing = True
            self._pdf_cancel = True
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
    ap.add_argument("--require-hebrew", action="store_true",
                    help="with --self-test: fail unless the Hebrew NER model is loaded")
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
        ok, lines = self_test(require_hebrew=args.require_hebrew)
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
