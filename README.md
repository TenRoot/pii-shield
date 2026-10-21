# PII Shield

PII Shield removes personal and sensitive data from text before you send the text to an LLM.
It replaces each sensitive value with a token, for example `<HOSTNAME_1>`. When the LLM
replies, PII Shield puts the original values back.

All processing is local. PII Shield uses Microsoft Presidio and a local spaCy model. The only
network traffic is the GitHub rules sync, and you start that sync manually. PII Shield never
sends prompt text.

## Features

- You review every detection in an editable table before PII Shield masks the text.
- The same value always gets the same token for the full session. `SRV-DC01` and `srv-dc01`
  share one token by default.
- You add custom recognizers as YAML or JSON rule files. Click **Reload Local Rules** to load
  changes without a restart.
- A team can share rules through a private GitHub repo. PII Shield checks the integrity of
  each downloaded file and validates all files before it applies them.

## Setup

CI uses Python 3.12. The local test run uses Python 3.13.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

The spaCy model gives name, location and organization detection. PII Shield never downloads
a model by itself. If `en_core_web_lg` is not installed, PII Shield uses the first installed
model from this list: `en_core_web_trf`, `en_core_web_md`, `en_core_web_sm`. If no model is
installed, PII Shield runs in regex-only mode with no name detection.

`keyring` is optional. With `keyring`, PII Shield stores the GitHub token in the OS
credential store. Without `keyring`, PII Shield stores the token in plain text in
`config.json`.

## Running the app

```bash
python pii_sanitizer.py                          # start the GUI
python pii_sanitizer.py --validate-rules DIR     # validate a rules folder and exit
python pii_sanitizer.py --version
python pii_sanitizer.py --debug                  # verbose logging
```

The GUI has five tabs:

1. **Input & Review** — paste or load text, then click **Analyze PII & Sensitive Data**.
   Enable or disable each finding. Add manual rules for values the engine did not find.
2. **Sanitize** — click **Generate Sanitized Prompt**, then copy the clean text into your LLM.
3. **Restore** — paste the LLM reply and click **Restore Original Values**.
4. **Session Map** — see the token-to-value map. Export it or import it to continue a
   session later.
5. **Log** — see engine and sync messages. The log never contains detected values or
   prompt text.

### Data folder

PII Shield keeps its data next to `pii_sanitizer.py`. To use a different folder, set
`PII_SHIELD_HOME`. The data folder contains:

| Path | Contents |
|---|---|
| `config.json` | Settings. Open **Settings** in the GUI to change them. |
| `rules/local/` | Your local rules. GitHub sync never changes this folder. |
| `rules/remote/` | Rules from GitHub. Each sync replaces this folder. |
| `backups/` | Backups of the script from app updates. |

Git ignores `config.json`, `backups/` and `rules/remote/`.

## Rules

### Rules layout

PII Shield loads rules in three layers:

1. **Bundled rules.** The script contains a copy of `github-repo-template/rules/`, so a fresh
   install detects hostnames, accounts, secrets and other values with an empty `rules/` folder.
2. **Remote rules** in `rules/remote/`.
3. **Local rules:** every other `.yaml`, `.yml` and `.json` file under `rules/`, including
   files in subfolders.

If two rules have the same `name`, the rule from the later layer is used. A local rule
overrides a remote rule, and both override a bundled rule.

After you change a file in `github-repo-template/rules/`, run `python tools/bundle_rules.py`
to update the bundled copy. A test fails if the two copies differ.

PII Shield writes these files in `rules/local/` from the GUI:

- `promoted_rules.yaml` — manual rules that you save with **Save to Local Rules**.
- `allow_list.yaml` — values that you add to the allow list.

`rules/local/local_rules.yaml` is an example local rule. It is disabled.

### Rule format

```yaml
version: 1
allow_list:            # values that PII Shield never masks (case-insensitive)
  - localhost
recognizers:
  - name: FileServers          # unique name
    entity: HOSTNAME           # UPPER_SNAKE_CASE; gives tokens like <HOSTNAME_1>
    score: 0.9
    patterns:                  # Python regular expressions
      - {name: fs, regex: '\bfs\d{2}\.contoso\.local\b'}
  - name: Customers
    entity: CUSTOMER
    wordlist: wordlists/customers.txt   # one value per line, relative to this file
```

A rule needs at least one of `patterns`, `deny_list` or `wordlist`. Other fields are
`context`, `case_sensitive`, `validator` (`luhn`, `israeli_id`, `ipv4`, `private_ipv4`) and
`enabled`. The header of `github-repo-template/rules/rules.yaml` gives the full schema.

If a rule file has an error, PII Shield skips only that file. The other files still load.

### Shared rules on GitHub

`github-repo-template/` is a starter for the shared rules repo:

| Path | Purpose |
|---|---|
| `rules/` | Rule files and wordlists. The app syncs this folder into `rules/remote/`. |
| `app/version.json` | Latest app version and the SHA-256 of the script, for update checks. |
| `Publish-AppVersion.ps1` | Writes `app/version.json` from `app/pii_sanitizer.py`. |
| `.github/workflows/validate-rules.yml` | CI. Validates the rules and checks the hash in `version.json`. |

To connect the app, click **Update Rules** on the toolbar. Enter the contents API URL of the
rules folder, for example `https://api.github.com/repos/org/repo/contents/rules`, the branch
and a token. Then click **Check & Pull Updates**.

The sync downloads only `.yaml`, `.yml`, `.json`, `.txt`, `.lst` and `.csv` files. It checks
the git blob SHA of each file and validates all rules in a staging folder. If any check
fails, the sync changes nothing.

Validate rules before you push them:

```bash
python pii_sanitizer.py --validate-rules github-repo-template/rules
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The suite has 28 tests:

- `tests/test_core.py` — detection, tokens, restore, rule reload and the offline guard. These
  tests use the rules in `github-repo-template/rules/`.
- `tests/test_sync.py` — GitHub sync against a local mock HTTPS server. These tests need the
  `openssl` command.

Run the tests with the Python from your virtual environment, because the tests import
Presidio and spaCy.
