# LLM-Powered Threat Hunter

Automated pipeline to monitor GitHub repositories for suspicious commits, score the risk with an LLM, and persist structured findings for later review.

## What it does

- Pulls recent commits from a target GitHub repository
- Analyzes changed file patches with an LLM
- Returns structured detection results
- Stores commit metadata and findings in SQLite
- Saves generated YARA rules for medium- and high-risk findings

## Structured finding format

Each file-level finding is normalized into:

- `risk`: `high`, `medium`, or `low`
- `confidence`: integer from `0` to `100`
- `summary`: short explanation
- `reasons`: list of detection reasons
- `indicators`: list of suspicious APIs, behaviors, or IOCs
- `yara_rule`: full YARA rule or `null`

## Project files

- [watchman.py](/Users/abhijithshaji/Documents/GitSecurity/watchman.py): main scanner, detection parsing, and SQLite persistence
- [testThreat.py](/Users/abhijithshaji/Documents/GitSecurity/testThreat.py): synthetic malicious patch for local testing
- [watchlist.txt.example](/Users/abhijithshaji/Documents/GitSecurity/watchlist.txt.example): starter watchlist for multi-repo scans
- [suppressions.json.example](/Users/abhijithshaji/Documents/GitSecurity/suppressions.json.example): starter suppression / allowlist config
- [datasets/eval_dataset.json](/Users/abhijithshaji/Documents/GitSecurity/datasets/eval_dataset.json): labeled evaluation dataset example
- `security_findings.db`: generated SQLite database
- `signatures/`: generated YARA signatures

## Setup

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For local development and test tooling:

```bash
pip install -r requirements-dev.txt
```

Create a `.env` file from [.env.example](/Users/abhijithshaji/Documents/GitSecurity/.env.example):

```env
GITHUB_TOKEN=your_github_token
OPENAI_API_KEY=your_openai_api_key
TARGET_REPO=psf/requests
OPENAI_MODEL=gpt-4o
WATCHMAN_DB_PATH=security_findings.db
WATCHLIST_PATH=watchlist.txt
SUPPRESSIONS_PATH=suppressions.json
EVAL_DATASET_PATH=datasets/eval_dataset.json
ALERTS_LOG_PATH=alerts/alerts.jsonl
ALERT_MIN_RISK=high
ALERT_MIN_CONFIDENCE=80
```

## Usage

Run the local synthetic test flow:

```bash
python3 watchman.py test
```

Scan a single repository:

```bash
python3 watchman.py scan --repo psf/requests --limit 3
```

Copy [watchlist.txt.example](/Users/abhijithshaji/Documents/GitSecurity/watchlist.txt.example) to `watchlist.txt`, then scan all watched repos:

```bash
python3 watchman.py scan-watchlist --limit 3
```

Review saved findings from the local database:

```bash
python3 watchman.py list-findings --risk high
python3 watchman.py show-finding 1
python3 watchman.py triage-finding 1 --disposition true_positive --note "Confirmed reverse shell behavior"
python3 watchman.py list-findings --disposition new
```

Run a labeled evaluation dataset to measure quality:

```bash
python3 watchman.py evaluate --dataset datasets/eval_dataset.json
```

Noise reduction and alert delivery:

- suppression rules are loaded from `suppressions.json` and matched by repo, file pattern, and rule hit
- matching suppressions downgrade known-safe findings to low risk and prevent alert delivery
- high-confidence unsuppressed findings are written to `alerts/alerts.jsonl`
- if `ALERT_WEBHOOK_URL` is set, the same alert payload is also posted to that webhook

Historical context is automatically applied during analysis when prior findings exist for the same repo/file and matching rule hits:

- prior `false_positive` or `ignored` findings reduce risk and confidence
- prior `true_positive` findings reinforce confidence
- `show-finding` displays the stored historical context used during scoring

## CI/CD practices

The repo now includes a basic CI baseline:

- GitHub Actions workflow at [.github/workflows/ci.yml](/Users/abhijithshaji/Documents/GitSecurity/.github/workflows/ci.yml)
- `ruff` linting
- Python syntax validation
- `pytest` unit tests for parsing and SQLite persistence
- Dependabot config at [.github/dependabot.yml](/Users/abhijithshaji/Documents/GitSecurity/.github/dependabot.yml)

Run the checks locally with:

```bash
ruff check .
pytest
python -m compileall watchman.py testThreat.py tests
```

## Persistence

Findings are stored in SQLite across two tables:

- `commits`: repo, commit SHA, author, message, URL, analysis timestamp
- `findings`: file name, risk, confidence, summary, reasons, indicators, rule hits, YARA, raw model response, disposition, analyst note, triage timestamp
- `findings` also store historical context used to adjust the final score
- `findings` also store suppression context used to explain why an alert was reduced

This makes it much easier to build a dashboard, alerting workflow, or evaluation pipeline on top of the scanner.

## v0.2 additions

This version adds a few product-oriented building blocks:

- multi-repo watchlist support
- deterministic prechecks before the LLM runs
- CLI commands for scanning and reviewing findings
- persisted rule hits so local heuristics are auditable later
- analyst triage workflow with dispositions and notes
- historical repo/file context to reduce false positives and reinforce known-bad patterns
- suppression rules and allowlist controls for recurring known-safe patterns
- evaluation datasets and CLI reporting to measure true/false positives and negatives
- alert delivery to a local alert inbox plus optional webhook
