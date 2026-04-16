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
```

## Usage

Run the local synthetic test flow:

```bash
python3 watchman.py
```

Run repository monitoring from Python:

```python
from watchman import build_hunter

hunter = build_hunter()
hunter.monitor_repository("psf/requests", limit=3)
```

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
- `findings`: file name, risk, confidence, summary, reasons, indicators, YARA, raw model response

This makes it much easier to build a dashboard, alerting workflow, or evaluation pipeline on top of the scanner.
