# LLM-Powered Threat Hunter

Automated pipeline to monitor GitHub repositories for suspicious commits, score the risk with an LLM, and persist structured findings for later review.

## What it does

- Pulls recent commits from a target GitHub repository
- Analyzes changed file patches with an LLM
- Returns structured detection results
- Stores commit metadata and findings in SQLite or PostgreSQL
- Saves generated YARA rules for medium- and high-risk findings
- Scopes findings to a team and analyst context so the app is ready for multi-user workflows

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
- [storage.py](/Users/abhijithshaji/Documents/GitSecurity/storage.py): abstract store layer with SQLite and PostgreSQL backends plus team/user ownership
- [testThreat.py](/Users/abhijithshaji/Documents/GitSecurity/testThreat.py): synthetic malicious patch for local testing
- [watchlist.txt.example](/Users/abhijithshaji/Documents/GitSecurity/watchlist.txt.example): starter watchlist for multi-repo scans
- [suppressions.json.example](/Users/abhijithshaji/Documents/GitSecurity/suppressions.json.example): starter suppression / allowlist config
- [datasets/eval_dataset.json](/Users/abhijithshaji/Documents/GitSecurity/datasets/eval_dataset.json): labeled evaluation dataset example
- [app.py](/Users/abhijithshaji/Documents/GitSecurity/app.py): FastAPI analyst inbox and service API
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
WATCHMAN_DATABASE_URL=
WATCHLIST_PATH=watchlist.txt
SUPPRESSIONS_PATH=suppressions.json
EVAL_DATASET_PATH=datasets/eval_dataset.json
ALERTS_LOG_PATH=alerts/alerts.jsonl
ALERT_MIN_RISK=high
ALERT_MIN_CONFIDENCE=80
WATCHMAN_DEFAULT_TEAM_SLUG=personal-lab
WATCHMAN_DEFAULT_TEAM_NAME=Personal Lab
WATCHMAN_DEFAULT_USER_EMAIL=analyst@example.com
WATCHMAN_DEFAULT_USER_NAME=Local Analyst
WATCHMAN_SESSION_SECRET=change-me-in-production
```

Use `WATCHMAN_DB_PATH` for local SQLite or set `WATCHMAN_DATABASE_URL` for PostgreSQL:

```env
WATCHMAN_DATABASE_URL=postgresql://watchman:secret@localhost:5432/threat_hunter
```

## Usage

Run the local synthetic test flow:

```bash
python3 watchman.py --team-slug personal-lab --user-email analyst@example.com test
```

Run the analyst inbox and service API:

```bash
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000` to review findings in the browser.

The web app now uses signed session cookies. Start by creating a team workspace from `/login`, then sign in and onboard watched repos from the dashboard.

Run the background scan worker for the current team:

```bash
python3 watchman.py --team-slug blue-team --team-name "Blue Team" run-worker
```

Run background scans for every team with active watched repos:

```bash
python3 watchman.py run-worker --all-teams
```

Scan a single repository:

```bash
python3 watchman.py --team-slug blue-team --team-name "Blue Team" --user-email analyst@blue.example scan --repo psf/requests --limit 3
```

Copy [watchlist.txt.example](/Users/abhijithshaji/Documents/GitSecurity/watchlist.txt.example) to `watchlist.txt`, then scan all watched repos:

```bash
python3 watchman.py scan-watchlist --limit 3
```

Review saved findings from the local database:

```bash
python3 watchman.py --team-slug blue-team list-findings --risk high
python3 watchman.py --team-slug blue-team show-finding 1
python3 watchman.py --team-slug blue-team --user-email analyst@blue.example triage-finding 1 --disposition true_positive --note "Confirmed reverse shell behavior"
python3 watchman.py --team-slug blue-team list-findings --disposition new
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
- alert delivery attempts are also persisted in the database with per-channel status and retry counts

## Service API

The repo now includes a product-facing FastAPI service:

- `GET /health`
- `GET /login`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /api/session`
- `GET /api/findings`
- `GET /api/findings/{id}`
- `POST /api/findings/{id}/triage`
- `GET /api/alerts`
- `GET /api/alert-deliveries`
- `GET /api/settings`
- `POST /api/settings`
- `GET /api/watchlist`
- `POST /api/watchlist`
- `POST /api/watchlist/{id}/deactivate`
- `POST /api/watchlist/{id}/scan-now`
- `GET /api/scan-runs`
- `POST /api/scans/run-cycle`
- `POST /api/demo/test-scan`

The app no longer trusts caller-provided identity headers. Team and user context come from a signed session cookie that is created during login or registration.

The browser dashboard at `/` provides:

- a findings inbox
- full finding detail
- triage updates
- alert inbox visibility
- alert delivery attempt visibility
- a one-click synthetic demo scan
- authenticated team and analyst context in the UI
- repo onboarding and watchlist management
- per-team alert thresholds and webhook settings
- team scan interval controls plus watchlist scheduling state
- recent scan run history
- manual scan-now and team scan-cycle actions
- backend visibility so you can tell whether the app is using SQLite or PostgreSQL

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

## Persistence And Ownership

Findings are stored behind an abstract store layer:

- `storage.py` selects SQLite or PostgreSQL at runtime
- `teams`, `users`, and `team_memberships` establish ownership
- `users` now store password hashes for local account login
- `repo_watchlists` persist team-owned repository onboarding state
- `team_settings` persist per-team alert thresholds, webhook routing, and scan limits
- `team_settings` also persist scan interval settings for scheduled execution
- `scan_runs` persist background/manual scan execution history plus lock expiry metadata
- `alert_deliveries` persist per-channel delivery attempts, failures, and retry counts
- `repo_watchlists` also track next scan time, last successful scan, and last scan error
- `commits` are scoped by `team_id + repo_name + commit_sha`
- `findings` store:
  - file name
  - risk
  - confidence
  - summary
  - reasons
  - indicators
  - rule hits
  - YARA
  - raw model response
  - disposition
  - analyst note
  - triage timestamp
  - triaging user identity
  - historical context
  - suppression context

This is the first step from a single-user demo toward a real multi-user product backend.

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
- FastAPI service and analyst inbox as the first product-facing surface
- abstract store layer with PostgreSQL support
- team and analyst ownership threaded through scans, findings, and triage
- local authentication plus signed sessions for the web app
- repo watchlist onboarding persisted in the database
- background scan worker orchestration with persisted scan runs
- per-team alert settings for risk/confidence thresholds, webhook routing, and scan intervals
- overlap protection so a repo cannot be scanned twice at the same time
- delivery reliability tracking so webhook failures are visible in the app
