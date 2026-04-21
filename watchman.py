import argparse
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from dotenv import load_dotenv
from github import Auth, Github
from openai import OpenAI


load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEFAULT_TARGET_REPO = os.getenv("TARGET_REPO", "psf/requests")
DATABASE_PATH = Path(os.getenv("WATCHMAN_DB_PATH", "security_findings.db"))
SIGNATURES_DIR = Path("signatures")
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
WATCHLIST_PATH = Path(os.getenv("WATCHLIST_PATH", "watchlist.txt"))
DEFAULT_SCAN_LIMIT = int(os.getenv("WATCHMAN_SCAN_LIMIT", "3"))
VALID_DISPOSITIONS = {"new", "true_positive", "false_positive", "ignored"}

RISK_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class DetectionResult:
    risk: str
    confidence: int
    summary: str
    reasons: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    yara_rule: Optional[str] = None
    raw_response: str = ""
    rule_hits: List[str] = field(default_factory=list)
    history_context: Dict[str, Any] = field(default_factory=dict)

    def normalized_risk(self) -> str:
        value = (self.risk or "").strip().lower()
        if value in {"high", "medium", "low"}:
            return value
        if value == "med":
            return "medium"
        return "unknown"

    def should_save_yara(self) -> bool:
        return self.normalized_risk() in {"high", "medium"} and bool(self.yara_rule)


@dataclass
class RuleSignal:
    rule_id: str
    risk: str
    confidence: int
    reason: str
    indicators: List[str] = field(default_factory=list)


class FindingStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS commits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT NOT NULL,
                    commit_sha TEXT NOT NULL UNIQUE,
                    author_name TEXT,
                    commit_message TEXT,
                    html_url TEXT,
                    analyzed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    commit_sha TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    indicators_json TEXT NOT NULL,
                    yara_rule TEXT,
                    raw_response TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(commit_sha) REFERENCES commits(commit_sha)
                );
                """
            )
            self._ensure_column(
                connection,
                table_name="findings",
                column_name="rule_hits_json",
                column_sql="TEXT NOT NULL DEFAULT '[]'",
            )
            self._ensure_column(
                connection,
                table_name="findings",
                column_name="disposition",
                column_sql="TEXT NOT NULL DEFAULT 'new'",
            )
            self._ensure_column(
                connection,
                table_name="findings",
                column_name="analyst_note",
                column_sql="TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                connection,
                table_name="findings",
                column_name="triaged_at",
                column_sql="TEXT",
            )
            self._ensure_column(
                connection,
                table_name="findings",
                column_name="history_context_json",
                column_sql="TEXT NOT NULL DEFAULT '{}'",
            )

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection,
        table_name: str,
        column_name: str,
        column_sql: str,
    ) -> None:
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in columns:
            try:
                connection.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}"
                )
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise

    def commit_exists(self, commit_sha: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM commits WHERE commit_sha = ?",
                (commit_sha,),
            ).fetchone()
        return row is not None

    def save_commit_metadata(
        self,
        repo_name: str,
        commit_sha: str,
        author_name: Optional[str],
        commit_message: Optional[str],
        html_url: Optional[str],
    ) -> None:
        analyzed_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO commits (
                    repo_name, commit_sha, author_name, commit_message, html_url, analyzed_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    repo_name,
                    commit_sha,
                    author_name,
                    commit_message,
                    html_url,
                    analyzed_at,
                ),
            )

    def save_finding(self, commit_sha: str, file_name: str, result: DetectionResult) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO findings (
                    commit_sha,
                    file_name,
                    risk,
                    confidence,
                    summary,
                    reasons_json,
                    indicators_json,
                    yara_rule,
                    raw_response,
                    created_at,
                    rule_hits_json,
                    disposition,
                    analyst_note,
                    triaged_at,
                    history_context_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    commit_sha,
                    file_name,
                    result.normalized_risk(),
                    result.confidence,
                    result.summary,
                    json.dumps(result.reasons),
                    json.dumps(result.indicators),
                    result.yara_rule,
                    result.raw_response,
                    created_at,
                    json.dumps(result.rule_hits),
                    "new",
                    "",
                    None,
                    json.dumps(result.history_context),
                ),
            )

    def list_findings(
        self,
        limit: int = 20,
        risk: Optional[str] = None,
        repo_name: Optional[str] = None,
        disposition: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        query = """
            SELECT
                findings.id,
                commits.repo_name,
                findings.commit_sha,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.created_at,
                findings.rule_hits_json,
                findings.disposition,
                findings.history_context_json
            FROM findings
            JOIN commits ON findings.commit_sha = commits.commit_sha
        """
        filters: List[str] = []
        params: List[Any] = []

        if risk:
            filters.append("findings.risk = ?")
            params.append(risk.lower())
        if repo_name:
            filters.append("commits.repo_name = ?")
            params.append(repo_name)
        if disposition:
            filters.append("findings.disposition = ?")
            params.append(disposition)

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY findings.created_at DESC, findings.id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as connection:
            return connection.execute(query, params).fetchall()

    def get_finding(self, finding_id: int) -> Optional[sqlite3.Row]:
        query = """
            SELECT
                findings.id,
                commits.repo_name,
                findings.commit_sha,
                commits.author_name,
                commits.commit_message,
                commits.html_url,
                findings.file_name,
                findings.risk,
                findings.confidence,
                findings.summary,
                findings.reasons_json,
                findings.indicators_json,
                findings.yara_rule,
                findings.rule_hits_json,
                findings.raw_response,
                findings.created_at,
                findings.disposition,
                findings.analyst_note,
                findings.triaged_at,
                findings.history_context_json
            FROM findings
            JOIN commits ON findings.commit_sha = commits.commit_sha
            WHERE findings.id = ?
        """
        with self._connect() as connection:
            return connection.execute(query, (finding_id,)).fetchone()

    def get_history_context(
        self,
        repo_name: str,
        file_name: str,
        rule_hits: List[str],
        exclude_commit_sha: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        query = """
            SELECT
                findings.id,
                findings.commit_sha,
                findings.rule_hits_json,
                findings.disposition
            FROM findings
            JOIN commits ON findings.commit_sha = commits.commit_sha
            WHERE commits.repo_name = ? AND findings.file_name = ?
            ORDER BY findings.created_at DESC, findings.id DESC
            LIMIT ?
        """
        with self._connect() as connection:
            rows = connection.execute(query, (repo_name, file_name, limit)).fetchall()

        if exclude_commit_sha:
            rows = [row for row in rows if row["commit_sha"] != exclude_commit_sha]

        context: Dict[str, Any] = {
            "same_file_finding_count": len(rows),
            "matching_rule_hit_count": 0,
            "matching_true_positive_count": 0,
            "matching_false_positive_count": 0,
            "matching_ignored_count": 0,
            "related_finding_ids": [],
            "adjustment": "none",
            "note": "",
        }
        if not rows or not rule_hits:
            return context

        current_rule_hits = set(rule_hits)
        matching_rows = []
        for row in rows:
            prior_rule_hits = set(json.loads(row["rule_hits_json"] or "[]"))
            if prior_rule_hits.intersection(current_rule_hits):
                matching_rows.append(row)

        context["matching_rule_hit_count"] = len(matching_rows)
        context["related_finding_ids"] = [row["id"] for row in matching_rows[:5]]
        context["matching_true_positive_count"] = sum(
            1 for row in matching_rows if row["disposition"] == "true_positive"
        )
        context["matching_false_positive_count"] = sum(
            1 for row in matching_rows if row["disposition"] == "false_positive"
        )
        context["matching_ignored_count"] = sum(
            1 for row in matching_rows if row["disposition"] == "ignored"
        )

        softening_count = (
            context["matching_false_positive_count"] + context["matching_ignored_count"]
        )
        if softening_count >= 1 and context["matching_true_positive_count"] == 0:
            context["adjustment"] = "reduced"
            context["note"] = (
                f"Historical context reduced risk because {softening_count} similar "
                "finding(s) in this repo/file were previously triaged as false positive or ignored."
            )
        elif context["matching_true_positive_count"] >= 1:
            context["adjustment"] = "reinforced"
            context["note"] = (
                f"Historical context reinforced confidence because "
                f"{context['matching_true_positive_count']} similar finding(s) in this repo/file "
                "were previously confirmed as true positive."
            )

        return context

    def update_finding_triage(
        self,
        finding_id: int,
        disposition: str,
        analyst_note: Optional[str] = None,
        clear_note: bool = False,
    ) -> bool:
        normalized = disposition.strip().lower()
        if normalized not in VALID_DISPOSITIONS:
            raise ValueError(f"Invalid disposition: {disposition}")

        with self._connect() as connection:
            current = connection.execute(
                "SELECT analyst_note FROM findings WHERE id = ?",
                (finding_id,),
            ).fetchone()
            if current is None:
                return False

            if clear_note:
                note_value = ""
            elif analyst_note is None:
                note_value = current["analyst_note"]
            else:
                note_value = analyst_note.strip()

            connection.execute(
                """
                UPDATE findings
                SET disposition = ?, analyst_note = ?, triaged_at = ?
                WHERE id = ?
                """,
                (
                    normalized,
                    note_value,
                    datetime.now(timezone.utc).isoformat(),
                    finding_id,
                ),
            )
        return True


class ThreatHunter:
    def __init__(
        self,
        github_token: Optional[str],
        openai_api_key: Optional[str],
        db_path: Path = DATABASE_PATH,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self.github = Github(auth=Auth.Token(github_token)) if github_token else None
        self.client = OpenAI(api_key=openai_api_key) if openai_api_key else None
        self.store = FindingStore(db_path)
        self.model = model
        SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)

    def monitor_repository(self, repo_name: str, limit: int = 3, skip_existing: bool = True) -> None:
        if not self.github:
            raise ValueError("Missing GITHUB_TOKEN. Required for repository scanning.")

        repo = self.github.get_repo(repo_name)
        commits = repo.get_commits()

        print(f"--- Monitoring {repo_name} ---")

        for index, commit in enumerate(commits):
            if index >= limit:
                break

            commit_sha = commit.sha
            if skip_existing and self.store.commit_exists(commit_sha):
                print(f"\n[-] Skipping {commit_sha[:7]} (already analyzed)")
                continue

            author_name = getattr(commit.commit.author, "name", "Unknown")
            commit_message = getattr(commit.commit, "message", "")
            print(f"\n[+] Analyzing Commit: {commit_sha[:7]}")
            print(f"    Author: {author_name}")

            self.store.save_commit_metadata(
                repo_name=repo_name,
                commit_sha=commit_sha,
                author_name=author_name,
                commit_message=commit_message,
                html_url=getattr(commit, "html_url", None),
            )

            for changed_file in commit.files:
                if not changed_file.patch:
                    continue

                print(f"    File changed: {changed_file.filename}")
                result = self.analyze_patch(
                    filename=changed_file.filename,
                    patch_data=changed_file.patch,
                    commit_sha=commit_sha,
                    repo_name=repo_name,
                )
                self.store.save_finding(commit_sha, changed_file.filename, result)
                self._print_result(result)

                if result.should_save_yara():
                    yara_path = self.save_yara_rule(result.yara_rule or "", commit_sha, changed_file.filename)
                    print(f"    YARA saved: {yara_path}")

    def analyze_patch(
        self,
        filename: str,
        patch_data: str,
        commit_sha: str = "test",
        repo_name: str = DEFAULT_TARGET_REPO,
    ) -> DetectionResult:
        print("    ... Auditing for threats ...")

        rule_result = self.run_prechecks(filename, patch_data)
        if not self.client:
            return self.apply_history_context(
                repo_name=repo_name,
                file_name=filename,
                commit_sha=commit_sha,
                result=rule_result,
            )

        user_prompt = f"""
Analyze this GitHub patch for malicious or suspicious activity.

Return valid JSON with exactly these keys:
- risk: one of ["high", "medium", "low"]
- confidence: integer from 0 to 100
- summary: short one-sentence explanation
- reasons: array of concise detection reasons
- indicators: array of suspicious APIs, IOCs, behaviors, or artifacts
- yara_rule: full YARA rule string if risk is high or medium, otherwise null

Deterministic rule signals already observed:
{json.dumps({
    "risk": rule_result.normalized_risk(),
    "confidence": rule_result.confidence,
    "rule_hits": rule_result.rule_hits,
    "reasons": rule_result.reasons,
    "indicators": rule_result.indicators,
})}

Only output JSON.

COMMIT_SHA: {commit_sha}
FILE: {filename}
PATCH:
{patch_data}
""".strip()

        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior malware analyst reviewing GitHub diffs. "
                        "Be conservative, explain your reasoning briefly, and only emit a YARA rule "
                        "when the patch contains meaningful malicious or strongly suspicious logic."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
        )

        raw_response = response.choices[0].message.content or "{}"
        payload = self._parse_detection_payload(raw_response)
        payload["raw_response"] = raw_response
        llm_result = DetectionResult(**payload)
        merged = self.merge_results(rule_result, llm_result)
        return self.apply_history_context(
            repo_name=repo_name,
            file_name=filename,
            commit_sha=commit_sha,
            result=merged,
        )

    def run_prechecks(self, filename: str, patch_data: str) -> DetectionResult:
        lower_patch = patch_data.lower()
        signals: List[RuleSignal] = []

        if all(token in lower_patch for token in ("socket", "dup2", "/bin/sh")):
            signals.append(
                RuleSignal(
                    rule_id="reverse-shell-pattern",
                    risk="high",
                    confidence=96,
                    reason="Patch combines socket redirection with an interactive shell.",
                    indicators=["socket", "dup2", "/bin/sh"],
                )
            )

        if "subprocess" in lower_patch and any(token in lower_patch for token in ("/bin/sh", "cmd.exe", "powershell")):
            signals.append(
                RuleSignal(
                    rule_id="shell-spawn",
                    risk="high",
                    confidence=88,
                    reason="Patch launches a shell through subprocess execution.",
                    indicators=["subprocess", "/bin/sh", "powershell", "cmd.exe"],
                )
            )

        if any(token in lower_patch for token in ("curl ", "wget ", "invoke-webrequest", "requests.get(")) and any(
            token in lower_patch for token in ("exec(", "eval(", "subprocess", "os.system(")
        ):
            signals.append(
                RuleSignal(
                    rule_id="download-and-execute",
                    risk="high",
                    confidence=90,
                    reason="Patch downloads remote content and executes it.",
                    indicators=["curl", "wget", "requests.get", "exec", "subprocess"],
                )
            )

        if "base64" in lower_patch and any(token in lower_patch for token in ("exec(", "eval(", "powershell -enc")):
            signals.append(
                RuleSignal(
                    rule_id="encoded-execution",
                    risk="medium",
                    confidence=78,
                    reason="Patch appears to decode or run an encoded payload.",
                    indicators=["base64", "exec", "eval", "powershell -enc"],
                )
            )

        if any(token in lower_patch for token in ("openai_api_key", "github_token", "aws_secret_access_key")):
            signals.append(
                RuleSignal(
                    rule_id="secret-access-pattern",
                    risk="medium",
                    confidence=65,
                    reason="Patch references sensitive credential material directly.",
                    indicators=["openai_api_key", "github_token", "aws_secret_access_key"],
                )
            )

        if not signals:
            return DetectionResult(
                risk="low",
                confidence=20,
                summary=f"No deterministic rule hits for {filename}.",
                reasons=["No high-signal behavioral matches were detected by local rules."],
                indicators=[],
                rule_hits=[],
                raw_response="",
            )

        strongest_signal = max(signals, key=lambda signal: (RISK_ORDER[signal.risk], signal.confidence))
        reasons = self._unique_preserve_order(signal.reason for signal in signals)
        indicators = self._unique_preserve_order(
            indicator
            for signal in signals
            for indicator in signal.indicators
            if indicator in lower_patch
        )

        summary = (
            f"Deterministic prechecks flagged {filename} with "
            f"{strongest_signal.risk} risk via {', '.join(signal.rule_id for signal in signals)}."
        )
        return DetectionResult(
            risk=strongest_signal.risk,
            confidence=strongest_signal.confidence,
            summary=summary,
            reasons=reasons,
            indicators=indicators,
            rule_hits=[signal.rule_id for signal in signals],
            raw_response="",
        )

    @staticmethod
    def merge_results(rule_result: DetectionResult, llm_result: DetectionResult) -> DetectionResult:
        final_result = llm_result if RISK_ORDER[llm_result.normalized_risk()] >= RISK_ORDER[rule_result.normalized_risk()] else rule_result
        merged_summary = llm_result.summary or rule_result.summary
        if rule_result.rule_hits:
            merged_summary = (
                f"{merged_summary} Rule hits: {', '.join(rule_result.rule_hits)}."
            )

        return DetectionResult(
            risk=final_result.normalized_risk(),
            confidence=max(rule_result.confidence, llm_result.confidence),
            summary=merged_summary,
            reasons=ThreatHunter._unique_preserve_order(rule_result.reasons + llm_result.reasons),
            indicators=ThreatHunter._unique_preserve_order(rule_result.indicators + llm_result.indicators),
            yara_rule=llm_result.yara_rule or rule_result.yara_rule,
            raw_response=llm_result.raw_response,
            rule_hits=ThreatHunter._unique_preserve_order(rule_result.rule_hits + llm_result.rule_hits),
            history_context=llm_result.history_context or rule_result.history_context,
        )

    def apply_history_context(
        self,
        repo_name: str,
        file_name: str,
        commit_sha: str,
        result: DetectionResult,
    ) -> DetectionResult:
        history_context = self.store.get_history_context(
            repo_name=repo_name,
            file_name=file_name,
            rule_hits=result.rule_hits,
            exclude_commit_sha=commit_sha,
        )
        note = history_context.get("note", "")
        adjustment = history_context.get("adjustment", "none")

        risk = result.normalized_risk()
        confidence = result.confidence
        summary = result.summary
        reasons = list(result.reasons)

        if adjustment == "reduced":
            risk = self._shift_risk(risk, -1)
            confidence = max(0, confidence - 15)
        elif adjustment == "reinforced":
            confidence = min(100, confidence + 10)

        if note:
            reasons = self._unique_preserve_order([note] + reasons)
            summary = f"{summary} {note}"

        return DetectionResult(
            risk=risk,
            confidence=confidence,
            summary=summary,
            reasons=reasons,
            indicators=result.indicators,
            yara_rule=result.yara_rule,
            raw_response=result.raw_response,
            rule_hits=result.rule_hits,
            history_context=history_context,
        )

    def save_yara_rule(self, rule_text: str, commit_sha: str, filename: str) -> Path:
        sanitized_name = filename.replace("/", "_").replace("\\", "_")
        yara_path = SIGNATURES_DIR / f"threat_{commit_sha}_{sanitized_name}.yar"
        yara_path.write_text(rule_text.strip() + "\n", encoding="utf-8")
        return yara_path

    def _parse_detection_payload(self, raw_response: str) -> Dict[str, Any]:
        try:
            payload = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model returned invalid JSON: {raw_response}") from exc

        risk = str(payload.get("risk", "unknown")).strip().lower()
        confidence = self._coerce_confidence(payload.get("confidence", 0))
        summary = str(payload.get("summary", "")).strip() or "No summary returned."
        reasons = self._coerce_list(payload.get("reasons"))
        indicators = self._coerce_list(payload.get("indicators"))
        rule_hits = self._coerce_list(payload.get("rule_hits"))
        yara_rule = payload.get("yara_rule")

        if yara_rule is not None:
            yara_rule = str(yara_rule).strip() or None

        return {
            "risk": risk,
            "confidence": confidence,
            "summary": summary,
            "reasons": reasons,
            "indicators": indicators,
            "yara_rule": yara_rule,
            "rule_hits": rule_hits,
        }

    @staticmethod
    def _coerce_confidence(value: Any) -> int:
        try:
            confidence = int(value)
        except (TypeError, ValueError):
            confidence = 0
        return max(0, min(100, confidence))

    @staticmethod
    def _coerce_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    @staticmethod
    def _unique_preserve_order(values: Iterable[str]) -> List[str]:
        seen = set()
        items: List[str] = []
        for value in values:
            cleaned = str(value).strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            items.append(cleaned)
        return items

    @staticmethod
    def _shift_risk(risk: str, delta: int) -> str:
        ordered_risks = ["unknown", "low", "medium", "high"]
        normalized = risk if risk in ordered_risks else "unknown"
        shifted = max(0, min(len(ordered_risks) - 1, ordered_risks.index(normalized) + delta))
        return ordered_risks[shifted]

    @staticmethod
    def _print_result(result: DetectionResult) -> None:
        print("    [SECURITY REPORT]")
        print(f"    Risk: {result.normalized_risk()} ({result.confidence}% confidence)")
        print(f"    Summary: {result.summary}")
        if result.history_context.get("adjustment") and result.history_context.get("adjustment") != "none":
            print(f"    History: {result.history_context['adjustment']}")
        if result.rule_hits:
            print(f"    Rule Hits: {', '.join(result.rule_hits)}")
        if result.reasons:
            print(f"    Reasons: {', '.join(result.reasons)}")
        if result.indicators:
            print(f"    Indicators: {', '.join(result.indicators)}")


def load_watchlist(path: Path = WATCHLIST_PATH) -> List[str]:
    env_repos = os.getenv("WATCHLIST_REPOS")
    if env_repos:
        return [repo.strip() for repo in env_repos.split(",") if repo.strip()]

    if not path.exists():
        return []

    repos: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        repos.append(cleaned)
    return repos


def print_findings_table(rows: List[sqlite3.Row]) -> None:
    if not rows:
        print("No findings matched the current filters.")
        return

    for row in rows:
        rule_hits = json.loads(row["rule_hits_json"] or "[]")
        history_context = json.loads(row["history_context_json"] or "{}")
        print(
            f"[{row['id']}] {row['risk'].upper():<6} {row['confidence']:>3}% "
            f"{row['disposition']:<14} "
            f"{row['repo_name']} {row['commit_sha'][:7]} {row['file_name']}"
        )
        print(f"      {row['summary']}")
        if rule_hits:
            print(f"      Rule hits: {', '.join(rule_hits)}")
        if history_context.get("adjustment") and history_context.get("adjustment") != "none":
            print(f"      History: {history_context['adjustment']}")


def print_finding_detail(row: Optional[sqlite3.Row]) -> None:
    if row is None:
        print("Finding not found.")
        return

    reasons = json.loads(row["reasons_json"] or "[]")
    indicators = json.loads(row["indicators_json"] or "[]")
    rule_hits = json.loads(row["rule_hits_json"] or "[]")
    history_context = json.loads(row["history_context_json"] or "{}")

    print(f"Finding #{row['id']}")
    print(f"Repo: {row['repo_name']}")
    print(f"Commit: {row['commit_sha']}")
    print(f"Author: {row['author_name']}")
    print(f"Message: {row['commit_message']}")
    print(f"File: {row['file_name']}")
    print(f"Risk: {row['risk']} ({row['confidence']}% confidence)")
    print(f"Disposition: {row['disposition']}")
    print(f"Created: {row['created_at']}")
    if row["triaged_at"]:
        print(f"Triaged: {row['triaged_at']}")
    if row["html_url"]:
        print(f"URL: {row['html_url']}")
    print(f"Summary: {row['summary']}")
    if row["analyst_note"]:
        print(f"Analyst Note: {row['analyst_note']}")
    if history_context.get("same_file_finding_count"):
        print("Historical Context:")
        print(f"  Same-file findings: {history_context.get('same_file_finding_count', 0)}")
        print(f"  Matching rule-hit findings: {history_context.get('matching_rule_hit_count', 0)}")
        print(f"  Confirmed true positives: {history_context.get('matching_true_positive_count', 0)}")
        print(f"  Prior false positives: {history_context.get('matching_false_positive_count', 0)}")
        print(f"  Prior ignored: {history_context.get('matching_ignored_count', 0)}")
        if history_context.get("related_finding_ids"):
            print(
                "  Related finding ids: "
                + ", ".join(str(item) for item in history_context["related_finding_ids"])
            )
        if history_context.get("note"):
            print(f"  Adjustment: {history_context['note']}")
    if rule_hits:
        print(f"Rule hits: {', '.join(rule_hits)}")
    if reasons:
        print(f"Reasons: {', '.join(reasons)}")
    if indicators:
        print(f"Indicators: {', '.join(indicators)}")
    if row["yara_rule"]:
        print("YARA:")
        print(row["yara_rule"])


def build_hunter() -> ThreatHunter:
    return ThreatHunter(
        github_token=GITHUB_TOKEN,
        openai_api_key=OPENAI_API_KEY,
        db_path=DATABASE_PATH,
        model=DEFAULT_MODEL,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-powered GitHub commit threat hunter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a single repository")
    scan_parser.add_argument("--repo", default=DEFAULT_TARGET_REPO, help="GitHub repo in owner/name format")
    scan_parser.add_argument("--limit", type=int, default=DEFAULT_SCAN_LIMIT, help="Number of recent commits to scan")
    scan_parser.add_argument(
        "--include-existing",
        action="store_true",
        help="Re-scan commits even if they already exist in the local database",
    )

    watchlist_parser = subparsers.add_parser("scan-watchlist", help="Scan repositories from the watchlist")
    watchlist_parser.add_argument("--watchlist", type=Path, default=WATCHLIST_PATH, help="Path to watchlist file")
    watchlist_parser.add_argument("--limit", type=int, default=DEFAULT_SCAN_LIMIT, help="Number of recent commits per repo")
    watchlist_parser.add_argument(
        "--include-existing",
        action="store_true",
        help="Re-scan commits even if they already exist in the local database",
    )

    list_parser = subparsers.add_parser("list-findings", help="List stored findings")
    list_parser.add_argument("--limit", type=int, default=20, help="Maximum findings to display")
    list_parser.add_argument("--risk", choices=["high", "medium", "low"], help="Filter by risk level")
    list_parser.add_argument("--repo", help="Filter by repository name")
    list_parser.add_argument("--disposition", choices=sorted(VALID_DISPOSITIONS), help="Filter by disposition")

    show_parser = subparsers.add_parser("show-finding", help="Show a finding in detail")
    show_parser.add_argument("finding_id", type=int, help="Finding identifier")

    triage_parser = subparsers.add_parser("triage-finding", help="Update finding disposition and analyst note")
    triage_parser.add_argument("finding_id", type=int, help="Finding identifier")
    triage_parser.add_argument(
        "--disposition",
        required=True,
        choices=sorted(VALID_DISPOSITIONS),
        help="Analyst disposition for the finding",
    )
    triage_parser.add_argument("--note", help="Optional analyst note to attach to the finding")
    triage_parser.add_argument(
        "--clear-note",
        action="store_true",
        help="Clear any existing analyst note",
    )

    test_parser = subparsers.add_parser("test", help="Run the synthetic local threat test")
    test_parser.add_argument("--filename", default="requests/api.py", help="Logical filename for the synthetic patch")
    test_parser.add_argument("--commit-sha", default="reverse_shell_001", help="Synthetic commit identifier")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command in {"scan", "scan-watchlist", "test"}:
        hunter = build_hunter()
    else:
        store = FindingStore(DATABASE_PATH)

    if args.command == "scan":
        hunter.monitor_repository(args.repo, limit=args.limit, skip_existing=not args.include_existing)
        return

    if args.command == "scan-watchlist":
        repos = load_watchlist(args.watchlist)
        if not repos:
            print(f"No repositories found in watchlist: {args.watchlist}")
            return
        for repo_name in repos:
            hunter.monitor_repository(repo_name, limit=args.limit, skip_existing=not args.include_existing)
        return

    if args.command == "list-findings":
        print_findings_table(
            store.list_findings(
                limit=args.limit,
                risk=args.risk,
                repo_name=args.repo,
                disposition=args.disposition,
            )
        )
        return

    if args.command == "show-finding":
        print_finding_detail(store.get_finding(args.finding_id))
        return

    if args.command == "triage-finding":
        updated = store.update_finding_triage(
            args.finding_id,
            disposition=args.disposition,
            analyst_note=args.note,
            clear_note=args.clear_note,
        )
        if not updated:
            print("Finding not found.")
            return
        print(
            f"Updated finding {args.finding_id} to disposition '{args.disposition}'."
        )
        if args.note is not None:
            print("Analyst note updated.")
        elif args.clear_note:
            print("Analyst note cleared.")
        return

    if args.command == "test":
        from testThreat import FAKE_PATCH

        result = hunter.analyze_patch(
            args.filename,
            FAKE_PATCH,
            commit_sha=args.commit_sha,
            repo_name=DEFAULT_TARGET_REPO,
        )
        hunter.store.save_commit_metadata(
            repo_name=DEFAULT_TARGET_REPO,
            commit_sha=args.commit_sha,
            author_name="local-test",
            commit_message="Synthetic reverse shell patch",
            html_url=None,
        )
        hunter.store.save_finding(args.commit_sha, args.filename, result)
        hunter._print_result(result)
        if result.should_save_yara():
            yara_path = hunter.save_yara_rule(result.yara_rule or "", args.commit_sha, args.filename)
            print(f"Saved YARA rule to {yara_path}")
        return

    parser.error(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
