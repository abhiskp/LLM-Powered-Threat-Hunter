import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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


@dataclass
class DetectionResult:
    risk: str
    confidence: int
    summary: str
    reasons: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    yara_rule: Optional[str] = None
    raw_response: str = ""

    def normalized_risk(self) -> str:
        value = (self.risk or "").strip().lower()
        if value in {"high", "medium", "low"}:
            return value
        if value == "med":
            return "medium"
        return "unknown"

    def should_save_yara(self) -> bool:
        return self.normalized_risk() in {"high", "medium"} and bool(self.yara_rule)


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
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )


class ThreatHunter:
    def __init__(
        self,
        github_token: str,
        openai_api_key: str,
        db_path: Path = DATABASE_PATH,
        model: str = DEFAULT_MODEL,
    ) -> None:
        if not github_token:
            raise ValueError("Missing GITHUB_TOKEN.")
        if not openai_api_key:
            raise ValueError("Missing OPENAI_API_KEY.")

        self.github = Github(auth=Auth.Token(github_token))
        self.client = OpenAI(api_key=openai_api_key)
        self.store = FindingStore(db_path)
        self.model = model
        SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)

    def monitor_repository(self, repo_name: str, limit: int = 3, skip_existing: bool = True) -> None:
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
                )
                self.store.save_finding(commit_sha, changed_file.filename, result)
                self._print_result(result)

                if result.should_save_yara():
                    yara_path = self.save_yara_rule(result.yara_rule or "", commit_sha, changed_file.filename)
                    print(f"    YARA saved: {yara_path}")

    def analyze_patch(self, filename: str, patch_data: str, commit_sha: str = "test") -> DetectionResult:
        print("    ... Auditing for threats ...")

        user_prompt = f"""
Analyze this GitHub patch for malicious or suspicious activity.

Return valid JSON with exactly these keys:
- risk: one of ["high", "medium", "low"]
- confidence: integer from 0 to 100
- summary: short one-sentence explanation
- reasons: array of concise detection reasons
- indicators: array of suspicious APIs, IOCs, behaviors, or artifacts
- yara_rule: full YARA rule string if risk is high or medium, otherwise null

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
        return DetectionResult(**payload)

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
    def _print_result(result: DetectionResult) -> None:
        print("    [SECURITY REPORT]")
        print(f"    Risk: {result.normalized_risk()} ({result.confidence}% confidence)")
        print(f"    Summary: {result.summary}")
        if result.reasons:
            print(f"    Reasons: {', '.join(result.reasons)}")
        if result.indicators:
            print(f"    Indicators: {', '.join(result.indicators)}")


def build_hunter() -> ThreatHunter:
    return ThreatHunter(
        github_token=GITHUB_TOKEN or "",
        openai_api_key=OPENAI_API_KEY or "",
        db_path=DATABASE_PATH,
        model=DEFAULT_MODEL,
    )


if __name__ == "__main__":
    hunter = build_hunter()

    from testThreat import FAKE_PATCH

    result = hunter.analyze_patch("requests/api.py", FAKE_PATCH, commit_sha="reverse_shell_001")
    hunter.store.save_commit_metadata(
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha="reverse_shell_001",
        author_name="local-test",
        commit_message="Synthetic reverse shell patch",
        html_url=None,
    )
    hunter.store.save_finding("reverse_shell_001", "requests/api.py", result)
    hunter._print_result(result)
    if result.should_save_yara():
        yara_path = hunter.save_yara_rule(result.yara_rule or "", "reverse_shell_001", "requests/api.py")
        print(f"Saved YARA rule to {yara_path}")
