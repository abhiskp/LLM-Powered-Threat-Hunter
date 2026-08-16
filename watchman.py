import argparse
import fnmatch
import json
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from dotenv import load_dotenv
from github import Auth, Github
from openai import OpenAI
from storage import FindingStore, OwnershipContext


load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEFAULT_TARGET_REPO = os.getenv("TARGET_REPO", "psf/requests")
DATABASE_PATH = Path(os.getenv("WATCHMAN_DB_PATH", "security_findings.db"))
DATABASE_URL = os.getenv("WATCHMAN_DATABASE_URL")
SIGNATURES_DIR = Path("signatures")
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
WATCHLIST_PATH = Path(os.getenv("WATCHLIST_PATH", "watchlist.txt"))
SUPPRESSIONS_PATH = Path(os.getenv("SUPPRESSIONS_PATH", "suppressions.json"))
DEFAULT_EVAL_DATASET = Path(os.getenv("EVAL_DATASET_PATH", "datasets/eval_dataset.json"))
DEFAULT_SCAN_LIMIT = int(os.getenv("WATCHMAN_SCAN_LIMIT", "3"))
DEFAULT_SCAN_INTERVAL_MINUTES = int(os.getenv("WATCHMAN_SCAN_INTERVAL_MINUTES", "60"))
ALERTS_LOG_PATH = Path(os.getenv("ALERTS_LOG_PATH", "alerts/alerts.jsonl"))
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")
ALERT_MIN_RISK = os.getenv("ALERT_MIN_RISK", "high").strip().lower()
ALERT_MIN_CONFIDENCE = int(os.getenv("ALERT_MIN_CONFIDENCE", "80"))
SCAN_LOCK_TIMEOUT_MINUTES = int(os.getenv("WATCHMAN_SCAN_LOCK_MINUTES", "30"))
DELIVERY_RETRY_LIMIT = int(os.getenv("WATCHMAN_DELIVERY_RETRY_LIMIT", "3"))
DELIVERY_RETRY_BASE_MINUTES = int(os.getenv("WATCHMAN_DELIVERY_RETRY_BASE_MINUTES", "5"))
DEFAULT_TEAM_SLUG = os.getenv("WATCHMAN_DEFAULT_TEAM_SLUG", "personal-lab")
DEFAULT_TEAM_NAME = os.getenv("WATCHMAN_DEFAULT_TEAM_NAME", "Personal Lab")
DEFAULT_USER_EMAIL = os.getenv("WATCHMAN_DEFAULT_USER_EMAIL", "analyst@example.com")
DEFAULT_USER_NAME = os.getenv("WATCHMAN_DEFAULT_USER_NAME", "Local Analyst")
BACKGROUND_SCANNER_USER_NAME = os.getenv("WATCHMAN_BACKGROUND_USER_NAME", "Background Scanner")
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
    suppression_context: Dict[str, Any] = field(default_factory=dict)

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


@dataclass
class EvaluationCaseResult:
    case_id: str
    expected_label: str
    predicted_label: str
    risk: str
    confidence: int
    passed: bool
    summary: str


@dataclass
class AlertDeliveryResult:
    delivered: bool
    channels: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class ScanExecutionResult:
    repo_name: str
    commits_seen: int = 0
    commits_scanned: int = 0
    findings_created: int = 0
    high_risk_findings: int = 0
    skipped_commits: int = 0


def build_slack_webhook_body(payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = str(payload.get("risk") or "unknown").upper()
    summary = str(payload.get("summary") or "Suspicious code detected.")
    repo_name = str(payload.get("repo_name") or "")
    commit_sha = str(payload.get("commit_sha") or "")
    file_name = str(payload.get("file_name") or "")
    confidence = int(payload.get("confidence") or 0)
    indicators = ", ".join(str(item) for item in payload.get("indicators") or []) or "None"
    return {
        "text": f"[{risk}] {repo_name} {file_name}: {summary}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*[{risk}] Threat Hunter alert*\n*Repo:* `{repo_name}`\n*File:* `{file_name}`",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Confidence*\n{confidence}%"},
                    {"type": "mrkdwn", "text": f"*Commit*\n`{commit_sha[:12]}`"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Indicators: {indicators}"}]},
        ],
    }

def default_ownership_context(
    team_slug: Optional[str] = None,
    team_name: Optional[str] = None,
    user_email: Optional[str] = None,
    user_name: Optional[str] = None,
) -> OwnershipContext:
    return OwnershipContext(
        team_slug=(team_slug or DEFAULT_TEAM_SLUG).strip(),
        team_name=(team_name or DEFAULT_TEAM_NAME).strip(),
        user_email=(user_email or DEFAULT_USER_EMAIL).strip(),
        user_name=(user_name or DEFAULT_USER_NAME).strip(),
    )


class ThreatHunter:
    def __init__(
        self,
        github_token: Optional[str],
        openai_api_key: Optional[str],
        db_path: Path = DATABASE_PATH,
        database_url: Optional[str] = DATABASE_URL,
        model: str = DEFAULT_MODEL,
        suppressions: Optional[List[Dict[str, Any]]] = None,
        ownership: Optional[OwnershipContext] = None,
        store: Optional[FindingStore] = None,
    ) -> None:
        self.github = Github(auth=Auth.Token(github_token)) if github_token else None
        self.client = OpenAI(api_key=openai_api_key) if openai_api_key else None
        self.store = store or FindingStore(db_path=db_path, database_url=database_url)
        self.model = model
        self.suppressions = suppressions if suppressions is not None else load_suppressions()
        self.ownership = ownership or default_ownership_context()
        SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)

    def monitor_repository(self, repo_name: str, limit: int = 3, skip_existing: bool = True) -> ScanExecutionResult:
        if not self.github:
            raise ValueError("Missing GITHUB_TOKEN. Required for repository scanning.")

        repo = self.github.get_repo(repo_name)
        commits = repo.get_commits()
        summary = ScanExecutionResult(repo_name=repo_name)

        print(f"--- Monitoring {repo_name} ---")

        for index, commit in enumerate(commits):
            if index >= limit:
                break

            summary.commits_seen += 1
            commit_sha = commit.sha
            if skip_existing and self.store.commit_exists(self.ownership, repo_name, commit_sha):
                print(f"\n[-] Skipping {commit_sha[:7]} (already analyzed)")
                summary.skipped_commits += 1
                continue

            summary.commits_scanned += 1
            author_name = getattr(commit.commit.author, "name", "Unknown")
            commit_message = getattr(commit.commit, "message", "")
            print(f"\n[+] Analyzing Commit: {commit_sha[:7]}")
            print(f"    Author: {author_name}")

            self.store.save_commit_metadata(
                ownership=self.ownership,
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
                self.store.save_finding(
                    ownership=self.ownership,
                    repo_name=repo_name,
                    commit_sha=commit_sha,
                    file_name=changed_file.filename,
                    result=result,
                )
                summary.findings_created += 1
                if result.normalized_risk() == "high":
                    summary.high_risk_findings += 1
                self._print_result(result)
                delivery = deliver_alert(
                    ownership=self.ownership,
                    repo_name=repo_name,
                    commit_sha=commit_sha,
                    file_name=changed_file.filename,
                    result=result,
                    store=self.store,
                )
                if delivery.delivered:
                    print(f"    Alert delivered: {', '.join(delivery.channels)}")
                elif delivery.errors:
                    print(f"    Alert delivery errors: {'; '.join(delivery.errors)}")

                if result.should_save_yara():
                    yara_path = self.save_yara_rule(result.yara_rule or "", commit_sha, changed_file.filename)
                    print(f"    YARA saved: {yara_path}")
        return summary

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
            history_adjusted = self.apply_history_context(
                repo_name=repo_name,
                file_name=filename,
                commit_sha=commit_sha,
                result=rule_result,
            )
            return self.apply_suppressions(
                repo_name=repo_name,
                file_name=filename,
                result=history_adjusted,
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
        history_adjusted = self.apply_history_context(
            repo_name=repo_name,
            file_name=filename,
            commit_sha=commit_sha,
            result=merged,
        )
        return self.apply_suppressions(
            repo_name=repo_name,
            file_name=filename,
            result=history_adjusted,
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
            ownership=self.ownership,
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
            suppression_context=result.suppression_context,
        )

    def apply_suppressions(
        self,
        repo_name: str,
        file_name: str,
        result: DetectionResult,
    ) -> DetectionResult:
        matched_rules = []
        for rule in self.suppressions:
            if not rule.get("enabled", True):
                continue
            if self._matches_suppression(rule, repo_name, file_name, result.rule_hits):
                matched_rules.append(rule)

        if not matched_rules:
            return result

        rule_names = [str(rule.get("id", "unnamed-rule")) for rule in matched_rules]
        note = (
            f"Suppression rules matched: {', '.join(rule_names)}. "
            "Risk was reduced for a known-safe or suppressed pattern."
        )
        return DetectionResult(
            risk="low",
            confidence=min(result.confidence, 25),
            summary=f"{result.summary} {note}",
            reasons=self._unique_preserve_order([note] + result.reasons),
            indicators=result.indicators,
            yara_rule=None,
            raw_response=result.raw_response,
            rule_hits=result.rule_hits,
            history_context=result.history_context,
            suppression_context={
                "matched_rule_ids": rule_names,
                "note": note,
            },
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
    def _matches_suppression(
        rule: Dict[str, Any],
        repo_name: str,
        file_name: str,
        rule_hits: List[str],
    ) -> bool:
        repo_pattern = str(rule.get("repo", "*"))
        file_pattern = str(rule.get("file_pattern", "*"))
        configured_rule_hits = rule.get("rule_hits", [])
        if not fnmatch.fnmatch(repo_name, repo_pattern):
            return False
        if not fnmatch.fnmatch(file_name, file_pattern):
            return False
        if not configured_rule_hits:
            return True
        configured_values = {str(item).strip() for item in configured_rule_hits if str(item).strip()}
        return bool(configured_values.intersection(set(rule_hits)))

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
        if result.suppression_context.get("matched_rule_ids"):
            print(f"    Suppression: {', '.join(result.suppression_context['matched_rule_ids'])}")
        if result.rule_hits:
            print(f"    Rule Hits: {', '.join(result.rule_hits)}")
        if result.reasons:
            print(f"    Reasons: {', '.join(result.reasons)}")
        if result.indicators:
            print(f"    Indicators: {', '.join(result.indicators)}")

    def evaluate_cases(self, cases: List[Dict[str, Any]]) -> List[EvaluationCaseResult]:
        results: List[EvaluationCaseResult] = []
        for index, case in enumerate(cases, start=1):
            case_id = str(case.get("id", f"case-{index}"))
            repo_name = str(case.get("repo_name", DEFAULT_TARGET_REPO))
            file_name = str(case["file_name"])
            patch = str(case["patch"])
            expected_label = str(case["expected_label"]).strip().lower()
            result = self.analyze_patch(
                filename=file_name,
                patch_data=patch,
                commit_sha=case_id,
                repo_name=repo_name,
            )
            predicted_label = self.label_from_risk(result.normalized_risk())
            results.append(
                EvaluationCaseResult(
                    case_id=case_id,
                    expected_label=expected_label,
                    predicted_label=predicted_label,
                    risk=result.normalized_risk(),
                    confidence=result.confidence,
                    passed=predicted_label == expected_label,
                    summary=result.summary,
                )
            )
        return results

    @staticmethod
    def label_from_risk(risk: str) -> str:
        return "malicious" if risk in {"medium", "high"} else "benign"


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


def load_suppressions(path: Path = SUPPRESSIONS_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        rules = payload.get("rules", [])
    elif isinstance(payload, list):
        rules = payload
    else:
        raise ValueError(f"Unsupported suppressions format in {path}")

    if not isinstance(rules, list):
        raise ValueError(f"Suppression rules must be a list in {path}")
    return [rule for rule in rules if isinstance(rule, dict)]


def load_evaluation_dataset(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        cases = payload.get("cases", [])
    elif isinstance(payload, list):
        cases = payload
    else:
        raise ValueError(f"Unsupported dataset format in {path}")

    if not isinstance(cases, list):
        raise ValueError(f"Evaluation dataset must contain a list of cases in {path}")
    return [case for case in cases if isinstance(case, dict)]


def print_findings_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("No findings matched the current filters.")
        return

    for row in rows:
        rule_hits = json.loads(row["rule_hits_json"] or "[]")
        history_context = json.loads(row["history_context_json"] or "{}")
        suppression_context = json.loads(row["suppression_context_json"] or "{}")
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
        if suppression_context.get("matched_rule_ids"):
            print(f"      Suppression: {', '.join(suppression_context['matched_rule_ids'])}")


def print_finding_detail(row: Optional[Dict[str, Any]]) -> None:
    if row is None:
        print("Finding not found.")
        return

    reasons = json.loads(row["reasons_json"] or "[]")
    indicators = json.loads(row["indicators_json"] or "[]")
    rule_hits = json.loads(row["rule_hits_json"] or "[]")
    history_context = json.loads(row["history_context_json"] or "{}")
    suppression_context = json.loads(row["suppression_context_json"] or "{}")

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
    if suppression_context.get("matched_rule_ids"):
        print("Suppression Context:")
        print(
            "  Matched rules: "
            + ", ".join(str(item) for item in suppression_context["matched_rule_ids"])
        )
        if suppression_context.get("note"):
            print(f"  Note: {suppression_context['note']}")
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


def print_evaluation_report(results: List[EvaluationCaseResult]) -> None:
    if not results:
        print("No evaluation cases were provided.")
        return

    total = len(results)
    passed = sum(1 for result in results if result.passed)
    tp = sum(
        1
        for result in results
        if result.expected_label == "malicious" and result.predicted_label == "malicious"
    )
    tn = sum(
        1
        for result in results
        if result.expected_label == "benign" and result.predicted_label == "benign"
    )
    fp = sum(
        1
        for result in results
        if result.expected_label == "benign" and result.predicted_label == "malicious"
    )
    fn = sum(
        1
        for result in results
        if result.expected_label == "malicious" and result.predicted_label == "benign"
    )

    print("Evaluation Summary")
    print(f"  Total cases: {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Accuracy: {(passed / total) * 100:.1f}%")
    print(f"  True positives: {tp}")
    print(f"  True negatives: {tn}")
    print(f"  False positives: {fp}")
    print(f"  False negatives: {fn}")
    print("")
    print("Case Results")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"[{status}] {result.case_id} expected={result.expected_label} "
            f"predicted={result.predicted_label} risk={result.risk} confidence={result.confidence}"
        )
        print(f"       {result.summary}")

    print("")
    print("Tuning Suggestions")
    if fp > 0:
        print(
            "  False positives detected: add or tighten suppression rules by repo/file/rule-hit "
            "for recurring known-safe patterns."
        )
    if fn > 0:
        print(
            "  False negatives detected: expand deterministic prechecks or improve labeled examples "
            "for the missed malicious behaviors."
        )
    if fp == 0 and fn == 0:
        print("  Current dataset is passing cleanly. Add more diverse benign and malicious samples next.")


def print_scan_run_report(results: List[Dict[str, Any]]) -> None:
    if not results:
        print("No scan targets were run.")
        return
    for result in results:
        status = str(result.get("status", "unknown")).upper()
        print(f"[{status}] {result.get('team_slug')} {result.get('repo_name')}")
        if result.get("status") == "completed":
            print(
                "       findings_created="
                f"{result.get('findings_created', 0)} high_risk_findings={result.get('high_risk_findings', 0)} "
                f"commits_scanned={result.get('commits_scanned', 0)}"
            )
        elif result.get("error_message"):
            print(f"       error={result['error_message']}")


def print_delivery_report(results: List[Dict[str, Any]]) -> None:
    if not results:
        print("No alert deliveries were processed.")
        return
    for result in results:
        status = str(result.get("status", "unknown")).upper()
        print(f"[{status}] {result.get('team_slug')} {result.get('repo_name')} via {result.get('channel')}")
        if result.get("error_message"):
            print(f"       error={result['error_message']}")
        if result.get("next_attempt_at"):
            print(f"       next_attempt_at={result['next_attempt_at']}")


def resolve_alert_settings(
    ownership: OwnershipContext,
    store: Optional[FindingStore] = None,
) -> Dict[str, Any]:
    defaults = {
        "alert_webhook_url": ALERT_WEBHOOK_URL,
        "alert_min_risk": ALERT_MIN_RISK,
        "alert_min_confidence": ALERT_MIN_CONFIDENCE,
        "scans_enabled": True,
        "scan_limit": DEFAULT_SCAN_LIMIT,
    }
    if store is None:
        return defaults
    try:
        persisted = store.get_team_settings(ownership)
    except Exception:
        return defaults
    return {
        "alert_webhook_url": persisted.get("alert_webhook_url") or ALERT_WEBHOOK_URL,
        "alert_min_risk": str(persisted.get("alert_min_risk") or ALERT_MIN_RISK).strip().lower(),
        "alert_min_confidence": int(persisted.get("alert_min_confidence", ALERT_MIN_CONFIDENCE)),
        "scans_enabled": bool(persisted.get("scans_enabled", True)),
        "scan_limit": int(persisted.get("scan_limit", DEFAULT_SCAN_LIMIT)),
        "scan_interval_minutes": int(
            persisted.get("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)
        ),
    }


def should_deliver_alert(result: DetectionResult, settings: Optional[Dict[str, Any]] = None) -> bool:
    settings = settings or {}
    normalized_risk = result.normalized_risk()
    min_risk = str(settings.get("alert_min_risk", ALERT_MIN_RISK)).strip().lower()
    min_confidence = int(settings.get("alert_min_confidence", ALERT_MIN_CONFIDENCE))
    if RISK_ORDER.get(normalized_risk, 0) < RISK_ORDER.get(min_risk, RISK_ORDER["high"]):
        return False
    if result.confidence < min_confidence:
        return False
    if result.suppression_context.get("matched_rule_ids"):
        return False
    return True


def build_alert_payload(
    ownership: OwnershipContext,
    repo_name: str,
    commit_sha: str,
    file_name: str,
    result: DetectionResult,
) -> Dict[str, Any]:
    return {
        "team_slug": ownership.team_slug,
        "team_name": ownership.team_name,
        "repo_name": repo_name,
        "commit_sha": commit_sha,
        "file_name": file_name,
        "risk": result.normalized_risk(),
        "confidence": result.confidence,
        "summary": result.summary,
        "rule_hits": result.rule_hits,
        "reasons": result.reasons,
        "indicators": result.indicators,
        "history_context": result.history_context,
        "suppression_context": result.suppression_context,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


class AlertDeliveryService:
    def __init__(self, store: Optional[FindingStore] = None) -> None:
        self.store = store or FindingStore(db_path=DATABASE_PATH, database_url=DATABASE_URL)

    def queue_destinations(
        self,
        ownership: OwnershipContext,
        payload: Dict[str, Any],
        repo_name: str,
        commit_sha: str,
        file_name: str,
    ) -> List[Dict[str, Any]]:
        queued: List[Dict[str, Any]] = []
        for destination in self.store.list_alert_destinations(ownership=ownership, active_only=True):
            queued.append(
                self.store.enqueue_alert_delivery(
                    ownership=ownership,
                    repo_name=repo_name,
                    commit_sha=commit_sha,
                    file_name=file_name,
                    channel=str(destination["kind"]),
                    destination=str(destination["target_url"]),
                    payload=payload,
                    destination_id=int(destination["id"]),
                    status="pending",
                )
            )
        return queued

    def process_cycle(self, team_slug: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for row in self.store.list_pending_alert_deliveries(team_slug=team_slug, limit=limit):
            results.append(self._process_delivery_row(row))
        return results

    def send_test_alert(self, ownership: OwnershipContext, destination_id: int) -> Dict[str, Any]:
        destination = self.store.get_alert_destination(ownership=ownership, destination_id=destination_id)
        if destination is None:
            raise ValueError("Alert destination not found.")
        payload = {
            "team_slug": ownership.team_slug,
            "team_name": ownership.team_name,
            "repo_name": "watchman/system",
            "commit_sha": "test-alert",
            "file_name": "system/test",
            "risk": "high",
            "confidence": 100,
            "summary": f"Test alert for destination {destination['name']}",
            "rule_hits": ["test-alert"],
            "reasons": ["Manual destination validation"],
            "indicators": ["test-alert"],
            "history_context": {},
            "suppression_context": {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        queued = self.store.enqueue_alert_delivery(
            ownership=ownership,
            repo_name="watchman/system",
            commit_sha="test-alert",
            file_name="system/test",
            channel=str(destination["kind"]),
            destination=str(destination["target_url"]),
            payload=payload,
            destination_id=int(destination["id"]),
            status="pending",
        )
        row = {
            **queued,
            "team_slug": ownership.team_slug,
            "team_name": ownership.team_name,
            "payload_json": json.dumps(payload),
            "destination_kind": destination["kind"],
            "destination_name": destination["name"],
            "target_url": destination["target_url"],
            "attempt_number": 0,
        }
        return self._process_delivery_row(row)

    def _process_delivery_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.loads(row.get("payload_json") or "{}")
        delivery_id = int(row["id"])
        destination_id = row.get("destination_id")
        try:
            self._send_destination(row, payload)
            self.store.update_alert_delivery_status(
                delivery_id,
                status="delivered",
                error_message=None,
                next_attempt_at=None,
                increment_attempt=True,
            )
            if destination_id:
                self.store.record_alert_destination_result(int(destination_id), error_message=None)
            return {
                "delivery_id": delivery_id,
                "team_slug": row.get("team_slug"),
                "repo_name": row.get("repo_name"),
                "channel": row.get("channel"),
                "status": "delivered",
            }
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            next_attempt_number = int(row.get("attempt_number") or 0) + 1
            if next_attempt_number >= DELIVERY_RETRY_LIMIT:
                status = "dead_letter"
                next_attempt_at = None
            else:
                status = "failed"
                next_attempt_at = self._retry_at(next_attempt_number)
            self.store.update_alert_delivery_status(
                delivery_id,
                status=status,
                error_message=str(exc),
                next_attempt_at=next_attempt_at,
                increment_attempt=True,
            )
            if destination_id:
                self.store.record_alert_destination_result(int(destination_id), error_message=str(exc))
            return {
                "delivery_id": delivery_id,
                "team_slug": row.get("team_slug"),
                "repo_name": row.get("repo_name"),
                "channel": row.get("channel"),
                "status": status,
                "error_message": str(exc),
                "next_attempt_at": next_attempt_at,
            }

    def _send_destination(self, row: Dict[str, Any], payload: Dict[str, Any]) -> None:
        kind = str(row.get("destination_kind") or row.get("channel") or "").strip().lower()
        target_url = str(row.get("target_url") or row.get("destination") or "").strip()
        if kind == "slack_webhook":
            self._send_json(target_url, build_slack_webhook_body(payload))
            return
        raise ValueError(f"Unsupported destination kind: {kind}")

    @staticmethod
    def _send_json(target_url: str, payload: Dict[str, Any]) -> None:
        request = urllib.request.Request(
            target_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()

    @staticmethod
    def _retry_at(attempt_number: int) -> str:
        delay_minutes = DELIVERY_RETRY_BASE_MINUTES * (2 ** max(0, attempt_number - 1))
        return (datetime.now(timezone.utc) + timedelta(minutes=delay_minutes)).isoformat()


def deliver_alert(
    ownership: OwnershipContext,
    repo_name: str,
    commit_sha: str,
    file_name: str,
    result: DetectionResult,
    store: Optional[FindingStore] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> AlertDeliveryResult:
    effective_settings = settings or resolve_alert_settings(ownership, store=store)
    if not should_deliver_alert(result, settings=effective_settings):
        return AlertDeliveryResult(delivered=False)

    payload = build_alert_payload(ownership, repo_name, commit_sha, file_name, result)
    channels: List[str] = []
    errors: List[str] = []

    ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ALERTS_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
    channels.append(f"log:{ALERTS_LOG_PATH}")
    if store is not None:
        store.record_alert_delivery(
            ownership=ownership,
            repo_name=repo_name,
            commit_sha=commit_sha,
            file_name=file_name,
            channel="log",
            destination=str(ALERTS_LOG_PATH),
            status="delivered",
        )

    if store is not None:
        delivery_service = AlertDeliveryService(store=store)
        queued = delivery_service.queue_destinations(
            ownership=ownership,
            payload=payload,
            repo_name=repo_name,
            commit_sha=commit_sha,
            file_name=file_name,
        )
        if queued:
            processed = delivery_service.process_cycle(team_slug=ownership.team_slug, limit=max(len(queued), 1))
            for row in processed:
                if row.get("status") == "delivered":
                    channels.append(str(row.get("channel") or "destination"))
                elif row.get("error_message"):
                    errors.append(str(row["error_message"]))

    webhook_url = effective_settings.get("alert_webhook_url") or ALERT_WEBHOOK_URL
    if webhook_url and store is None:
        request = urllib.request.Request(
            str(webhook_url),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            channels.append("webhook")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            errors.append(f"webhook failed: {exc}")
    elif webhook_url and store is not None and not store.list_alert_destinations(ownership=ownership, active_only=True):
        request = urllib.request.Request(
            str(webhook_url),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            channels.append("webhook")
            store.record_alert_delivery(
                ownership=ownership,
                repo_name=repo_name,
                commit_sha=commit_sha,
                file_name=file_name,
                channel="webhook",
                destination=str(webhook_url),
                status="delivered",
            )
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            errors.append(f"webhook failed: {exc}")
            store.record_alert_delivery(
                ownership=ownership,
                repo_name=repo_name,
                commit_sha=commit_sha,
                file_name=file_name,
                channel="webhook",
                destination=str(webhook_url),
                status="failed",
                error_message=str(exc),
            )

    return AlertDeliveryResult(delivered=bool(channels), channels=channels, errors=errors)


class BackgroundScanService:
    def __init__(
        self,
        store: Optional[FindingStore] = None,
        github_token: Optional[str] = GITHUB_TOKEN,
        openai_api_key: Optional[str] = OPENAI_API_KEY,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self.store = store or FindingStore(db_path=DATABASE_PATH, database_url=DATABASE_URL)
        self.github_token = github_token
        self.openai_api_key = openai_api_key
        self.model = model

    def list_targets(self, team_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.store.list_scan_targets(team_slug=team_slug)

    def run_cycle(self, team_slug: Optional[str] = None) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for target in self.list_targets(team_slug=team_slug):
            if not target.get("scans_enabled", True):
                continue
            if not self._is_target_due(target):
                continue
            results.append(self.scan_target(target, trigger_mode="scheduled"))
        return results

    @staticmethod
    def _is_target_due(target: Dict[str, Any]) -> bool:
        next_scan_at = str(target.get("next_scan_at") or "").strip()
        if not next_scan_at:
            return True
        try:
            return datetime.fromisoformat(next_scan_at) <= datetime.now(timezone.utc)
        except ValueError:
            return True

    def scan_watchlist_entry(
        self,
        ownership: OwnershipContext,
        watchlist_id: int,
        trigger_mode: str = "manual",
    ) -> Dict[str, Any]:
        watchlist_row = self.store.get_repo_watchlist(ownership, watchlist_id)
        if watchlist_row is None:
            raise ValueError("Watchlist entry not found.")
        team_settings = resolve_alert_settings(ownership, store=self.store)
        target = {
            "repo_watchlist_id": watchlist_row["id"],
            "repo_name": watchlist_row["repo_name"],
            "team_slug": ownership.team_slug,
            "team_name": ownership.team_name,
            "alert_webhook_url": team_settings["alert_webhook_url"],
            "alert_min_risk": team_settings["alert_min_risk"],
            "alert_min_confidence": team_settings["alert_min_confidence"],
            "scans_enabled": team_settings["scans_enabled"],
            "scan_limit": team_settings["scan_limit"],
            "scan_interval_minutes": watchlist_row.get("scan_interval_minutes", team_settings["scan_interval_minutes"]),
            "next_scan_at": watchlist_row.get("next_scan_at"),
        }
        return self.scan_target(target, trigger_mode=trigger_mode)

    def scan_target(self, target: Dict[str, Any], trigger_mode: str) -> Dict[str, Any]:
        ownership = default_ownership_context(
            team_slug=target["team_slug"],
            team_name=target["team_name"],
            user_email=f"scanner+{target['team_slug']}@watchman.local",
            user_name=BACKGROUND_SCANNER_USER_NAME,
        )
        scan_run = self.store.claim_scan_run(
            ownership=ownership,
            repo_watchlist_id=int(target["repo_watchlist_id"]),
            repo_name=str(target["repo_name"]),
            trigger_mode=trigger_mode,
            lock_timeout_minutes=SCAN_LOCK_TIMEOUT_MINUTES,
        )
        if scan_run is None:
            return {
                "scan_run_id": None,
                "team_slug": ownership.team_slug,
                "repo_name": str(target["repo_name"]),
                "status": "skipped",
                "skip_reason": "already_running",
            }
        scan_run_id = int(scan_run["id"])
        try:
            hunter = ThreatHunter(
                github_token=self.github_token,
                openai_api_key=self.openai_api_key,
                db_path=DATABASE_PATH,
                database_url=DATABASE_URL,
                model=self.model,
                suppressions=load_suppressions(),
                ownership=ownership,
                store=self.store,
            )
            summary = hunter.monitor_repository(
                repo_name=str(target["repo_name"]),
                limit=int(target.get("scan_limit", DEFAULT_SCAN_LIMIT)),
                skip_existing=True,
            )
            self.store.complete_scan_run(
                ownership=ownership,
                scan_run_id=scan_run_id,
                status="completed",
                findings_created=summary.findings_created,
                high_risk_findings=summary.high_risk_findings,
            )
            return {
                "scan_run_id": scan_run_id,
                "team_slug": ownership.team_slug,
                "repo_name": summary.repo_name,
                "status": "completed",
                "findings_created": summary.findings_created,
                "high_risk_findings": summary.high_risk_findings,
                "commits_scanned": summary.commits_scanned,
            }
        except Exception as exc:
            self.store.complete_scan_run(
                ownership=ownership,
                scan_run_id=scan_run_id,
                status="failed",
                error_message=str(exc),
            )
            return {
                "scan_run_id": scan_run_id,
                "team_slug": ownership.team_slug,
                "repo_name": str(target["repo_name"]),
                "status": "failed",
                "error_message": str(exc),
            }


def build_hunter() -> ThreatHunter:
    return ThreatHunter(
        github_token=GITHUB_TOKEN,
        openai_api_key=OPENAI_API_KEY,
        db_path=DATABASE_PATH,
        database_url=DATABASE_URL,
        model=DEFAULT_MODEL,
        suppressions=load_suppressions(),
        ownership=default_ownership_context(),
    )


def build_evaluation_hunter(
    dataset_db_path: Path,
    use_llm: bool,
) -> ThreatHunter:
    return ThreatHunter(
        github_token=None,
        openai_api_key=OPENAI_API_KEY if use_llm else None,
        db_path=dataset_db_path,
        database_url=None,
        model=DEFAULT_MODEL,
        suppressions=load_suppressions(),
        ownership=default_ownership_context(
            team_slug="evaluation-team",
            team_name="Evaluation Team",
            user_email="evaluation@watchman.local",
            user_name="Evaluation Runner",
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-powered GitHub commit threat hunter")
    parser.add_argument(
        "--team-slug",
        default=DEFAULT_TEAM_SLUG,
        help="Logical team slug for ownership scoping",
    )
    parser.add_argument(
        "--team-name",
        default=DEFAULT_TEAM_NAME,
        help="Display name for the current team context",
    )
    parser.add_argument(
        "--user-email",
        default=DEFAULT_USER_EMAIL,
        help="Analyst email for ownership and triage attribution",
    )
    parser.add_argument(
        "--user-name",
        default=DEFAULT_USER_NAME,
        help="Analyst display name for ownership and triage attribution",
    )
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

    evaluate_parser = subparsers.add_parser("evaluate", help="Run a labeled evaluation dataset")
    evaluate_parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_EVAL_DATASET,
        help="Path to a labeled evaluation dataset JSON file",
    )
    evaluate_parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Use the configured LLM during evaluation instead of rule-only scoring",
    )

    worker_parser = subparsers.add_parser("run-worker", help="Run background scans for active team watchlists")
    worker_parser.add_argument(
        "--all-teams",
        action="store_true",
        help="Run the scan cycle for every team with active watchlists",
    )

    delivery_worker_parser = subparsers.add_parser(
        "run-delivery-worker",
        help="Process pending alert deliveries for configured destinations",
    )
    delivery_worker_parser.add_argument(
        "--all-teams",
        action="store_true",
        help="Process the delivery queue for every team",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    ownership = default_ownership_context(
        team_slug=args.team_slug,
        team_name=args.team_name,
        user_email=args.user_email,
        user_name=args.user_name,
    )

    if args.command in {"scan", "scan-watchlist", "test"}:
        hunter = ThreatHunter(
            github_token=GITHUB_TOKEN,
            openai_api_key=OPENAI_API_KEY,
            db_path=DATABASE_PATH,
            database_url=DATABASE_URL,
            model=DEFAULT_MODEL,
            suppressions=load_suppressions(),
            ownership=ownership,
        )
    else:
        store = FindingStore(db_path=DATABASE_PATH, database_url=DATABASE_URL)

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
                ownership=ownership,
                limit=args.limit,
                risk=args.risk,
                repo_name=args.repo,
                disposition=args.disposition,
            )
        )
        return

    if args.command == "show-finding":
        print_finding_detail(store.get_finding(ownership=ownership, finding_id=args.finding_id))
        return

    if args.command == "triage-finding":
        updated = store.update_finding_triage(
            ownership=ownership,
            finding_id=args.finding_id,
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
            ownership=ownership,
            repo_name=DEFAULT_TARGET_REPO,
            commit_sha=args.commit_sha,
            author_name="local-test",
            commit_message="Synthetic reverse shell patch",
            html_url=None,
        )
        hunter.store.save_finding(
            ownership=ownership,
            repo_name=DEFAULT_TARGET_REPO,
            commit_sha=args.commit_sha,
            file_name=args.filename,
            result=result,
        )
        hunter._print_result(result)
        delivery = deliver_alert(
            ownership=ownership,
            repo_name=DEFAULT_TARGET_REPO,
            commit_sha=args.commit_sha,
            file_name=args.filename,
            result=result,
            store=hunter.store,
        )
        if delivery.delivered:
            print(f"Alert delivered: {', '.join(delivery.channels)}")
        elif delivery.errors:
            print(f"Alert delivery errors: {'; '.join(delivery.errors)}")
        if result.should_save_yara():
            yara_path = hunter.save_yara_rule(result.yara_rule or "", args.commit_sha, args.filename)
            print(f"Saved YARA rule to {yara_path}")
        return

    if args.command == "evaluate":
        if not args.dataset.exists():
            print(f"Dataset not found: {args.dataset}")
            return

        dataset = load_evaluation_dataset(args.dataset)
        with tempfile.NamedTemporaryFile(prefix="watchman-eval-", suffix=".db", delete=False) as handle:
            temp_db_path = Path(handle.name)

        try:
            evaluation_hunter = build_evaluation_hunter(
                dataset_db_path=temp_db_path,
                use_llm=args.use_llm,
            )
            results = evaluation_hunter.evaluate_cases(dataset)
            print_evaluation_report(results)
        finally:
            if temp_db_path.exists():
                temp_db_path.unlink()
        return

    if args.command == "run-worker":
        service = BackgroundScanService()
        results = service.run_cycle(team_slug=None if args.all_teams else ownership.team_slug)
        print_scan_run_report(results)
        return

    if args.command == "run-delivery-worker":
        service = AlertDeliveryService(store=store)
        results = service.process_cycle(team_slug=None if args.all_teams else ownership.team_slug, limit=50)
        print_delivery_report(results)
        return

    parser.error(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
