import json
import tempfile
from pathlib import Path

import watchman
from testThreat import FAKE_PATCH
from watchman import (
    DetectionResult,
    FindingStore,
    ThreatHunter,
    deliver_alert,
    load_evaluation_dataset,
    load_suppressions,
    load_watchlist,
)


def build_test_hunter(tmp_path: Path) -> ThreatHunter:
    return ThreatHunter(
        github_token="test-token",
        openai_api_key="test-key",
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
    )


def test_detection_result_normalizes_med_risk() -> None:
    result = DetectionResult(risk="Med", confidence=85, summary="suspicious")
    assert result.normalized_risk() == "medium"


def test_detection_result_requires_yara_for_persistence() -> None:
    result = DetectionResult(risk="high", confidence=95, summary="reverse shell", yara_rule=None)
    assert result.should_save_yara() is False


def test_parse_detection_payload_coerces_fields(tmp_path: Path) -> None:
    hunter = build_test_hunter(tmp_path)
    payload = json.dumps(
        {
            "risk": "High",
            "confidence": "101",
            "summary": "Reverse shell behavior detected.",
            "reasons": ["spawns shell", "opens outbound socket"],
            "indicators": ["socket", "/bin/sh"],
            "rule_hits": ["reverse-shell-pattern"],
            "yara_rule": "rule reverse_shell { condition: true }",
        }
    )

    parsed = hunter._parse_detection_payload(payload)

    assert parsed["risk"] == "high"
    assert parsed["confidence"] == 100
    assert parsed["summary"] == "Reverse shell behavior detected."
    assert parsed["reasons"] == ["spawns shell", "opens outbound socket"]
    assert parsed["indicators"] == ["socket", "/bin/sh"]
    assert parsed["rule_hits"] == ["reverse-shell-pattern"]


def test_run_prechecks_detects_reverse_shell(tmp_path: Path) -> None:
    hunter = build_test_hunter(tmp_path)
    result = hunter.run_prechecks("requests/api.py", FAKE_PATCH)

    assert result.normalized_risk() == "high"
    assert "reverse-shell-pattern" in result.rule_hits
    assert "/bin/sh" in result.indicators


def test_finding_store_saves_commit_and_finding(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    store.save_commit_metadata(
        repo_name="psf/requests",
        commit_sha="abc123",
        author_name="alice",
        commit_message="suspicious change",
        html_url="https://example.com/commit/abc123",
    )
    result = DetectionResult(
        risk="medium",
        confidence=77,
        summary="Suspicious subprocess usage.",
        reasons=["launches shell"],
        indicators=["subprocess", "/bin/sh"],
        yara_rule="rule suspicious_shell { condition: true }",
        raw_response='{"risk":"medium"}',
        rule_hits=["shell-spawn"],
    )

    store.save_finding("abc123", "requests/api.py", result)

    with store._connect() as connection:
        commit = connection.execute("SELECT repo_name, commit_sha FROM commits").fetchone()
        finding = connection.execute(
            "SELECT file_name, risk, confidence, summary, rule_hits_json, disposition, analyst_note, history_context_json FROM findings"
        ).fetchone()

    assert commit["repo_name"] == "psf/requests"
    assert commit["commit_sha"] == "abc123"
    assert finding["file_name"] == "requests/api.py"
    assert finding["risk"] == "medium"
    assert finding["confidence"] == 77
    assert json.loads(finding["rule_hits_json"]) == ["shell-spawn"]
    assert finding["disposition"] == "new"
    assert finding["analyst_note"] == ""
    assert json.loads(finding["history_context_json"]) == {}


def test_save_yara_rule_creates_file(tmp_path: Path) -> None:
    hunter = build_test_hunter(tmp_path)

    with tempfile.TemporaryDirectory() as directory:
        original_path = watchman.SIGNATURES_DIR
        try:
            watchman.SIGNATURES_DIR = Path(directory)
            yara_path = hunter.save_yara_rule(
                "rule reverse_shell { condition: true }",
                "deadbeef",
                "requests/api.py",
            )
            assert yara_path.exists()
            assert "requests_api.py" in yara_path.name
        finally:
            watchman.SIGNATURES_DIR = original_path


def test_load_watchlist_ignores_comments_and_blank_lines(tmp_path: Path) -> None:
    watchlist_path = tmp_path / "watchlist.txt"
    watchlist_path.write_text(
        "# monitored repos\npsf/requests\n\npallets/flask\n",
        encoding="utf-8",
    )

    repos = load_watchlist(watchlist_path)

    assert repos == ["psf/requests", "pallets/flask"]


def test_load_suppressions_reads_rule_list(tmp_path: Path) -> None:
    suppressions_path = tmp_path / "suppressions.json"
    suppressions_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "trusted-shell-helper",
                        "repo": "psf/*",
                        "file_pattern": "requests/*.py",
                        "rule_hits": ["shell-spawn"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_suppressions(suppressions_path)

    assert len(rules) == 1
    assert rules[0]["id"] == "trusted-shell-helper"


def test_load_evaluation_dataset_reads_cases(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "mal-001",
                        "repo_name": "psf/requests",
                        "file_name": "requests/api.py",
                        "patch": FAKE_PATCH,
                        "expected_label": "malicious",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    cases = load_evaluation_dataset(dataset_path)

    assert len(cases) == 1
    assert cases[0]["id"] == "mal-001"


def test_update_finding_triage_sets_disposition_and_note(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    store.save_commit_metadata(
        repo_name="psf/requests",
        commit_sha="abc124",
        author_name="alice",
        commit_message="another suspicious change",
        html_url="https://example.com/commit/abc124",
    )
    store.save_finding(
        "abc124",
        "requests/api.py",
        DetectionResult(
            risk="high",
            confidence=92,
            summary="High-risk shell execution.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            rule_hits=["shell-spawn"],
        ),
    )

    updated = store.update_finding_triage(
        1,
        disposition="true_positive",
        analyst_note="Confirmed reverse shell behavior.",
    )

    assert updated is True
    row = store.get_finding(1)
    assert row is not None
    assert row["disposition"] == "true_positive"
    assert row["analyst_note"] == "Confirmed reverse shell behavior."
    assert row["triaged_at"] is not None


def test_history_context_reduces_risk_after_false_positive(tmp_path: Path) -> None:
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
    )
    hunter.store.save_commit_metadata(
        repo_name="psf/requests",
        commit_sha="hist001",
        author_name="alice",
        commit_message="older shell pattern",
        html_url=None,
    )
    hunter.store.save_finding(
        "hist001",
        "requests/api.py",
        DetectionResult(
            risk="high",
            confidence=90,
            summary="Older shell spawn.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            rule_hits=["shell-spawn"],
        ),
    )
    hunter.store.update_finding_triage(1, disposition="false_positive", analyst_note="known admin helper")

    result = hunter.apply_history_context(
        repo_name="psf/requests",
        file_name="requests/api.py",
        commit_sha="new001",
        result=DetectionResult(
            risk="high",
            confidence=88,
            summary="Current shell spawn.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            rule_hits=["shell-spawn"],
        ),
    )

    assert result.normalized_risk() == "medium"
    assert result.confidence == 73
    assert result.history_context["adjustment"] == "reduced"
    assert "false positive or ignored" in result.summary


def test_history_context_reinforces_confidence_after_true_positive(tmp_path: Path) -> None:
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
    )
    hunter.store.save_commit_metadata(
        repo_name="psf/requests",
        commit_sha="hist002",
        author_name="alice",
        commit_message="confirmed reverse shell",
        html_url=None,
    )
    hunter.store.save_finding(
        "hist002",
        "requests/api.py",
        DetectionResult(
            risk="high",
            confidence=91,
            summary="Older reverse shell.",
            reasons=["launches shell"],
            indicators=["socket", "dup2", "/bin/sh"],
            rule_hits=["reverse-shell-pattern"],
        ),
    )
    hunter.store.update_finding_triage(1, disposition="true_positive", analyst_note="confirmed malicious")

    result = hunter.apply_history_context(
        repo_name="psf/requests",
        file_name="requests/api.py",
        commit_sha="new002",
        result=DetectionResult(
            risk="high",
            confidence=80,
            summary="Current reverse shell.",
            reasons=["launches shell"],
            indicators=["socket", "dup2", "/bin/sh"],
            rule_hits=["reverse-shell-pattern"],
        ),
    )

    assert result.normalized_risk() == "high"
    assert result.confidence == 90
    assert result.history_context["adjustment"] == "reinforced"
    assert "true positive" in result.summary


def test_suppression_rules_reduce_known_safe_pattern(tmp_path: Path) -> None:
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
        suppressions=[
            {
                "id": "trusted-shell-helper",
                "repo": "psf/*",
                "file_pattern": "requests/*.py",
                "rule_hits": ["shell-spawn"],
            }
        ],
    )

    result = hunter.analyze_patch(
        filename="requests/api.py",
        patch_data=FAKE_PATCH,
        commit_sha="supp001",
        repo_name="psf/requests",
    )

    assert result.normalized_risk() == "low"
    assert result.confidence == 25
    assert result.suppression_context["matched_rule_ids"] == ["trusted-shell-helper"]


def test_evaluate_cases_reports_expected_labels(tmp_path: Path) -> None:
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
    )

    results = hunter.evaluate_cases(
        [
            {
                "id": "mal-001",
                "repo_name": "psf/requests",
                "file_name": "requests/api.py",
                "patch": FAKE_PATCH,
                "expected_label": "malicious",
            },
            {
                "id": "ben-001",
                "repo_name": "psf/requests",
                "file_name": "requests/models.py",
                "patch": "+++ b/requests/models.py\n+def ok():\n+    return 'safe'\n",
                "expected_label": "benign",
            },
        ]
    )

    assert len(results) == 2
    assert results[0].passed is True
    assert results[1].passed is True


def test_deliver_alert_writes_jsonl_log(tmp_path: Path) -> None:
    original_path = watchman.ALERTS_LOG_PATH
    original_risk = watchman.ALERT_MIN_RISK
    original_confidence = watchman.ALERT_MIN_CONFIDENCE
    try:
        watchman.ALERTS_LOG_PATH = tmp_path / "alerts.jsonl"
        watchman.ALERT_MIN_RISK = "high"
        watchman.ALERT_MIN_CONFIDENCE = 80

        delivery = deliver_alert(
            repo_name="psf/requests",
            commit_sha="alert001",
            file_name="requests/api.py",
            result=DetectionResult(
                risk="high",
                confidence=95,
                summary="Reverse shell behavior.",
                reasons=["launches shell"],
                indicators=["socket", "/bin/sh"],
                rule_hits=["reverse-shell-pattern"],
            ),
        )

        assert delivery.delivered is True
        assert watchman.ALERTS_LOG_PATH.exists()
        payload = json.loads(watchman.ALERTS_LOG_PATH.read_text(encoding="utf-8").strip())
        assert payload["commit_sha"] == "alert001"
        assert payload["risk"] == "high"
    finally:
        watchman.ALERTS_LOG_PATH = original_path
        watchman.ALERT_MIN_RISK = original_risk
        watchman.ALERT_MIN_CONFIDENCE = original_confidence


def test_deliver_alert_skips_suppressed_findings(tmp_path: Path) -> None:
    original_path = watchman.ALERTS_LOG_PATH
    try:
        watchman.ALERTS_LOG_PATH = tmp_path / "alerts.jsonl"
        delivery = deliver_alert(
            repo_name="psf/requests",
            commit_sha="alert002",
            file_name="requests/api.py",
            result=DetectionResult(
                risk="high",
                confidence=95,
                summary="Suppressed shell helper.",
                suppression_context={"matched_rule_ids": ["trusted-shell-helper"]},
            ),
        )

        assert delivery.delivered is False
        assert watchman.ALERTS_LOG_PATH.exists() is False
    finally:
        watchman.ALERTS_LOG_PATH = original_path
