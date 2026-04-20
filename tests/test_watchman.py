import json
import tempfile
from pathlib import Path

import watchman
from testThreat import FAKE_PATCH
from watchman import DetectionResult, FindingStore, ThreatHunter, load_watchlist


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
            "SELECT file_name, risk, confidence, summary, rule_hits_json, disposition, analyst_note FROM findings"
        ).fetchone()

    assert commit["repo_name"] == "psf/requests"
    assert commit["commit_sha"] == "abc123"
    assert finding["file_name"] == "requests/api.py"
    assert finding["risk"] == "medium"
    assert finding["confidence"] == 77
    assert json.loads(finding["rule_hits_json"]) == ["shell-spawn"]
    assert finding["disposition"] == "new"
    assert finding["analyst_note"] == ""


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
