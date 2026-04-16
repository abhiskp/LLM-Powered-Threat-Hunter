import json
import tempfile
from pathlib import Path

import watchman
from watchman import DetectionResult, FindingStore, ThreatHunter


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
            "yara_rule": "rule reverse_shell { condition: true }",
        }
    )

    parsed = hunter._parse_detection_payload(payload)

    assert parsed["risk"] == "high"
    assert parsed["confidence"] == 100
    assert parsed["summary"] == "Reverse shell behavior detected."
    assert parsed["reasons"] == ["spawns shell", "opens outbound socket"]
    assert parsed["indicators"] == ["socket", "/bin/sh"]


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
    )

    store.save_finding("abc123", "requests/api.py", result)

    with store._connect() as connection:
        commit = connection.execute("SELECT repo_name, commit_sha FROM commits").fetchone()
        finding = connection.execute(
            "SELECT file_name, risk, confidence, summary FROM findings"
        ).fetchone()

    assert commit["repo_name"] == "psf/requests"
    assert commit["commit_sha"] == "abc123"
    assert finding["file_name"] == "requests/api.py"
    assert finding["risk"] == "medium"
    assert finding["confidence"] == 77


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
