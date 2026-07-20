import json
import tempfile
from pathlib import Path

import watchman
from storage import infer_backend_name
from testThreat import FAKE_PATCH
from watchman import (
    DetectionResult,
    FindingStore,
    ThreatHunter,
    default_ownership_context,
    deliver_alert,
    load_evaluation_dataset,
    load_suppressions,
    load_watchlist,
)


def ownership(
    team_slug: str = "alpha-team",
    team_name: str = "Alpha Team",
    user_email: str = "analyst@alpha.example",
    user_name: str = "Alpha Analyst",
):
    return default_ownership_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
    )


def build_test_hunter(tmp_path: Path, team_slug: str = "alpha-team") -> ThreatHunter:
    return ThreatHunter(
        github_token="test-token",
        openai_api_key="test-key",
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
        ownership=ownership(team_slug=team_slug, team_name=team_slug.replace("-", " ").title()),
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


def test_finding_store_saves_commit_and_finding_with_team_context(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    team = ownership()
    store.save_commit_metadata(
        ownership=team,
        repo_name="psf/requests",
        commit_sha="abc123",
        author_name="alice",
        commit_message="suspicious change",
        html_url="https://example.com/commit/abc123",
    )
    finding_id = store.save_finding(
        ownership=team,
        repo_name="psf/requests",
        commit_sha="abc123",
        file_name="requests/api.py",
        result=DetectionResult(
            risk="medium",
            confidence=77,
            summary="Suspicious subprocess usage.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            yara_rule="rule suspicious_shell { condition: true }",
            raw_response='{"risk":"medium"}',
            rule_hits=["shell-spawn"],
        ),
    )

    row = store.get_finding(team, finding_id)

    assert row is not None
    assert row["repo_name"] == "psf/requests"
    assert row["commit_sha"] == "abc123"
    assert row["file_name"] == "requests/api.py"
    assert row["risk"] == "medium"
    assert row["confidence"] == 77
    assert json.loads(row["rule_hits_json"]) == ["shell-spawn"]
    assert row["disposition"] == "new"
    assert row["analyst_note"] == ""
    assert json.loads(row["history_context_json"]) == {}
    assert row["team_slug"] == "alpha-team"


def test_store_scopes_same_commit_sha_per_team(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    alpha = ownership(team_slug="alpha", team_name="Alpha", user_email="a@alpha.test", user_name="Alice")
    bravo = ownership(team_slug="bravo", team_name="Bravo", user_email="b@bravo.test", user_name="Bob")

    for team in (alpha, bravo):
        store.save_commit_metadata(
            ownership=team,
            repo_name="psf/requests",
            commit_sha="shared-sha",
            author_name="robot",
            commit_message="same commit in different tenant",
            html_url=None,
        )
        store.save_finding(
            ownership=team,
            repo_name="psf/requests",
            commit_sha="shared-sha",
            file_name="requests/api.py",
            result=DetectionResult(
                risk="high",
                confidence=90,
                summary=f"Finding for {team.team_slug}",
                reasons=["launches shell"],
                indicators=["subprocess", "/bin/sh"],
                rule_hits=["shell-spawn"],
            ),
        )

    alpha_rows = store.list_findings(alpha, limit=10)
    bravo_rows = store.list_findings(bravo, limit=10)

    assert len(alpha_rows) == 1
    assert len(bravo_rows) == 1
    assert alpha_rows[0]["team_slug"] == "alpha"
    assert bravo_rows[0]["team_slug"] == "bravo"
    assert alpha_rows[0]["id"] != bravo_rows[0]["id"]


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


def test_update_finding_triage_sets_disposition_note_and_triager(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    team = ownership()
    store.save_commit_metadata(
        ownership=team,
        repo_name="psf/requests",
        commit_sha="abc124",
        author_name="alice",
        commit_message="another suspicious change",
        html_url="https://example.com/commit/abc124",
    )
    finding_id = store.save_finding(
        ownership=team,
        repo_name="psf/requests",
        commit_sha="abc124",
        file_name="requests/api.py",
        result=DetectionResult(
            risk="high",
            confidence=92,
            summary="High-risk shell execution.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            rule_hits=["shell-spawn"],
        ),
    )

    updated = store.update_finding_triage(
        ownership=team,
        finding_id=finding_id,
        disposition="true_positive",
        analyst_note="Confirmed reverse shell behavior.",
    )

    assert updated is True
    row = store.get_finding(team, finding_id)
    assert row is not None
    assert row["disposition"] == "true_positive"
    assert row["analyst_note"] == "Confirmed reverse shell behavior."
    assert row["triaged_at"] is not None
    assert row["triaged_by_user_email"] == team.user_email


def test_history_context_reduces_risk_after_false_positive(tmp_path: Path) -> None:
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=tmp_path / "findings.db",
        model="gpt-4o",
        ownership=ownership(),
    )
    hunter.store.save_commit_metadata(
        ownership=hunter.ownership,
        repo_name="psf/requests",
        commit_sha="hist001",
        author_name="alice",
        commit_message="older shell pattern",
        html_url=None,
    )
    hunter.store.save_finding(
        ownership=hunter.ownership,
        repo_name="psf/requests",
        commit_sha="hist001",
        file_name="requests/api.py",
        result=DetectionResult(
            risk="high",
            confidence=90,
            summary="Older shell spawn.",
            reasons=["launches shell"],
            indicators=["subprocess", "/bin/sh"],
            rule_hits=["shell-spawn"],
        ),
    )
    hunter.store.update_finding_triage(
        ownership=hunter.ownership,
        finding_id=1,
        disposition="false_positive",
        analyst_note="known admin helper",
    )

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
        ownership=ownership(),
    )
    hunter.store.save_commit_metadata(
        ownership=hunter.ownership,
        repo_name="psf/requests",
        commit_sha="hist002",
        author_name="alice",
        commit_message="confirmed reverse shell",
        html_url=None,
    )
    hunter.store.save_finding(
        ownership=hunter.ownership,
        repo_name="psf/requests",
        commit_sha="hist002",
        file_name="requests/api.py",
        result=DetectionResult(
            risk="high",
            confidence=91,
            summary="Older reverse shell.",
            reasons=["launches shell"],
            indicators=["socket", "dup2", "/bin/sh"],
            rule_hits=["reverse-shell-pattern"],
        ),
    )
    hunter.store.update_finding_triage(
        ownership=hunter.ownership,
        finding_id=1,
        disposition="true_positive",
        analyst_note="confirmed malicious",
    )

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
        ownership=ownership(),
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
        ownership=ownership(),
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
        store = FindingStore(tmp_path / "alerts.db")

        delivery = deliver_alert(
            ownership=ownership(),
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
            store=store,
        )

        assert delivery.delivered is True
        assert watchman.ALERTS_LOG_PATH.exists()
        payload = json.loads(watchman.ALERTS_LOG_PATH.read_text(encoding="utf-8").strip())
        assert payload["commit_sha"] == "alert001"
        assert payload["risk"] == "high"
        assert payload["team_slug"] == "alpha-team"
        deliveries = store.list_alert_deliveries(ownership(), limit=5)
        assert deliveries[0]["channel"] == "log"
        assert deliveries[0]["status"] == "delivered"
    finally:
        watchman.ALERTS_LOG_PATH = original_path
        watchman.ALERT_MIN_RISK = original_risk
        watchman.ALERT_MIN_CONFIDENCE = original_confidence


def test_deliver_alert_skips_suppressed_findings(tmp_path: Path) -> None:
    original_path = watchman.ALERTS_LOG_PATH
    try:
        watchman.ALERTS_LOG_PATH = tmp_path / "alerts.jsonl"
        delivery = deliver_alert(
            ownership=ownership(),
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


def test_infer_backend_name_supports_postgres_urls() -> None:
    assert infer_backend_name("postgresql://watchman:secret@localhost/threathunter", None) == "postgresql"
    assert infer_backend_name(None, Path("security_findings.db")) == "sqlite"


def test_register_and_authenticate_account_creates_owner_membership(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "auth.db")

    record = store.register_account(
        team_slug="blue-team",
        team_name="Blue Team",
        user_email="alice@example.com",
        user_name="Alice",
        password="hunterpass123",
    )

    assert record.team_slug == "blue-team"
    assert record.user_email == "alice@example.com"

    authenticated = store.authenticate_account(
        team_slug="blue-team",
        user_email="alice@example.com",
        password="hunterpass123",
    )

    assert authenticated is not None
    assert authenticated.team_slug == "blue-team"
    assert authenticated.user_name == "Alice"


def test_register_account_rejects_existing_team_slug(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "auth.db")
    store.register_account(
        team_slug="blue-team",
        team_name="Blue Team",
        user_email="alice@example.com",
        user_name="Alice",
        password="hunterpass123",
    )

    try:
        store.register_account(
            team_slug="blue-team",
            team_name="Blue Team 2",
            user_email="bob@example.com",
            user_name="Bob",
            password="hunterpass123",
        )
    except ValueError as exc:
        assert "already in use" in str(exc)
    else:
        raise AssertionError("Expected team slug collision to fail")


def test_repo_watchlist_add_and_deactivate(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "watchlists.db")
    team = ownership(team_slug="ops", team_name="Ops Team", user_email="ops@example.com", user_name="Olive")
    store.register_account(
        team_slug=team.team_slug,
        team_name=team.team_name,
        user_email=team.user_email,
        user_name=team.user_name,
        password="hunterpass123",
    )

    first = store.add_repo_watchlist(team, "psf/requests")
    second = store.add_repo_watchlist(team, "pallets/flask")
    rows = store.list_repo_watchlists(team)

    assert [row["repo_name"] for row in rows] == ["pallets/flask", "psf/requests"]
    assert first["id"] != second["id"]

    updated = store.deactivate_repo_watchlist(team, first["id"])
    assert updated is True
    active_rows = store.list_repo_watchlists(team)
    all_rows = store.list_repo_watchlists(team, include_inactive=True)
    assert [row["repo_name"] for row in active_rows] == ["pallets/flask"]
    assert len(all_rows) == 2


def test_team_settings_update_and_scan_runs(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "operations.db")
    team = ownership(team_slug="ops", team_name="Ops Team", user_email="ops@example.com", user_name="Olive")
    store.register_account(
        team_slug=team.team_slug,
        team_name=team.team_name,
        user_email=team.user_email,
        user_name=team.user_name,
        password="hunterpass123",
    )
    watchlist = store.add_repo_watchlist(team, "psf/requests")

    initial = store.get_team_settings(team)
    assert initial["alert_min_risk"] == "high"
    assert initial["scan_limit"] >= 1

    updated = store.update_team_settings(
        team,
        alert_webhook_url="https://hooks.example.test/alerts",
        alert_min_risk="medium",
        alert_min_confidence=65,
        scans_enabled=False,
        scan_limit=7,
        scan_interval_minutes=45,
    )
    assert updated["alert_webhook_url"] == "https://hooks.example.test/alerts"
    assert updated["alert_min_risk"] == "medium"
    assert updated["alert_min_confidence"] == 65
    assert updated["scans_enabled"] is False
    assert updated["scan_limit"] == 7
    assert updated["scan_interval_minutes"] == 45

    scan_run_id = store.create_scan_run(team, watchlist["id"], "psf/requests", "manual")
    completed = store.complete_scan_run(
        team,
        scan_run_id,
        status="completed",
        findings_created=3,
        high_risk_findings=1,
    )
    assert completed is True

    runs = store.list_scan_runs(team, limit=5)
    assert runs[0]["id"] == scan_run_id
    assert runs[0]["status"] == "completed"
    assert runs[0]["findings_created"] == 3
    assert runs[0]["high_risk_findings"] == 1
    assert runs[0]["lock_expires_at"] is None

    target = store.list_scan_targets(team_slug="ops")[0]
    assert target["repo_name"] == "psf/requests"
    assert target["scans_enabled"] is False
    assert target["scan_limit"] == 7
    assert target["scan_interval_minutes"] == 45

    watchlist_row = store.get_repo_watchlist(team, watchlist["id"])
    assert watchlist_row is not None
    assert watchlist_row["last_successful_scan_at"] is not None
    assert watchlist_row["next_scan_at"] is not None
    assert watchlist_row["last_scan_error"] == ""


def test_claim_scan_run_blocks_overlap_until_completion(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "scan-locks.db")
    team = ownership(team_slug="ops", team_name="Ops Team", user_email="ops@example.com", user_name="Olive")
    store.register_account(
        team_slug=team.team_slug,
        team_name=team.team_name,
        user_email=team.user_email,
        user_name=team.user_name,
        password="hunterpass123",
    )
    watchlist = store.add_repo_watchlist(team, "psf/requests")

    first = store.claim_scan_run(team, watchlist["id"], "psf/requests", "manual")
    second = store.claim_scan_run(team, watchlist["id"], "psf/requests", "manual")

    assert first is not None
    assert second is None

    completed = store.complete_scan_run(team, int(first["id"]), status="completed")
    assert completed is True

    third = store.claim_scan_run(team, watchlist["id"], "psf/requests", "manual")
    assert third is not None
