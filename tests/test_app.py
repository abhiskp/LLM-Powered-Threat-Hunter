from pathlib import Path

import app as threat_app
import watchman
from fastapi.testclient import TestClient


def register_team(client: TestClient, team_slug: str, team_name: str, user_email: str, user_name: str) -> None:
    response = client.post(
        "/auth/register",
        data={
            "team_slug": team_slug,
            "team_name": team_name,
            "user_email": user_email,
            "user_name": user_name,
            "password": "hunterpass123",
            "first_repo": "psf/requests",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_login_required_and_team_dashboard_flow(tmp_path: Path) -> None:
    db_path = tmp_path / "dashboard.db"
    alert_path = tmp_path / "alerts.jsonl"

    original_db = watchman.DATABASE_PATH
    original_alert_path = watchman.ALERTS_LOG_PATH
    original_app_db = threat_app.DATABASE_PATH
    original_app_alert = threat_app.ALERTS_LOG_PATH
    try:
        watchman.DATABASE_PATH = db_path
        watchman.ALERTS_LOG_PATH = alert_path
        threat_app.DATABASE_PATH = db_path
        threat_app.ALERTS_LOG_PATH = alert_path

        anonymous = TestClient(threat_app.app)
        redirect = anonymous.get("/", follow_redirects=False)
        assert redirect.status_code == 303
        assert redirect.headers["location"] == "/login"

        client = TestClient(threat_app.app)
        register_team(client, "alpha", "Alpha Team", "alpha@example.com", "Alice")

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "Alpha Team" in dashboard.text
        assert "psf/requests" in dashboard.text

        session = client.get("/api/session")
        assert session.status_code == 200
        payload = session.json()
        assert payload["session"]["team_slug"] == "alpha"
        assert payload["watchlist"][0]["repo_name"] == "psf/requests"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_watchlist_and_findings_are_scoped_by_authenticated_team(tmp_path: Path) -> None:
    db_path = tmp_path / "scoped.db"
    alert_path = tmp_path / "alerts.jsonl"

    original_db = watchman.DATABASE_PATH
    original_alert_path = watchman.ALERTS_LOG_PATH
    original_app_db = threat_app.DATABASE_PATH
    original_app_alert = threat_app.ALERTS_LOG_PATH
    try:
        watchman.DATABASE_PATH = db_path
        watchman.ALERTS_LOG_PATH = alert_path
        threat_app.DATABASE_PATH = db_path
        threat_app.ALERTS_LOG_PATH = alert_path

        alpha = TestClient(threat_app.app)
        register_team(alpha, "alpha", "Alpha Team", "alpha@example.com", "Alice")
        alpha.post("/api/demo/test-scan")
        alpha.post("/api/watchlist", data={"repo_name": "pallets/flask"})

        bravo = TestClient(threat_app.app)
        register_team(bravo, "bravo", "Bravo Team", "bravo@example.com", "Bob")
        bravo.post("/api/demo/test-scan")

        alpha_findings = alpha.get("/api/findings")
        bravo_findings = bravo.get("/api/findings")
        assert alpha_findings.status_code == 200
        assert bravo_findings.status_code == 200
        assert len(alpha_findings.json()["findings"]) == 1
        assert len(bravo_findings.json()["findings"]) == 1
        assert alpha_findings.json()["findings"][0]["team_slug"] == "alpha"
        assert bravo_findings.json()["findings"][0]["team_slug"] == "bravo"

        alpha_watchlist = alpha.get("/api/watchlist").json()["watchlist"]
        bravo_watchlist = bravo.get("/api/watchlist").json()["watchlist"]
        assert [row["repo_name"] for row in alpha_watchlist] == ["pallets/flask", "psf/requests"]
        assert [row["repo_name"] for row in bravo_watchlist] == ["psf/requests"]

        finding_id = alpha_findings.json()["findings"][0]["id"]
        triage = alpha.post(
            f"/api/findings/{finding_id}/triage",
            data={"disposition": "true_positive", "note": "Confirmed in API test"},
        )
        assert triage.status_code == 200

        updated = alpha.get(f"/api/findings/{finding_id}")
        assert updated.status_code == 200
        assert updated.json()["finding"]["triaged_by_user_email"] == "alpha@example.com"
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert


def test_login_and_logout_cycle(tmp_path: Path) -> None:
    db_path = tmp_path / "auth.db"
    alert_path = tmp_path / "alerts.jsonl"

    original_db = watchman.DATABASE_PATH
    original_alert_path = watchman.ALERTS_LOG_PATH
    original_app_db = threat_app.DATABASE_PATH
    original_app_alert = threat_app.ALERTS_LOG_PATH
    try:
        watchman.DATABASE_PATH = db_path
        watchman.ALERTS_LOG_PATH = alert_path
        threat_app.DATABASE_PATH = db_path
        threat_app.ALERTS_LOG_PATH = alert_path

        bootstrap = TestClient(threat_app.app)
        register_team(bootstrap, "soc", "SOC Team", "soc@example.com", "Sam SOC")

        client = TestClient(threat_app.app)
        login = client.post(
            "/auth/login",
            data={
                "team_slug": "soc",
                "user_email": "soc@example.com",
                "password": "hunterpass123",
            },
            follow_redirects=False,
        )
        assert login.status_code == 303

        assert client.get("/api/session").status_code == 200

        logout = client.post("/auth/logout", follow_redirects=False)
        assert logout.status_code == 303
        assert client.get("/api/session").status_code == 401
    finally:
        watchman.DATABASE_PATH = original_db
        watchman.ALERTS_LOG_PATH = original_alert_path
        threat_app.DATABASE_PATH = original_app_db
        threat_app.ALERTS_LOG_PATH = original_app_alert
