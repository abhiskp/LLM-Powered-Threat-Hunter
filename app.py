import json
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from auth import SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS, create_session_cookie, parse_session_cookie
from storage import OwnershipRecord
from testThreat import FAKE_PATCH
from watchman import (
    ALERTS_LOG_PATH,
    AlertDeliveryService,
    DATABASE_PATH,
    DATABASE_URL,
    BackgroundScanService,
    DEFAULT_MODEL,
    DEFAULT_TARGET_REPO,
    VALID_DISPOSITIONS,
    FindingStore,
    OwnershipContext,
    ThreatHunter,
    deliver_alert,
    load_suppressions,
)


app = FastAPI(title="Threat Hunter Analyst Inbox", version="0.2.0")


def get_store() -> FindingStore:
    return FindingStore(db_path=DATABASE_PATH, database_url=DATABASE_URL)


def get_scan_service(store: Optional[FindingStore] = None) -> BackgroundScanService:
    return BackgroundScanService(store=store or get_store())


def get_delivery_service(store: Optional[FindingStore] = None) -> AlertDeliveryService:
    return AlertDeliveryService(store=store or get_store())


def record_to_ownership(record: OwnershipRecord) -> OwnershipContext:
    return OwnershipContext(
        team_slug=record.team_slug,
        team_name=record.team_name,
        user_email=record.user_email,
        user_name=record.user_name,
    )


def get_authenticated_record(request: Request, store: Optional[FindingStore] = None) -> OwnershipRecord:
    active_store = store or get_store()
    payload = parse_session_cookie(request.cookies.get(SESSION_COOKIE_NAME))
    if payload is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    record = active_store.get_membership(
        team_slug=str(payload["team_slug"]),
        user_email=str(payload["user_email"]),
    )
    if record is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    return record


def get_optional_record(request: Request, store: Optional[FindingStore] = None) -> Optional[OwnershipRecord]:
    try:
        return get_authenticated_record(request, store=store)
    except HTTPException:
        return None


def row_to_summary(row: Any) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "team_slug": row["team_slug"],
        "team_name": row["team_name"],
        "repo_name": row["repo_name"],
        "commit_sha": row["commit_sha"],
        "file_name": row["file_name"],
        "risk": row["risk"],
        "confidence": row["confidence"],
        "summary": row["summary"],
        "created_at": row["created_at"],
        "disposition": row["disposition"],
        "rule_hits": json.loads(row["rule_hits_json"] or "[]"),
        "history_context": json.loads(row["history_context_json"] or "{}"),
        "suppression_context": json.loads(row["suppression_context_json"] or "{}"),
    }


def row_to_detail(row: Any) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "team_slug": row["team_slug"],
        "team_name": row["team_name"],
        "repo_name": row["repo_name"],
        "commit_sha": row["commit_sha"],
        "author_name": row["author_name"],
        "commit_message": row["commit_message"],
        "html_url": row["html_url"],
        "file_name": row["file_name"],
        "risk": row["risk"],
        "confidence": row["confidence"],
        "summary": row["summary"],
        "reasons": json.loads(row["reasons_json"] or "[]"),
        "indicators": json.loads(row["indicators_json"] or "[]"),
        "rule_hits": json.loads(row["rule_hits_json"] or "[]"),
        "history_context": json.loads(row["history_context_json"] or "{}"),
        "suppression_context": json.loads(row["suppression_context_json"] or "{}"),
        "disposition": row["disposition"],
        "analyst_note": row["analyst_note"],
        "triaged_at": row["triaged_at"],
        "triaged_by_user_email": row.get("triaged_by_user_email"),
        "triaged_by_user_name": row.get("triaged_by_user_name"),
        "created_at": row["created_at"],
        "yara_rule": row["yara_rule"],
    }


def team_settings_to_payload(settings: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_webhook_url": settings.get("alert_webhook_url") or "",
        "alert_min_risk": settings.get("alert_min_risk", "high"),
        "alert_min_confidence": int(settings.get("alert_min_confidence", 80)),
        "scans_enabled": bool(settings.get("scans_enabled", True)),
        "scan_limit": int(settings.get("scan_limit", 3)),
        "scan_interval_minutes": int(settings.get("scan_interval_minutes", 60)),
        "updated_at": settings.get("updated_at"),
    }


def scan_run_to_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "repo_watchlist_id": row["repo_watchlist_id"],
        "repo_name": row["repo_name"],
        "trigger_mode": row["trigger_mode"],
        "status": row["status"],
        "started_at": row["started_at"],
        "lock_expires_at": row.get("lock_expires_at"),
        "completed_at": row["completed_at"],
        "error_message": row["error_message"],
        "findings_created": row["findings_created"],
        "high_risk_findings": row["high_risk_findings"],
    }


def alert_delivery_to_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "destination_id": row.get("destination_id"),
        "repo_name": row["repo_name"],
        "commit_sha": row["commit_sha"],
        "file_name": row["file_name"],
        "channel": row["channel"],
        "destination": row["destination"],
        "status": row["status"],
        "attempt_number": int(row["attempt_number"]),
        "next_attempt_at": row.get("next_attempt_at"),
        "delivered_at": row.get("delivered_at"),
        "error_message": row["error_message"],
        "created_at": row["created_at"],
        "updated_at": row.get("updated_at"),
    }


def alert_destination_to_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "target_url": row["target_url"],
        "is_active": bool(row["is_active"]),
        "last_tested_at": row.get("last_tested_at"),
        "last_error": row.get("last_error") or "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def load_alert_inbox(team_slug: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    if not ALERTS_LOG_PATH.exists():
        return []

    lines = ALERTS_LOG_PATH.read_text(encoding="utf-8").splitlines()
    alerts: List[Dict[str, Any]] = []
    for line in reversed(lines):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if team_slug and payload.get("team_slug") != team_slug:
            continue
        alerts.append(payload)
        if len(alerts) >= limit:
            break
    return alerts


def render_login_html(message: Optional[str] = None) -> str:
    banner = ""
    if message:
        banner = f"<p class='banner'>{escape(message)}</p>"
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Threat Hunter Login</title>
      <style>
        :root {{
          --bg: #f2efe8;
          --paper: #fffdf8;
          --ink: #181613;
          --muted: #6c665a;
          --line: #d8d0c3;
          --accent: #9e4024;
          --accent-soft: #f7e1d7;
          --shadow: 0 18px 44px rgba(41, 29, 12, 0.08);
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: Georgia, "Iowan Old Style", serif;
          color: var(--ink);
          background:
            radial-gradient(circle at top left, #f6d9cb 0, transparent 28%),
            radial-gradient(circle at bottom right, #dfe8d7 0, transparent 22%),
            var(--bg);
        }}
        .shell {{
          min-height: 100vh;
          display: grid;
          place-items: center;
          padding: 24px;
        }}
        .layout {{
          width: min(1120px, 100%);
          display: grid;
          grid-template-columns: 1.1fr 0.9fr;
          gap: 24px;
        }}
        .hero, .card {{
          background: var(--paper);
          border: 1px solid var(--line);
          border-radius: 24px;
          box-shadow: var(--shadow);
        }}
        .hero {{
          padding: 32px;
          background: linear-gradient(140deg, #fff7ee, #fbfaf6 65%);
        }}
        .hero h1 {{ margin: 0 0 12px; font-size: 2.5rem; }}
        .hero p {{ margin: 0 0 16px; color: var(--muted); max-width: 56ch; }}
        .card {{
          padding: 24px;
          display: grid;
          gap: 20px;
        }}
        h2 {{ margin: 0 0 10px; font-size: 1.2rem; }}
        form {{
          display: grid;
          gap: 12px;
        }}
        label {{
          font-size: 0.95rem;
          color: var(--muted);
          display: grid;
          gap: 6px;
        }}
        input, button {{
          font: inherit;
          border-radius: 12px;
          border: 1px solid var(--line);
          padding: 11px 13px;
          background: white;
          color: var(--ink);
        }}
        button {{
          border: none;
          background: var(--accent);
          color: white;
          cursor: pointer;
        }}
        .banner {{
          margin: 0;
          padding: 12px 14px;
          border-radius: 12px;
          background: var(--accent-soft);
          color: var(--accent);
        }}
        .split {{
          display: grid;
          gap: 16px;
          grid-template-columns: 1fr;
        }}
        .facts {{
          display: grid;
          gap: 10px;
          color: var(--muted);
        }}
        @media (max-width: 960px) {{
          .layout {{ grid-template-columns: 1fr; }}
          .hero {{ padding: 24px; }}
          .card {{ padding: 20px; }}
        }}
      </style>
    </head>
    <body>
      <div class="shell">
        <div class="layout">
          <section class="hero">
            <h1>Threat Hunter</h1>
            <p>Turn GitHub commit analysis into a real team workflow. Sign in to review findings, onboard watched repos, and triage suspicious diffs in a scoped team workspace.</p>
            <div class="facts">
              <div>Real session cookies instead of caller-provided identity headers.</div>
              <div>Team-scoped findings and watchlists backed by SQLite or PostgreSQL.</div>
              <div>Product-ready path for onboarding, alert routing, and background scanning.</div>
            </div>
          </section>
          <section class="card">
            {banner}
            <div class="split">
              <div>
                <h2>Sign In</h2>
                <form method="post" action="/auth/login">
                  <label>Team Slug<input type="text" name="team_slug" placeholder="blue-team" required /></label>
                  <label>Email<input type="email" name="user_email" placeholder="analyst@company.com" required /></label>
                  <label>Password<input type="password" name="password" required /></label>
                  <button type="submit">Sign In</button>
                </form>
              </div>
              <div>
                <h2>Create Team</h2>
                <form method="post" action="/auth/register">
                  <label>Team Name<input type="text" name="team_name" placeholder="Blue Team" required /></label>
                  <label>Team Slug<input type="text" name="team_slug" placeholder="blue-team" required /></label>
                  <label>Your Name<input type="text" name="user_name" placeholder="Alex Analyst" required /></label>
                  <label>Email<input type="email" name="user_email" placeholder="alex@company.com" required /></label>
                  <label>Password<input type="password" name="password" required /></label>
                  <label>First Repo (Optional)<input type="text" name="first_repo" placeholder="owner/repo" /></label>
                  <button type="submit">Create Team Workspace</button>
                </form>
              </div>
            </div>
          </section>
        </div>
      </div>
    </body>
    </html>
    """


def render_dashboard_html(
    findings: List[Dict[str, Any]],
    selected_finding: Optional[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    alert_deliveries: List[Dict[str, Any]],
    alert_destinations: List[Dict[str, Any]],
    watchlist: List[Dict[str, Any]],
    team_settings: Dict[str, Any],
    scan_runs: List[Dict[str, Any]],
    filters: Dict[str, str],
    session: Dict[str, str],
    backend_name: str,
) -> str:
    selected_panel = "<p class='muted'>Select a finding to inspect its full context.</p>"
    if selected_finding:
        reasons = "".join(f"<li>{escape(reason)}</li>" for reason in selected_finding["reasons"])
        indicators = "".join(f"<li>{escape(indicator)}</li>" for indicator in selected_finding["indicators"])
        rule_hits = ", ".join(selected_finding["rule_hits"]) or "None"
        history_note = selected_finding["history_context"].get("note", "None")
        suppression_note = selected_finding["suppression_context"].get("note", "None")
        triaged_by = selected_finding["triaged_by_user_name"] or selected_finding["triaged_by_user_email"] or "None"
        yara_block = ""
        if selected_finding["yara_rule"]:
            yara_block = "<h4>YARA</h4>" f"<pre>{escape(selected_finding['yara_rule'])}</pre>"
        selected_panel = f"""
        <div class="detail-card">
          <h3>Finding #{selected_finding['id']}</h3>
          <p><strong>Repo:</strong> {escape(selected_finding['repo_name'])}</p>
          <p><strong>Commit:</strong> {escape(selected_finding['commit_sha'])}</p>
          <p><strong>File:</strong> {escape(selected_finding['file_name'])}</p>
          <p><strong>Risk:</strong> {escape(selected_finding['risk'])} ({selected_finding['confidence']}%)</p>
          <p><strong>Disposition:</strong> {escape(selected_finding['disposition'])}</p>
          <p><strong>Triaged By:</strong> {escape(triaged_by)}</p>
          <p><strong>Summary:</strong> {escape(selected_finding['summary'])}</p>
          <p><strong>Rule Hits:</strong> {escape(rule_hits)}</p>
          <p><strong>History:</strong> {escape(history_note)}</p>
          <p><strong>Suppression:</strong> {escape(suppression_note)}</p>
          <p><strong>Analyst Note:</strong> {escape(selected_finding['analyst_note'] or 'None')}</p>
          <h4>Reasons</h4>
          <ul>{reasons or '<li>None</li>'}</ul>
          <h4>Indicators</h4>
          <ul>{indicators or '<li>None</li>'}</ul>
          {yara_block}
          <form method="post" action="/findings/{selected_finding['id']}/triage" class="triage-form">
            <label>Disposition</label>
            <select name="disposition">
              {''.join(f"<option value='{value}' {'selected' if selected_finding['disposition'] == value else ''}>{value}</option>" for value in sorted(VALID_DISPOSITIONS))}
            </select>
            <label>Analyst Note</label>
            <textarea name="note" rows="4">{escape(selected_finding['analyst_note'] or '')}</textarea>
            <button type="submit">Update Finding</button>
          </form>
        </div>
        """

    finding_rows = ""
    for finding in findings:
        finding_rows += f"""
        <tr>
          <td><a href="/?finding_id={finding['id']}">{finding['id']}</a></td>
          <td>{escape(finding['risk'])}</td>
          <td>{finding['confidence']}%</td>
          <td>{escape(finding['disposition'])}</td>
          <td>{escape(finding['repo_name'])}</td>
          <td>{escape(finding['file_name'])}</td>
          <td>{escape(finding['summary'])}</td>
        </tr>
        """

    watchlist_rows = ""
    for item in watchlist:
        watchlist_rows += f"""
        <tr>
          <td>{escape(item['repo_name'])}</td>
          <td>{'active' if item['is_active'] else 'inactive'}</td>
          <td>{escape(item['last_scanned_at'] or 'never')}</td>
          <td>{escape(item.get('next_scan_at') or 'due now')}</td>
          <td>{escape(item.get('last_scan_error') or 'healthy')}</td>
          <td>
            <div class="inline-form">
              <form method="post" action="/watchlist/{item['id']}/scan-now">
                <button type="submit" class="small">Scan Now</button>
              </form>
              <form method="post" action="/watchlist/{item['id']}/deactivate">
                <button type="submit" class="small danger">Deactivate</button>
              </form>
            </div>
          </td>
        </tr>
        """

    delivery_rows = ""
    for delivery in alert_deliveries:
        delivery_rows += f"""
        <tr>
          <td>{escape(delivery['created_at'])}</td>
          <td>{escape(delivery.get('destination') or '')}</td>
          <td>{escape(delivery['repo_name'])}</td>
          <td>{escape(delivery['channel'])}</td>
          <td>{escape(delivery['status'])}</td>
          <td>{delivery['attempt_number']}</td>
          <td>{escape(delivery['error_message'] or '')}</td>
        </tr>
        """

    destination_rows = ""
    for destination in alert_destinations:
        destination_rows += f"""
        <tr>
          <td>{escape(destination['name'])}</td>
          <td>{escape(destination['kind'])}</td>
          <td>{escape(destination['target_url'])}</td>
          <td>{escape(destination.get('last_tested_at') or 'never')}</td>
          <td>{escape(destination.get('last_error') or 'healthy')}</td>
          <td>
            <div class="inline-form">
              <form method="post" action="/alert-destinations/{destination['id']}/test">
                <button type="submit" class="small">Send Test</button>
              </form>
              <form method="post" action="/alert-destinations/{destination['id']}/deactivate">
                <button type="submit" class="small danger">Deactivate</button>
              </form>
            </div>
          </td>
        </tr>
        """

    alert_rows = ""
    for alert in alerts:
        alert_rows += f"""
        <tr>
          <td>{escape(alert.get('created_at', ''))}</td>
          <td>{escape(alert.get('risk', ''))}</td>
          <td>{escape(alert.get('repo_name', ''))}</td>
          <td>{escape(alert.get('file_name', ''))}</td>
          <td>{escape(alert.get('summary', ''))}</td>
        </tr>
        """

    scan_run_rows = ""
    for run in scan_runs:
        scan_run_rows += f"""
        <tr>
          <td>{escape(run['started_at'])}</td>
          <td>{escape(run['repo_name'])}</td>
          <td>{escape(run['status'])}</td>
          <td>{escape(run['trigger_mode'])}</td>
          <td>{escape(run.get('lock_expires_at') or '')}</td>
          <td>{run['findings_created']}</td>
          <td>{run['high_risk_findings']}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Threat Hunter Analyst Inbox</title>
      <style>
        :root {{
          --bg: #f6f3ee;
          --paper: #fffdf8;
          --ink: #1b1a17;
          --muted: #6b655b;
          --line: #d8d1c5;
          --accent: #b44b2a;
          --accent-soft: #f1d5cc;
          --danger: #8f2d20;
          --shadow: 0 18px 40px rgba(42, 30, 12, 0.08);
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: Georgia, "Iowan Old Style", serif;
          color: var(--ink);
          background:
            radial-gradient(circle at top left, #f8e5d9 0, transparent 28%),
            radial-gradient(circle at bottom right, #e5ecde 0, transparent 24%),
            var(--bg);
        }}
        .shell {{ max-width: 1440px; margin: 0 auto; padding: 28px; }}
        .hero {{
          background: linear-gradient(135deg, #fff5ed, #fbfaf6 65%);
          border: 1px solid var(--line);
          border-radius: 24px;
          padding: 28px;
          box-shadow: var(--shadow);
          margin-bottom: 24px;
        }}
        .hero h1 {{ margin: 0 0 8px; font-size: 2rem; }}
        .hero p {{ margin: 0; color: var(--muted); max-width: 65ch; }}
        .meta {{
          margin-top: 14px;
          color: var(--muted);
          display: flex;
          flex-wrap: wrap;
          gap: 14px;
        }}
        .actions {{
          margin-top: 18px;
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          align-items: center;
        }}
        .actions form, .filters {{
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          align-items: center;
        }}
        input, select, textarea, button {{
          font: inherit;
          border-radius: 12px;
          border: 1px solid var(--line);
          padding: 10px 12px;
          background: var(--paper);
          color: var(--ink);
        }}
        button {{
          background: var(--accent);
          color: white;
          border: none;
          cursor: pointer;
        }}
        .small {{ padding: 8px 10px; font-size: 0.9rem; }}
        .danger {{ background: var(--danger); }}
        .layout {{
          display: grid;
          grid-template-columns: 1.1fr 0.9fr;
          gap: 24px;
        }}
        .stack {{ display: grid; gap: 24px; }}
        .panel {{
          background: var(--paper);
          border: 1px solid var(--line);
          border-radius: 20px;
          box-shadow: var(--shadow);
          overflow: hidden;
        }}
        .panel-header {{
          padding: 18px 20px;
          border-bottom: 1px solid var(--line);
          background: rgba(255,255,255,0.7);
        }}
        .panel-body {{ padding: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{
          padding: 12px 10px;
          text-align: left;
          border-bottom: 1px solid var(--line);
          vertical-align: top;
        }}
        th {{ color: var(--muted); font-weight: 600; }}
        a {{ color: var(--accent); text-decoration: none; }}
        .muted {{ color: var(--muted); }}
        .detail-card pre {{
          white-space: pre-wrap;
          background: #1f1c18;
          color: #f6efe4;
          padding: 14px;
          border-radius: 14px;
          overflow-x: auto;
        }}
        .triage-form, .watchlist-form {{
          display: grid;
          gap: 10px;
          margin-top: 18px;
        }}
        .inline-form {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
        .inbox-table td:first-child, .watchlist-table td:first-child {{ white-space: nowrap; }}
        .topbar {{
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: flex-start;
        }}
        @media (max-width: 980px) {{
          .layout {{ grid-template-columns: 1fr; }}
          .shell {{ padding: 16px; }}
          .hero {{ padding: 20px; }}
          .topbar {{ flex-direction: column; }}
        }}
      </style>
    </head>
    <body>
      <div class="shell">
        <section class="hero">
          <div class="topbar">
            <div>
              <h1>Threat Hunter Analyst Inbox</h1>
              <p>Review suspicious commit diffs, onboard watched repos, and keep the team’s detection workflow in one authenticated workspace.</p>
              <div class="meta">
                <span><strong>Team:</strong> {escape(session['team_name'])} ({escape(session['team_slug'])})</span>
                <span><strong>Analyst:</strong> {escape(session['user_name'])} ({escape(session['user_email'])})</span>
                <span><strong>Store:</strong> {escape(backend_name)}</span>
              </div>
            </div>
            <form method="post" action="/auth/logout">
              <button type="submit" class="small">Sign Out</button>
            </form>
          </div>
          <div class="actions">
            <form method="post" action="/demo/test-scan">
              <button type="submit">Run Synthetic Demo Scan</button>
            </form>
            <form method="post" action="/scans/run-cycle">
              <button type="submit">Run Team Scan Cycle</button>
            </form>
            <form method="post" action="/alerts/process-queue">
              <button type="submit">Run Delivery Queue</button>
            </form>
            <form method="get" action="/" class="filters">
              <select name="risk">
                <option value="">All risks</option>
                <option value="high" {'selected' if filters.get('risk') == 'high' else ''}>high</option>
                <option value="medium" {'selected' if filters.get('risk') == 'medium' else ''}>medium</option>
                <option value="low" {'selected' if filters.get('risk') == 'low' else ''}>low</option>
              </select>
              <select name="disposition">
                <option value="">All dispositions</option>
                {''.join(f"<option value='{value}' {'selected' if filters.get('disposition') == value else ''}>{value}</option>" for value in sorted(VALID_DISPOSITIONS))}
              </select>
              <input type="number" min="1" max="200" name="limit" value="{filters.get('limit', '25')}" />
              <button type="submit">Apply Filters</button>
            </form>
          </div>
        </section>

        <div class="layout">
          <section class="panel">
            <div class="panel-header"><strong>Findings</strong></div>
            <div class="panel-body">
              <table>
                <thead>
                  <tr>
                    <th>ID</th><th>Risk</th><th>Confidence</th><th>Disposition</th><th>Repo</th><th>File</th><th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {finding_rows or "<tr><td colspan='7' class='muted'>No findings yet.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>

          <div class="stack">
            <section class="panel">
              <div class="panel-header"><strong>Finding Detail</strong></div>
              <div class="panel-body">
                {selected_panel}
              </div>
            </section>
            <section class="panel">
              <div class="panel-header"><strong>Team Settings</strong></div>
              <div class="panel-body">
                <form method="post" action="/settings" class="watchlist-form">
                  <label>Alert Webhook URL<input type="url" name="alert_webhook_url" value="{escape(team_settings.get('alert_webhook_url', ''))}" placeholder="https://hooks.slack.com/services/..." /></label>
                  <label>Minimum Alert Risk
                    <select name="alert_min_risk">
                      <option value="high" {'selected' if team_settings.get('alert_min_risk') == 'high' else ''}>high</option>
                      <option value="medium" {'selected' if team_settings.get('alert_min_risk') == 'medium' else ''}>medium</option>
                      <option value="low" {'selected' if team_settings.get('alert_min_risk') == 'low' else ''}>low</option>
                    </select>
                  </label>
                  <label>Minimum Alert Confidence<input type="number" min="0" max="100" name="alert_min_confidence" value="{team_settings.get('alert_min_confidence', 80)}" /></label>
                  <label>Scan Limit Per Repo<input type="number" min="1" max="50" name="scan_limit" value="{team_settings.get('scan_limit', 3)}" /></label>
                  <label>Scan Interval Minutes<input type="number" min="1" max="10080" name="scan_interval_minutes" value="{team_settings.get('scan_interval_minutes', 60)}" /></label>
                  <label>Scanning Enabled
                    <select name="scans_enabled">
                      <option value="true" {'selected' if team_settings.get('scans_enabled', True) else ''}>true</option>
                      <option value="false" {'selected' if not team_settings.get('scans_enabled', True) else ''}>false</option>
                    </select>
                  </label>
                  <button type="submit">Save Team Settings</button>
                </form>
              </div>
            </section>
            <section class="panel">
              <div class="panel-header"><strong>Repo Watchlist</strong></div>
              <div class="panel-body">
                <form method="post" action="/watchlist" class="watchlist-form">
                  <label>Repository<input type="text" name="repo_name" placeholder="owner/repo" required /></label>
                  <button type="submit">Add Repo</button>
                </form>
                <table class="watchlist-table" style="margin-top: 18px;">
                  <thead>
                    <tr><th>Repo</th><th>Status</th><th>Last Scanned</th><th>Next Scan</th><th>Last Error</th><th></th></tr>
                  </thead>
                  <tbody>
                    {watchlist_rows or "<tr><td colspan='6' class='muted'>No watched repos yet.</td></tr>"}
                  </tbody>
                </table>
              </div>
            </section>
            <section class="panel">
              <div class="panel-header"><strong>Alert Destinations</strong></div>
              <div class="panel-body">
                <form method="post" action="/alert-destinations" class="watchlist-form">
                  <label>Destination Name<input type="text" name="name" placeholder="Primary Slack" required /></label>
                  <label>Destination Type
                    <select name="kind">
                      <option value="slack_webhook">slack_webhook</option>
                    </select>
                  </label>
                  <label>Target URL<input type="url" name="target_url" placeholder="https://hooks.slack.com/services/..." required /></label>
                  <button type="submit">Add Destination</button>
                </form>
                <table class="watchlist-table" style="margin-top: 18px;">
                  <thead>
                    <tr><th>Name</th><th>Kind</th><th>Target</th><th>Last Tested</th><th>Last Error</th><th></th></tr>
                  </thead>
                  <tbody>
                    {destination_rows or "<tr><td colspan='6' class='muted'>No alert destinations configured yet.</td></tr>"}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        </div>

        <section class="panel" style="margin-top: 24px;">
          <div class="panel-header"><strong>Recent Scan Runs</strong></div>
          <div class="panel-body">
            <table class="inbox-table">
              <thead>
                <tr>
                  <th>Started</th><th>Repo</th><th>Status</th><th>Trigger</th><th>Lock Until</th><th>Findings</th><th>High Risk</th>
                </tr>
              </thead>
              <tbody>
                {scan_run_rows or "<tr><td colspan='7' class='muted'>No scan runs yet.</td></tr>"}
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel" style="margin-top: 24px;">
          <div class="panel-header"><strong>Alert Delivery Attempts</strong></div>
          <div class="panel-body">
            <table class="inbox-table">
              <thead>
                <tr>
                  <th>Created</th><th>Destination</th><th>Repo</th><th>Channel</th><th>Status</th><th>Attempt</th><th>Error</th>
                </tr>
              </thead>
              <tbody>
                {delivery_rows or "<tr><td colspan='7' class='muted'>No alert deliveries recorded yet.</td></tr>"}
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel" style="margin-top: 24px;">
          <div class="panel-header"><strong>Alert Inbox</strong></div>
          <div class="panel-body">
            <table class="inbox-table">
              <thead>
                <tr>
                  <th>Created</th><th>Risk</th><th>Repo</th><th>File</th><th>Summary</th>
                </tr>
              </thead>
              <tbody>
                {alert_rows or "<tr><td colspan='5' class='muted'>No alerts delivered yet.</td></tr>"}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </body>
    </html>
    """


def authenticated_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=303)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, message: Optional[str] = None) -> HTMLResponse:
    store = get_store()
    if get_optional_record(request, store=store) is not None:
        return RedirectResponse(url="/", status_code=303)
    return HTMLResponse(render_login_html(message=message))


@app.post("/auth/register")
def register(
    team_name: str = Form(...),
    team_slug: str = Form(...),
    user_name: str = Form(...),
    user_email: str = Form(...),
    password: str = Form(...),
    first_repo: str = Form(default=""),
) -> HTMLResponse:
    store = get_store()
    try:
        record = store.register_account(
            team_slug=team_slug,
            team_name=team_name,
            user_email=user_email,
            user_name=user_name,
            password=password,
        )
        ownership = record_to_ownership(record)
        if first_repo.strip():
            store.add_repo_watchlist(ownership=ownership, repo_name=first_repo)
    except ValueError as exc:
        return HTMLResponse(render_login_html(message=str(exc)), status_code=400)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        create_session_cookie(record.team_slug, record.user_email),
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return response


@app.post("/auth/login")
def login(
    team_slug: str = Form(...),
    user_email: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    store = get_store()
    record = store.authenticate_account(
        team_slug=team_slug,
        user_email=user_email,
        password=password,
    )
    if record is None:
        return HTMLResponse(render_login_html(message="Invalid team, email, or password."), status_code=401)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        create_session_cookie(record.team_slug, record.user_email),
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return response


@app.post("/auth/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/api/session")
def session_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    record = get_authenticated_record(request, store=store)
    ownership = record_to_ownership(record)
    return {
        "session": {
            "team_slug": record.team_slug,
            "team_name": record.team_name,
            "user_email": record.user_email,
            "user_name": record.user_name,
        },
        "settings": team_settings_to_payload(store.get_team_settings(ownership=ownership)),
        "watchlist": store.list_repo_watchlists(ownership=ownership),
        "store_backend": store.backend_name,
    }


@app.get("/api/settings")
def settings_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    return {"settings": team_settings_to_payload(store.get_team_settings(ownership=ownership))}


@app.post("/api/settings")
def update_settings_api(
    request: Request,
    alert_webhook_url: str = Form(default=""),
    alert_min_risk: str = Form(...),
    alert_min_confidence: int = Form(...),
    scans_enabled: str = Form(...),
    scan_limit: int = Form(...),
    scan_interval_minutes: int = Form(...),
) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    settings = store.update_team_settings(
        ownership=ownership,
        alert_webhook_url=alert_webhook_url,
        alert_min_risk=alert_min_risk,
        alert_min_confidence=alert_min_confidence,
        scans_enabled=scans_enabled.strip().lower() == "true",
        scan_limit=scan_limit,
        scan_interval_minutes=scan_interval_minutes,
    )
    return {"settings": team_settings_to_payload(settings)}


@app.get("/api/findings")
def list_findings_api(
    request: Request,
    limit: int = 25,
    risk: Optional[str] = None,
    repo: Optional[str] = None,
    disposition: Optional[str] = None,
) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    rows = store.list_findings(
        ownership=ownership,
        limit=limit,
        risk=risk,
        repo_name=repo,
        disposition=disposition,
    )
    return {"findings": [row_to_summary(row) for row in rows]}


@app.get("/api/findings/{finding_id}")
def get_finding_api(finding_id: int, request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    row = store.get_finding(ownership=ownership, finding_id=finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": row_to_detail(row)}


@app.post("/api/findings/{finding_id}/triage")
def triage_finding_api(
    finding_id: int,
    request: Request,
    disposition: str = Form(...),
    note: str = Form(default=""),
) -> Dict[str, Any]:
    if disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="Invalid disposition")
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.update_finding_triage(
        ownership=ownership,
        finding_id=finding_id,
        disposition=disposition,
        analyst_note=note,
        clear_note=False,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"updated": True, "finding_id": finding_id}


@app.get("/api/alerts")
def alerts_api(request: Request, limit: int = 20) -> Dict[str, Any]:
    record = get_authenticated_record(request, store=get_store())
    return {"alerts": load_alert_inbox(team_slug=record.team_slug, limit=limit)}


@app.get("/api/alert-deliveries")
def alert_deliveries_api(request: Request, limit: int = 20) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    rows = store.list_alert_deliveries(ownership=ownership, limit=limit)
    return {"alert_deliveries": [alert_delivery_to_payload(row) for row in rows]}


@app.get("/api/alert-destinations")
def alert_destinations_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    rows = store.list_alert_destinations(ownership=ownership, active_only=True)
    return {"alert_destinations": [alert_destination_to_payload(row) for row in rows]}


@app.post("/api/alert-destinations")
def add_alert_destination_api(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    target_url: str = Form(...),
) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        row = store.add_alert_destination(
            ownership=ownership,
            name=name,
            kind=kind,
            target_url=target_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"alert_destination": alert_destination_to_payload(row)}


@app.post("/api/alert-destinations/{destination_id}/deactivate")
def deactivate_alert_destination_api(destination_id: int, request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.deactivate_alert_destination(ownership=ownership, destination_id=destination_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert destination not found")
    return {"updated": True}


@app.post("/api/alert-destinations/{destination_id}/test")
def test_alert_destination_api(destination_id: int, request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        result = get_delivery_service(store=store).send_test_alert(ownership=ownership, destination_id=destination_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"delivery": result}


@app.post("/api/alerts/process-queue")
def process_alert_queue_api(request: Request, limit: int = 20) -> Dict[str, Any]:
    store = get_store()
    record = get_authenticated_record(request, store=store)
    results = get_delivery_service(store=store).process_cycle(team_slug=record.team_slug, limit=limit)
    return {"deliveries": results}


@app.get("/api/watchlist")
def list_watchlist_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    return {"watchlist": store.list_repo_watchlists(ownership=ownership)}


@app.post("/api/watchlist")
def add_watchlist_api(
    request: Request,
    repo_name: str = Form(...),
) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        row = store.add_repo_watchlist(ownership=ownership, repo_name=repo_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"watchlist_entry": row}


@app.post("/api/watchlist/{watchlist_id}/deactivate")
def deactivate_watchlist_api(watchlist_id: int, request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.deactivate_repo_watchlist(ownership=ownership, watchlist_id=watchlist_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Watchlist entry not found")
    return {"updated": True}


@app.get("/api/scan-runs")
def scan_runs_api(request: Request, limit: int = 20) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    rows = store.list_scan_runs(ownership=ownership, limit=limit)
    return {"scan_runs": [scan_run_to_payload(row) for row in rows]}


@app.post("/api/watchlist/{watchlist_id}/scan-now")
def scan_watchlist_now_api(watchlist_id: int, request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    result = get_scan_service(store=store).scan_watchlist_entry(
        ownership=ownership,
        watchlist_id=watchlist_id,
        trigger_mode="manual",
    )
    if result.get("status") == "skipped":
        raise HTTPException(status_code=409, detail="A scan is already running for this repository")
    if result.get("status") == "failed":
        raise HTTPException(status_code=502, detail=result.get("error_message", "Scan failed"))
    return {"scan_run": result}


@app.post("/api/scans/run-cycle")
def run_scan_cycle_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    record = get_authenticated_record(request, store=store)
    results = get_scan_service(store=store).run_cycle(team_slug=record.team_slug)
    return {"scan_runs": results}


@app.post("/api/demo/test-scan")
def demo_test_scan_api(request: Request) -> Dict[str, Any]:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    commit_sha = f"web_demo_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    hunter = ThreatHunter(
        github_token=None,
        openai_api_key=None,
        db_path=DATABASE_PATH,
        database_url=DATABASE_URL,
        model=DEFAULT_MODEL,
        suppressions=load_suppressions(),
        ownership=ownership,
    )
    result = hunter.analyze_patch(
        filename="requests/api.py",
        patch_data=FAKE_PATCH,
        commit_sha=commit_sha,
        repo_name=DEFAULT_TARGET_REPO,
    )
    hunter.store.save_commit_metadata(
        ownership=ownership,
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha=commit_sha,
        author_name="web-demo",
        commit_message="Synthetic reverse shell patch",
        html_url=None,
    )
    finding_id = hunter.store.save_finding(
        ownership=ownership,
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha=commit_sha,
        file_name="requests/api.py",
        result=result,
    )
    delivery = deliver_alert(
        ownership=ownership,
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha=commit_sha,
        file_name="requests/api.py",
        result=result,
        store=store,
    )
    if result.should_save_yara():
        hunter.save_yara_rule(result.yara_rule or "", commit_sha, "requests/api.py")
    return {
        "commit_sha": commit_sha,
        "risk": result.normalized_risk(),
        "confidence": result.confidence,
        "alert_channels": delivery.channels,
        "team_slug": ownership.team_slug,
        "finding_id": finding_id,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    finding_id: Optional[int] = None,
    limit: int = 25,
    risk: Optional[str] = None,
    disposition: Optional[str] = None,
) -> HTMLResponse:
    store = get_store()
    record = get_optional_record(request, store=store)
    if record is None:
        return authenticated_redirect()

    ownership = record_to_ownership(record)
    team_settings = store.get_team_settings(ownership=ownership)
    findings = [
        row_to_summary(row)
        for row in store.list_findings(
            ownership=ownership,
            limit=limit,
            risk=risk,
            repo_name=None,
            disposition=disposition,
        )
    ]

    selected_finding = None
    if finding_id is not None:
        row = store.get_finding(ownership=ownership, finding_id=finding_id)
        if row:
            selected_finding = row_to_detail(row)
    elif findings:
        row = store.get_finding(ownership=ownership, finding_id=findings[0]["id"])
        if row:
            selected_finding = row_to_detail(row)

    html = render_dashboard_html(
        findings=findings,
        selected_finding=selected_finding,
        alerts=load_alert_inbox(team_slug=record.team_slug, limit=20),
        alert_deliveries=[
            alert_delivery_to_payload(row)
            for row in store.list_alert_deliveries(ownership=ownership, limit=10)
        ],
        alert_destinations=[
            alert_destination_to_payload(row)
            for row in store.list_alert_destinations(ownership=ownership, active_only=True)
        ],
        watchlist=store.list_repo_watchlists(ownership=ownership),
        team_settings=team_settings_to_payload(team_settings),
        scan_runs=[scan_run_to_payload(row) for row in store.list_scan_runs(ownership=ownership, limit=10)],
        filters={
            "limit": str(limit),
            "risk": risk or "",
            "disposition": disposition or "",
        },
        session={
            "team_slug": record.team_slug,
            "team_name": record.team_name,
            "user_email": record.user_email,
            "user_name": record.user_name,
        },
        backend_name=store.backend_name,
    )
    return HTMLResponse(content=html)


@app.post("/findings/{finding_id}/triage")
def triage_finding_form(
    finding_id: int,
    request: Request,
    disposition: str = Form(...),
    note: str = Form(default=""),
) -> RedirectResponse:
    if disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="Invalid disposition")
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.update_finding_triage(
        ownership=ownership,
        finding_id=finding_id,
        disposition=disposition,
        analyst_note=note,
        clear_note=False,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return RedirectResponse(url=f"/?finding_id={finding_id}", status_code=303)


@app.post("/watchlist")
def add_watchlist_form(request: Request, repo_name: str = Form(...)) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        store.add_repo_watchlist(ownership=ownership, repo_name=repo_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/alert-destinations")
def add_alert_destination_form(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    target_url: str = Form(...),
) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        store.add_alert_destination(
            ownership=ownership,
            name=name,
            kind=kind,
            target_url=target_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/alert-destinations/{destination_id}/deactivate")
def deactivate_alert_destination_form(destination_id: int, request: Request) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.deactivate_alert_destination(ownership=ownership, destination_id=destination_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert destination not found")
    return RedirectResponse(url="/", status_code=303)


@app.post("/alert-destinations/{destination_id}/test")
def test_alert_destination_form(destination_id: int, request: Request) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    try:
        get_delivery_service(store=store).send_test_alert(ownership=ownership, destination_id=destination_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RedirectResponse(url="/", status_code=303)


@app.post("/watchlist/{watchlist_id}/deactivate")
def deactivate_watchlist_form(watchlist_id: int, request: Request) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    updated = store.deactivate_repo_watchlist(ownership=ownership, watchlist_id=watchlist_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Watchlist entry not found")
    return RedirectResponse(url="/", status_code=303)


@app.post("/watchlist/{watchlist_id}/scan-now")
def scan_watchlist_now_form(watchlist_id: int, request: Request) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    result = get_scan_service(store=store).scan_watchlist_entry(
        ownership=ownership,
        watchlist_id=watchlist_id,
        trigger_mode="manual",
    )
    if result.get("status") == "skipped":
        raise HTTPException(status_code=409, detail="A scan is already running for this repository")
    if result.get("status") == "failed":
        raise HTTPException(status_code=502, detail=result.get("error_message", "Scan failed"))
    return RedirectResponse(url="/", status_code=303)


@app.post("/settings")
def update_settings_form(
    request: Request,
    alert_webhook_url: str = Form(default=""),
    alert_min_risk: str = Form(...),
    alert_min_confidence: int = Form(...),
    scans_enabled: str = Form(...),
    scan_limit: int = Form(...),
    scan_interval_minutes: int = Form(...),
) -> RedirectResponse:
    store = get_store()
    ownership = record_to_ownership(get_authenticated_record(request, store=store))
    store.update_team_settings(
        ownership=ownership,
        alert_webhook_url=alert_webhook_url,
        alert_min_risk=alert_min_risk,
        alert_min_confidence=alert_min_confidence,
        scans_enabled=scans_enabled.strip().lower() == "true",
        scan_limit=scan_limit,
        scan_interval_minutes=scan_interval_minutes,
    )
    return RedirectResponse(url="/", status_code=303)


@app.post("/scans/run-cycle")
def run_scan_cycle_form(request: Request) -> RedirectResponse:
    store = get_store()
    record = get_authenticated_record(request, store=store)
    get_scan_service(store=store).run_cycle(team_slug=record.team_slug)
    return RedirectResponse(url="/", status_code=303)


@app.post("/alerts/process-queue")
def process_alert_queue_form(request: Request) -> RedirectResponse:
    store = get_store()
    record = get_authenticated_record(request, store=store)
    get_delivery_service(store=store).process_cycle(team_slug=record.team_slug, limit=20)
    return RedirectResponse(url="/", status_code=303)


@app.post("/demo/test-scan")
def demo_test_scan_form(request: Request) -> RedirectResponse:
    response = demo_test_scan_api(request)
    return RedirectResponse(url=f"/?finding_id={response['finding_id']}", status_code=303)
