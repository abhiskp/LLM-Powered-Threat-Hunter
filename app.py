import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from testThreat import FAKE_PATCH
from watchman import (
    ALERTS_LOG_PATH,
    DATABASE_PATH,
    DATABASE_URL,
    DEFAULT_TARGET_REPO,
    DEFAULT_MODEL,
    VALID_DISPOSITIONS,
    FindingStore,
    OwnershipContext,
    ThreatHunter,
    deliver_alert,
    default_ownership_context,
    load_suppressions,
)


app = FastAPI(title="Threat Hunter Analyst Inbox", version="0.1.0")


def get_store() -> FindingStore:
    return FindingStore(db_path=DATABASE_PATH, database_url=DATABASE_URL)


def resolve_request_context(
    team_slug: Optional[str] = None,
    team_name: Optional[str] = None,
    user_email: Optional[str] = None,
    user_name: Optional[str] = None,
    x_team_slug: Optional[str] = None,
    x_team_name: Optional[str] = None,
    x_user_email: Optional[str] = None,
    x_user_name: Optional[str] = None,
) -> OwnershipContext:
    return default_ownership_context(
        team_slug=team_slug or x_team_slug,
        team_name=team_name or x_team_name,
        user_email=user_email or x_user_email,
        user_name=user_name or x_user_name,
    )


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


def load_alert_inbox(limit: int = 20) -> List[Dict[str, Any]]:
    if not ALERTS_LOG_PATH.exists():
        return []

    lines = ALERTS_LOG_PATH.read_text(encoding="utf-8").splitlines()
    alerts: List[Dict[str, Any]] = []
    for line in reversed(lines[-limit:]):
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def render_dashboard_html(
    findings: List[Dict[str, Any]],
    selected_finding: Optional[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    filters: Dict[str, str],
    session: Dict[str, str],
    backend_name: str,
) -> str:
    selected_panel = "<p class='muted'>Select a finding to inspect its full context.</p>"
    if selected_finding:
        reasons = "".join(f"<li>{reason}</li>" for reason in selected_finding["reasons"])
        indicators = "".join(f"<li>{indicator}</li>" for indicator in selected_finding["indicators"])
        rule_hits = ", ".join(selected_finding["rule_hits"]) or "None"
        history_note = selected_finding["history_context"].get("note", "None")
        suppression_note = selected_finding["suppression_context"].get("note", "None")
        triaged_by = selected_finding["triaged_by_user_name"] or selected_finding["triaged_by_user_email"] or "None"
        yara_block = ""
        if selected_finding["yara_rule"]:
            yara_block = (
                "<h4>YARA</h4>"
                f"<pre>{selected_finding['yara_rule']}</pre>"
            )
        selected_panel = f"""
        <div class="detail-card">
          <h3>Finding #{selected_finding['id']}</h3>
          <p><strong>Repo:</strong> {selected_finding['repo_name']}</p>
          <p><strong>Commit:</strong> {selected_finding['commit_sha']}</p>
          <p><strong>File:</strong> {selected_finding['file_name']}</p>
          <p><strong>Risk:</strong> {selected_finding['risk']} ({selected_finding['confidence']}%)</p>
          <p><strong>Disposition:</strong> {selected_finding['disposition']}</p>
          <p><strong>Triaged By:</strong> {triaged_by}</p>
          <p><strong>Summary:</strong> {selected_finding['summary']}</p>
          <p><strong>Rule Hits:</strong> {rule_hits}</p>
          <p><strong>History:</strong> {history_note}</p>
          <p><strong>Suppression:</strong> {suppression_note}</p>
          <p><strong>Analyst Note:</strong> {selected_finding['analyst_note'] or 'None'}</p>
          <h4>Reasons</h4>
          <ul>{reasons or '<li>None</li>'}</ul>
          <h4>Indicators</h4>
          <ul>{indicators or '<li>None</li>'}</ul>
          {yara_block}
          <form method="post" action="/findings/{selected_finding['id']}/triage" class="triage-form">
            <input type="hidden" name="team_slug" value="{session['team_slug']}" />
            <input type="hidden" name="team_name" value="{session['team_name']}" />
            <input type="hidden" name="user_email" value="{session['user_email']}" />
            <input type="hidden" name="user_name" value="{session['user_name']}" />
            <label>Disposition</label>
            <select name="disposition">
              {''.join(f"<option value='{value}' {'selected' if selected_finding['disposition'] == value else ''}>{value}</option>" for value in sorted(VALID_DISPOSITIONS))}
            </select>
            <label>Analyst Note</label>
            <textarea name="note" rows="4">{selected_finding['analyst_note'] or ''}</textarea>
            <button type="submit">Update Finding</button>
          </form>
        </div>
        """

    finding_rows = ""
    for finding in findings:
        finding_rows += f"""
        <tr>
          <td><a href="/?finding_id={finding['id']}">{finding['id']}</a></td>
          <td>{finding['risk']}</td>
          <td>{finding['confidence']}%</td>
          <td>{finding['disposition']}</td>
          <td>{finding['repo_name']}</td>
          <td>{finding['file_name']}</td>
          <td>{finding['summary']}</td>
        </tr>
        """

    alert_rows = ""
    for alert in alerts:
        alert_rows += f"""
        <tr>
          <td>{alert.get('created_at', '')}</td>
          <td>{alert.get('risk', '')}</td>
          <td>{alert.get('repo_name', '')}</td>
          <td>{alert.get('file_name', '')}</td>
          <td>{alert.get('summary', '')}</td>
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
          --green: #356f45;
          --yellow: #8b6d14;
          --red: #8f2d20;
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
        .shell {{
          max-width: 1440px;
          margin: 0 auto;
          padding: 28px;
        }}
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
        .layout {{
          display: grid;
          grid-template-columns: 1.1fr 0.9fr;
          gap: 24px;
        }}
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
        .panel-body {{
          padding: 20px;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
        }}
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
        .triage-form {{
          display: grid;
          gap: 10px;
          margin-top: 18px;
        }}
        .inbox-table td:first-child {{ white-space: nowrap; }}
        @media (max-width: 980px) {{
          .layout {{ grid-template-columns: 1fr; }}
          .shell {{ padding: 16px; }}
          .hero {{ padding: 20px; }}
        }}
      </style>
    </head>
    <body>
      <div class="shell">
        <section class="hero">
          <h1>Threat Hunter Analyst Inbox</h1>
          <p>Review suspicious commit diffs, triage findings, and inspect alert history in one place. This is the first product-facing surface on top of the existing threat hunting engine.</p>
          <div class="meta">
            <span><strong>Team:</strong> {session['team_name']} ({session['team_slug']})</span>
            <span><strong>Analyst:</strong> {session['user_name']} ({session['user_email']})</span>
            <span><strong>Store:</strong> {backend_name}</span>
          </div>
          <div class="actions">
            <form method="post" action="/demo/test-scan">
              <input type="hidden" name="team_slug" value="{session['team_slug']}" />
              <input type="hidden" name="team_name" value="{session['team_name']}" />
              <input type="hidden" name="user_email" value="{session['user_email']}" />
              <input type="hidden" name="user_name" value="{session['user_name']}" />
              <button type="submit">Run Synthetic Demo Scan</button>
            </form>
            <form method="get" action="/" class="filters">
              <input type="hidden" name="team_slug" value="{session['team_slug']}" />
              <input type="hidden" name="team_name" value="{session['team_name']}" />
              <input type="hidden" name="user_email" value="{session['user_email']}" />
              <input type="hidden" name="user_name" value="{session['user_name']}" />
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

          <section class="panel">
            <div class="panel-header"><strong>Finding Detail</strong></div>
            <div class="panel-body">
              {selected_panel}
            </div>
          </section>
        </div>

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


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/session")
def session_api(
    team_slug: Optional[str] = Query(default=None),
    team_name: Optional[str] = Query(default=None),
    user_email: Optional[str] = Query(default=None),
    user_name: Optional[str] = Query(default=None),
    x_team_slug: Optional[str] = Header(default=None, alias="X-Team-Slug"),
    x_team_name: Optional[str] = Header(default=None, alias="X-Team-Name"),
    x_user_email: Optional[str] = Header(default=None, alias="X-User-Email"),
    x_user_name: Optional[str] = Header(default=None, alias="X-User-Name"),
) -> Dict[str, Any]:
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
        x_team_slug=x_team_slug,
        x_team_name=x_team_name,
        x_user_email=x_user_email,
        x_user_name=x_user_name,
    )
    store = get_store()
    record = store.resolve_ownership(ownership)
    return {
        "session": {
            "team_slug": record.team_slug,
            "team_name": record.team_name,
            "user_email": record.user_email,
            "user_name": record.user_name,
        },
        "store_backend": store.backend_name,
    }


@app.get("/api/findings")
def list_findings_api(
    limit: int = Query(default=25, ge=1, le=200),
    risk: Optional[str] = None,
    repo: Optional[str] = None,
    disposition: Optional[str] = None,
    team_slug: Optional[str] = Query(default=None),
    team_name: Optional[str] = Query(default=None),
    user_email: Optional[str] = Query(default=None),
    user_name: Optional[str] = Query(default=None),
    x_team_slug: Optional[str] = Header(default=None, alias="X-Team-Slug"),
    x_team_name: Optional[str] = Header(default=None, alias="X-Team-Name"),
    x_user_email: Optional[str] = Header(default=None, alias="X-User-Email"),
    x_user_name: Optional[str] = Header(default=None, alias="X-User-Name"),
) -> Dict[str, Any]:
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
        x_team_slug=x_team_slug,
        x_team_name=x_team_name,
        x_user_email=x_user_email,
        x_user_name=x_user_name,
    )
    rows = get_store().list_findings(
        ownership=ownership,
        limit=limit,
        risk=risk,
        repo_name=repo,
        disposition=disposition,
    )
    return {"findings": [row_to_summary(row) for row in rows]}


@app.get("/api/findings/{finding_id}")
def get_finding_api(
    finding_id: int,
    team_slug: Optional[str] = Query(default=None),
    team_name: Optional[str] = Query(default=None),
    user_email: Optional[str] = Query(default=None),
    user_name: Optional[str] = Query(default=None),
    x_team_slug: Optional[str] = Header(default=None, alias="X-Team-Slug"),
    x_team_name: Optional[str] = Header(default=None, alias="X-Team-Name"),
    x_user_email: Optional[str] = Header(default=None, alias="X-User-Email"),
    x_user_name: Optional[str] = Header(default=None, alias="X-User-Name"),
) -> Dict[str, Any]:
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
        x_team_slug=x_team_slug,
        x_team_name=x_team_name,
        x_user_email=x_user_email,
        x_user_name=x_user_name,
    )
    row = get_store().get_finding(ownership=ownership, finding_id=finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": row_to_detail(row)}


@app.post("/api/findings/{finding_id}/triage")
def triage_finding_api(
    finding_id: int,
    disposition: str = Form(...),
    note: str = Form(default=""),
    team_slug: Optional[str] = Form(default=None),
    team_name: Optional[str] = Form(default=None),
    user_email: Optional[str] = Form(default=None),
    user_name: Optional[str] = Form(default=None),
    x_team_slug: Optional[str] = Header(default=None, alias="X-Team-Slug"),
    x_team_name: Optional[str] = Header(default=None, alias="X-Team-Name"),
    x_user_email: Optional[str] = Header(default=None, alias="X-User-Email"),
    x_user_name: Optional[str] = Header(default=None, alias="X-User-Name"),
) -> Dict[str, Any]:
    if disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="Invalid disposition")

    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
        x_team_slug=x_team_slug,
        x_team_name=x_team_name,
        x_user_email=x_user_email,
        x_user_name=x_user_name,
    )
    updated = get_store().update_finding_triage(
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
def alerts_api(limit: int = Query(default=20, ge=1, le=200)) -> Dict[str, Any]:
    return {"alerts": load_alert_inbox(limit=limit)}


@app.post("/api/demo/test-scan")
def demo_test_scan_api(
    team_slug: Optional[str] = Form(default=None),
    team_name: Optional[str] = Form(default=None),
    user_email: Optional[str] = Form(default=None),
    user_name: Optional[str] = Form(default=None),
    x_team_slug: Optional[str] = Header(default=None, alias="X-Team-Slug"),
    x_team_name: Optional[str] = Header(default=None, alias="X-Team-Name"),
    x_user_email: Optional[str] = Header(default=None, alias="X-User-Email"),
    x_user_name: Optional[str] = Header(default=None, alias="X-User-Name"),
) -> Dict[str, Any]:
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
        x_team_slug=x_team_slug,
        x_team_name=x_team_name,
        x_user_email=x_user_email,
        x_user_name=x_user_name,
    )
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
    hunter.store.save_finding(
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
    )
    if result.should_save_yara():
        hunter.save_yara_rule(result.yara_rule or "", commit_sha, "requests/api.py")
    return {
        "commit_sha": commit_sha,
        "risk": result.normalized_risk(),
        "confidence": result.confidence,
        "alert_channels": delivery.channels,
        "team_slug": ownership.team_slug,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(
    finding_id: Optional[int] = None,
    limit: int = 25,
    risk: Optional[str] = None,
    disposition: Optional[str] = None,
    team_slug: Optional[str] = None,
    team_name: Optional[str] = None,
    user_email: Optional[str] = None,
    user_name: Optional[str] = None,
) -> HTMLResponse:
    store = get_store()
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
    )
    record = store.resolve_ownership(ownership)
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
        alerts=load_alert_inbox(limit=20),
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
    disposition: str = Form(...),
    note: str = Form(default=""),
    team_slug: Optional[str] = Form(default=None),
    team_name: Optional[str] = Form(default=None),
    user_email: Optional[str] = Form(default=None),
    user_name: Optional[str] = Form(default=None),
) -> RedirectResponse:
    if disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail="Invalid disposition")
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
    )
    updated = get_store().update_finding_triage(
        ownership=ownership,
        finding_id=finding_id,
        disposition=disposition,
        analyst_note=note,
        clear_note=False,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    query_string = urlencode(
        {
            "finding_id": finding_id,
            "team_slug": ownership.team_slug,
            "team_name": ownership.team_name,
            "user_email": ownership.user_email,
            "user_name": ownership.user_name,
        }
    )
    return RedirectResponse(
        url=f"/?{query_string}",
        status_code=303,
    )


@app.post("/demo/test-scan")
def demo_test_scan_form(
    team_slug: Optional[str] = Form(default=None),
    team_name: Optional[str] = Form(default=None),
    user_email: Optional[str] = Form(default=None),
    user_name: Optional[str] = Form(default=None),
) -> RedirectResponse:
    ownership = resolve_request_context(
        team_slug=team_slug,
        team_name=team_name,
        user_email=user_email,
        user_name=user_name,
    )
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
    hunter.store.save_finding(
        ownership=ownership,
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha=commit_sha,
        file_name="requests/api.py",
        result=result,
    )
    deliver_alert(
        ownership=ownership,
        repo_name=DEFAULT_TARGET_REPO,
        commit_sha=commit_sha,
        file_name="requests/api.py",
        result=result,
    )
    rows = get_store().list_findings(ownership=ownership, limit=1)
    redirect_id = rows[0]["id"] if rows else None
    query_payload = {
        "team_slug": ownership.team_slug,
        "team_name": ownership.team_name,
        "user_email": ownership.user_email,
        "user_name": ownership.user_name,
    }
    if redirect_id:
        query_payload["finding_id"] = str(redirect_id)
    target = f"/?{urlencode(query_payload)}"
    return RedirectResponse(url=target, status_code=303)
