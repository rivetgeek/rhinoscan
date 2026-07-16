import React, { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, RefreshCw, Download, AlertTriangle, ChevronUp, ChevronDown } from "lucide-react";
import {
  getRun, getFindings, getProwlerFindings, getProwlerFinding,
  getSecretFindings, getAlerts, getScorecard, reportUrl,
} from "../api";

const TAB_LABELS = {
  findings: "Findings",
  prowler: "Cloud Checks",
  github: "GitHub Checks",
  secrets: "Secrets",
  alerts: "Alerts",
  scorecard: "Scorecard",
};

// Which tabs an engine contributes beyond the always-on unified Findings tab.
const ENGINE_TABS = {
  "prowler-aws": ["prowler"],
  "prowler-github": ["github"],
  "trufflehog": ["secrets", "alerts"],
  "scorecard": ["scorecard"],
};

export default function ScanDetail() {
  const { runId, tab = "findings" } = useParams();
  const navigate = useNavigate();
  const [run, setRun] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadRun = useCallback(async () => {
    const data = await getRun(runId);
    setRun(data);
    setLoading(false);
  }, [runId]);

  useEffect(() => {
    loadRun();
    const t = setInterval(() => {
      if (run?.status === "running") loadRun();
    }, 4000);
    return () => clearInterval(t);
  }, [loadRun, run?.status]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 40 }}>Loading…</div>;

  const tabs = ["findings"];
  for (const engine of run?.engines || []) {
    tabs.push(...(ENGINE_TABS[engine] || []));
  }

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <button className="btn btn-ghost" style={{ marginBottom: 16, paddingLeft: 8 }} onClick={() => navigate("/assess")}>
          <ArrowLeft size={14} /> All Runs
        </button>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 600, color: "var(--text-hi)", fontFamily: "var(--mono)" }}>
              {run.target}
            </h1>
            <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
              {(run.engines || []).map((e) => (
                <span key={e} className={`stat stat-${run.engine_status?.[e] || "pending"}`}>
                  {e}: {run.engine_status?.[e] || "pending"}
                </span>
              ))}
              <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>
                {formatDate(run.started_at)}
              </span>
            </div>
            {run.errors && (
              <div style={{ marginTop: 8, fontSize: 12, color: "var(--red)", fontFamily: "var(--mono)" }}>
                {Object.entries(run.errors).map(([e, msg]) => `${e}: ${msg}`).join(" | ")}
              </div>
            )}
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className={`stat stat-${run.status}`}>{run.status}</span>
            <button className="btn btn-ghost" onClick={loadRun}><RefreshCw size={13} /></button>
            <a className="btn btn-ghost" href={reportUrl(runId)} download>
              <Download size={13} /> Report
            </a>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)", marginBottom: 20 }}>
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => navigate(`/assess/${runId}/${t}`)}
            style={{
              padding: "10px 18px",
              fontSize: 13,
              fontWeight: tab === t ? 600 : 400,
              color: tab === t ? "var(--text-hi)" : "var(--text-dim)",
              background: "none",
              border: "none",
              borderBottom: tab === t ? "2px solid var(--accent)" : "2px solid transparent",
              cursor: "pointer",
              marginBottom: -1,
            }}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      {tab === "findings" && <FindingsTab runId={runId} />}
      {tab === "prowler" && <ProwlerTab runId={runId} provider="aws" />}
      {tab === "github" && <ProwlerTab runId={runId} provider="github" />}
      {tab === "secrets" && <SecretsTab runId={runId} />}
      {tab === "alerts" && <AlertsTab runId={runId} />}
      {tab === "scorecard" && <ScorecardTab runId={runId} />}
    </div>
  );
}

// ── Unified Findings Tab ──────────────────────────────────────────────────────

function FindingsTab({ runId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    setLoading(true);
    getFindings({ run_id: runId, page, page_size: 100 })
      .then(setData)
      .finally(() => setLoading(false));
  }, [runId, page]);

  if (loading) return <Spinner />;
  if (!data?.findings?.length) return (
    <div className="card" style={{ padding: 48, textAlign: "center", color: "var(--text-dim)" }}>
      No unified findings for this run.
    </div>
  );

  return (
    <>
      <div className="card" style={{ overflow: "hidden", marginBottom: 12 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th>Severity</th>
              <th>Source</th>
              <th>Category</th>
              <th>Title</th>
              <th>Resource</th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f) => (
              <React.Fragment key={f.id}>
                <tr style={{ cursor: "pointer" }} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                  <td>{expanded === f.id ? <ChevronUp size={14} /> : <ChevronDown size={14} style={{ opacity: 0.35 }} />}</td>
                  <td><span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{f.origin}</td>
                  <td>{f.category}</td>
                  <td>{f.title}</td>
                  <td className="mono">
                    <div style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.resource}>
                      {f.resource}
                    </div>
                  </td>
                </tr>
                {expanded === f.id && (
                  <tr>
                    <td colSpan={6} style={{ background: "var(--bg)" }}>
                      <div style={{ padding: "8px 4px 12px", display: "flex", flexDirection: "column", gap: 10 }}>
                        <Detail label="Description" value={f.description} />
                        <Detail label="Remediation" value={f.remediation} />
                        <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                          <Detail label="Check" value={f.source} mono />
                          {f.api && <Detail label="AWS API" value={f.api} mono />}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <Pager total={data.total} page={page} pageSize={100} onChange={setPage} />
    </>
  );
}

function Detail({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)", marginBottom: 3 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: "var(--text)", fontFamily: mono ? "var(--mono)" : "inherit", lineHeight: 1.5 }}>
        {value}
      </div>
    </div>
  );
}

// ── Alerts Tab ────────────────────────────────────────────────────────────────

function AlertsTab({ runId }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAlerts(runId).then(setAlerts).finally(() => setLoading(false));
  }, [runId]);

  if (loading) return <Spinner />;

  if (!alerts.length) return (
    <div className="card" style={{ padding: 48, textAlign: "center", color: "var(--text-dim)" }}>
      No correlated alerts found. Either no AWS keys were exposed, or no AWS profiles were in the scan request to correlate against.
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {alerts.map((a) => (
        <div key={a.id} className="alert-card">
          <div className="alert-header">
            <AlertTriangle size={18} color="var(--red)" style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <div className="alert-title">{a.title}</div>
              <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                <span className={`sev sev-${a.severity.toLowerCase()}`}>{a.severity}</span>
                {a.key_active !== null && (
                  <span className={`stat ${a.key_active ? "stat-FAIL" : "stat-PASS"}`}>
                    Key {a.key_active ? "ACTIVE" : "INACTIVE"}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="narrative">{a.narrative}</div>

          <div className="alert-meta">
            <MetaItem label="Key ID" value={a.key_id} />
            <MetaItem label="IAM User" value={a.iam_entity_name} />
            <MetaItem label="Repository" value={a.repo} />
            <MetaItem label="File" value={a.file_path} />
            <MetaItem label="Commit" value={a.commit?.slice(0, 12)} />
            <MetaItem label="Author" value={a.author} />
            <MetaItem label="Date Exposed" value={a.exposed_date} />
          </div>

          {a.attached_policies?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)", marginBottom: 8 }}>
                Attached Policies
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {a.attached_policies.map((p) => (
                  <span key={p} style={{
                    fontFamily: "var(--mono)", fontSize: 11,
                    padding: "3px 8px", background: "var(--bg)",
                    border: "1px solid var(--border)", borderRadius: 3,
                    color: "var(--text)",
                  }}>
                    {p.split("/").pop()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function MetaItem({ label, value }) {
  if (!value) return null;
  return (
    <div className="meta-item">
      <label>{label}</label>
      <span>{value}</span>
    </div>
  );
}

// ── Prowler Tab ───────────────────────────────────────────────────────────────

function ProwlerTab({ runId, provider = "aws" }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [params, setParams] = useState({
    severity: "", status: "FAIL", service: "", search: "",
    sort_by: "severity", sort_dir: "desc", page: 1, page_size: 50,
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getProwlerFindings(runId, { ...params, provider });
      setData(res);
    } finally {
      setLoading(false);
    }
  }, [runId, provider, params]);

  useEffect(() => { load(); }, [load]);

  const set = (k) => (v) => setParams((p) => ({ ...p, [k]: v, page: 1 }));
  const toggleSort = (col) => {
    if (params.sort_by === col) {
      setParams((p) => ({ ...p, sort_dir: p.sort_dir === "asc" ? "desc" : "asc" }));
    } else {
      setParams((p) => ({ ...p, sort_by: col, sort_dir: "desc" }));
    }
  };

  return (
    <div>
      {/* Filters */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
        <input className="input" placeholder="Search findings…" style={{ flex: "1 1 200px" }}
          value={params.search} onChange={(e) => set("search")(e.target.value)} />
        <select className="select" value={params.severity} onChange={(e) => set("severity")(e.target.value)}>
          <option value="">All Severities</option>
          {["critical","high","medium","low","informational"].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select" value={params.status} onChange={(e) => set("status")(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="FAIL">FAIL</option>
          <option value="PASS">PASS</option>
        </select>
        <button className="btn btn-ghost" onClick={load}><RefreshCw size={13} /></button>
      </div>

      {loading ? <Spinner /> : (
        <>
          <div className="card" style={{ overflow: "hidden", marginBottom: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <SortTh col="severity" cur={params} onClick={toggleSort}>Severity</SortTh>
                  <SortTh col="status" cur={params} onClick={toggleSort}>Status</SortTh>
                  <SortTh col="service" cur={params} onClick={toggleSort}>Service</SortTh>
                  <SortTh col="check_title" cur={params} onClick={toggleSort}>Check</SortTh>
                  <SortTh col="region" cur={params} onClick={toggleSort}>Region</SortTh>
                  <th>Resource</th>
                </tr>
              </thead>
              <tbody>
                {data?.findings?.map((f) => (
                  <ProwlerRow key={f.id} runId={runId} f={f} />
                ))}
              </tbody>
            </table>
          </div>
          <Pager total={data?.total} page={params.page} pageSize={params.page_size}
            onChange={(p) => setParams((x) => ({ ...x, page: p }))} />
        </>
      )}
    </div>
  );
}

// Expandable Prowler row — click to load and show the full Prowler/OCSF result.
function ProwlerRow({ runId, f }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      setLoading(true);
      try { setDetail(await getProwlerFinding(runId, f.id)); }
      finally { setLoading(false); }
    }
  };

  return (
    <>
      <tr onClick={toggle} style={{ cursor: "pointer" }}>
        <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
        <td><span className={`stat stat-${f.status}`}>{f.status}</span></td>
        <td className="mono">{f.service}</td>
        <td>
          <div style={{ fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
            {open ? <ChevronUp size={12} /> : <ChevronDown size={12} style={{ opacity: 0.35 }} />}
            {f.check_title}
          </div>
          {f.status_extended && <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 3 }}>{f.status_extended}</div>}
        </td>
        <td className="mono">{f.region}</td>
        <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {f.resource_name || f.resource_arn?.split("/").pop() || "—"}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} style={{ background: "var(--bg)", padding: 0 }}>
            {loading
              ? <div style={{ padding: 16, color: "var(--text-dim)" }}>Loading…</div>
              : detail && <ProwlerDetail d={detail} />}
          </td>
        </tr>
      )}
    </>
  );
}

function ProwlerDetail({ d }) {
  return (
    <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
      <div className="alert-meta">
        <MetaItem label="Check ID" value={d.check_id} />
        <MetaItem label="Severity" value={d.severity} />
        <MetaItem label="Status" value={d.status} />
        <MetaItem label="Service" value={d.service} />
        <MetaItem label="Region" value={d.region} />
        <MetaItem label="Resource" value={d.resource_name} />
        <MetaItem label="Resource ARN" value={d.resource_arn} />
      </div>
      {d.status_extended && <div style={{ fontSize: 13, color: "var(--text)" }}>{d.status_extended}</div>}
      <div>
        <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)", marginBottom: 6 }}>
          Full Prowler Result
        </div>
        <pre style={{
          margin: 0, maxHeight: 440, overflow: "auto",
          background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 4,
          padding: 12, fontSize: 11.5, fontFamily: "var(--mono)", color: "var(--text)",
          whiteSpace: "pre-wrap", wordBreak: "break-word",
        }}>
{JSON.stringify(d.raw, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ── Secrets Tab ───────────────────────────────────────────────────────────────

function SecretsTab({ runId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [params, setParams] = useState({ search: "", sort_by: "date", sort_dir: "desc", page: 1, page_size: 50 });

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await getSecretFindings(runId, params)); }
    finally { setLoading(false); }
  }, [runId, params]);

  useEffect(() => { load(); }, [load]);

  const toggleSort = (col) => {
    if (params.sort_by === col) {
      setParams((p) => ({ ...p, sort_dir: p.sort_dir === "asc" ? "desc" : "asc" }));
    } else {
      setParams((p) => ({ ...p, sort_by: col, sort_dir: "desc" }));
    }
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="input" placeholder="Search repos, authors, files…" style={{ flex: 1 }}
          value={params.search} onChange={(e) => setParams((p) => ({ ...p, search: e.target.value, page: 1 }))} />
        <button className="btn btn-ghost" onClick={load}><RefreshCw size={13} /></button>
      </div>

      {loading ? <Spinner /> : (
        <>
          <div className="card" style={{ overflow: "hidden", marginBottom: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Verified</th>
                  <SortTh col="repo" cur={params} onClick={toggleSort}>Repo</SortTh>
                  <th>Key ID</th>
                  <th>File</th>
                  <SortTh col="author" cur={params} onClick={toggleSort}>Author</SortTh>
                  <SortTh col="date" cur={params} onClick={toggleSort}>Date</SortTh>
                  <th>Commit</th>
                </tr>
              </thead>
              <tbody>
                {data?.findings?.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span className={`stat ${f.verified ? "stat-FAIL" : "stat-MANUAL"}`}>
                        {f.verified ? "Verified" : "Unverified"}
                      </span>
                    </td>
                    <td className="mono">{f.repo}</td>
                    <td className="mono">{f.key_id || "—"}</td>
                    <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {f.file_path || "—"}
                    </td>
                    <td>{f.author || "—"}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{f.date || "—"}</td>
                    <td className="mono">{f.commit?.slice(0, 8) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager total={data?.total} page={params.page} pageSize={params.page_size}
            onChange={(p) => setParams((x) => ({ ...x, page: p }))} />
        </>
      )}
    </div>
  );
}

// ── Scorecard Tab ─────────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score == null || score < 0) return "var(--text-dim)";
  if (score >= 8) return "var(--green, #2ecc71)";
  if (score >= 5) return "var(--yellow, #f1c40f)";
  return "var(--red)";
}

function ScorecardTab({ runId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await getScorecard(runId)); }
    finally { setLoading(false); }
  }, [runId]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner />;

  if (!data?.repos?.length) return (
    <div className="card" style={{ padding: 48, textAlign: "center", color: "var(--text-dim)" }}>
      No Scorecard results. Either the engine failed, or no repos were scored.
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {data.repos.map((r) => {
        const isOpen = open === r.repo;
        return (
          <div key={r.repo} className="card" style={{ overflow: "hidden" }}>
            <div
              style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", cursor: "pointer" }}
              onClick={() => setOpen(isOpen ? null : r.repo)}
            >
              {isOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              <span className="mono" style={{ flex: 1 }}>{r.repo}</span>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 600, color: scoreColor(r.repo_score) }}>
                {r.repo_score != null ? `${r.repo_score} / 10` : "—"}
              </span>
            </div>
            {isOpen && (
              <table className="tbl">
                <thead>
                  <tr><th>Check</th><th>Score</th><th>Reason</th></tr>
                </thead>
                <tbody>
                  {r.checks.map((c) => (
                    <tr key={c.check_name}>
                      <td>
                        {c.documentation_url ? (
                          <a href={c.documentation_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
                            {c.check_name}
                          </a>
                        ) : c.check_name}
                      </td>
                      <td style={{ fontFamily: "var(--mono)", color: scoreColor(c.check_score) }}>
                        {c.check_score != null && c.check_score >= 0 ? c.check_score : "?"}
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{c.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Shared components ─────────────────────────────────────────────────────────

function SortTh({ col, cur, onClick, children }) {
  const active = cur.sort_by === col;
  return (
    <th onClick={() => onClick(col)} style={{ color: active ? "var(--text)" : undefined }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
        {children}
        {active
          ? cur.sort_dir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} />
          : <ChevronDown size={12} style={{ opacity: 0.3 }} />}
      </span>
    </th>
  );
}

function Pager({ total, page, pageSize, onChange }) {
  const pages = Math.ceil(total / pageSize);
  if (pages <= 1) return null;
  return (
    <div className="pager">
      <button className="btn btn-ghost" disabled={page === 1} onClick={() => onChange(page - 1)} style={{ padding: "5px 10px" }}>
        ‹
      </button>
      <span>Page {page} of {pages} ({total} total)</span>
      <button className="btn btn-ghost" disabled={page >= pages} onClick={() => onChange(page + 1)} style={{ padding: "5px 10px" }}>
        ›
      </button>
    </div>
  );
}

function Spinner() {
  return <div style={{ color: "var(--text-dim)", padding: 40, textAlign: "center" }}>Loading…</div>;
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
