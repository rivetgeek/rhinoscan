import React, { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, RefreshCw, Download, AlertTriangle, ChevronUp, ChevronDown } from "lucide-react";
import { getScan, getProwlerFindings, getTruffleFindings, getAlerts, getRawFindings } from "../api";

const TABS = ["alerts", "prowler", "secrets"];

export default function ScanDetail() {
  const { jobId, tab = "alerts" } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadJob = useCallback(async () => {
    const data = await getScan(jobId);
    setJob(data);
    setLoading(false);
  }, [jobId]);

  useEffect(() => {
    loadJob();
    const t = setInterval(() => {
      if (job?.status === "running") loadJob();
    }, 4000);
    return () => clearInterval(t);
  }, [loadJob, job?.status]);

  const downloadRaw = async () => {
    const data = await getRawFindings(jobId);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `rhino-${jobId}.json`; a.click();
  };

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 40 }}>Loading…</div>;

  const summary = job?.summary || {};

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <button className="btn btn-ghost" style={{ marginBottom: 16, paddingLeft: 8 }} onClick={() => navigate("/")}>
          <ArrowLeft size={14} /> All Scans
        </button>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 600, color: "var(--text-hi)" }}>
              {truncateArn(job.role_arn)}
            </h1>
            <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
              <span>{job.aws_region}</span>
              {job.github_org && <span>{job.github_org}</span>}
              <span>{formatDate(job.created_at)}</span>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className={`stat stat-${job.status}`}>{job.status}</span>
            <button className="btn btn-ghost" onClick={loadJob}><RefreshCw size={13} /></button>
            <button className="btn btn-ghost" onClick={downloadRaw}><Download size={13} /> JSON</button>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 10, marginBottom: 28 }}>
        {[
          { label: "Critical", value: summary.prowler_by_severity?.critical || 0, cls: "sev-critical" },
          { label: "High", value: summary.prowler_by_severity?.high || 0, cls: "sev-high" },
          { label: "Medium", value: summary.prowler_by_severity?.medium || 0, cls: "sev-medium" },
          { label: "Low", value: summary.prowler_by_severity?.low || 0, cls: "sev-low" },
          { label: "Secrets Found", value: summary.truffle_findings || 0, cls: "sev-critical" },
          { label: "Correlated Alerts", value: summary.correlated_alerts || 0, cls: "sev-critical" },
        ].map(({ label, value, cls }) => (
          <div key={label} className="card" style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 24, fontWeight: 600, color: "var(--text-hi)", fontFamily: "var(--mono)" }}>{value}</div>
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4, textTransform: "uppercase", letterSpacing: ".06em" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border)", marginBottom: 20 }}>
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => navigate(`/scans/${jobId}/${t}`)}
            style={{
              padding: "10px 18px",
              fontSize: 13,
              fontWeight: tab === t ? 600 : 400,
              color: tab === t ? "var(--text-hi)" : "var(--text-dim)",
              background: "none",
              border: "none",
              borderBottom: tab === t ? "2px solid var(--accent)" : "2px solid transparent",
              cursor: "pointer",
              textTransform: "capitalize",
              marginBottom: -1,
            }}
          >
            {t === "alerts" ? `⚠ Alerts (${summary.correlated_alerts || 0})` : t === "prowler" ? `Cloud Findings` : `Secrets`}
          </button>
        ))}
      </div>

      {tab === "alerts" && <AlertsTab jobId={jobId} />}
      {tab === "prowler" && <ProwlerTab jobId={jobId} />}
      {tab === "secrets" && <SecretsTab jobId={jobId} />}
    </div>
  );
}

// ── Alerts Tab ────────────────────────────────────────────────────────────────

function AlertsTab({ jobId }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAlerts(jobId).then(setAlerts).finally(() => setLoading(false));
  }, [jobId]);

  if (loading) return <Spinner />;

  if (!alerts.length) return (
    <div className="card" style={{ padding: 48, textAlign: "center", color: "var(--text-dim)" }}>
      No correlated alerts found. Either no AWS keys were exposed, or the GitHub scan was skipped.
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

function ProwlerTab({ jobId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [params, setParams] = useState({
    severity: "", status: "FAIL", service: "", search: "",
    sort_by: "severity", sort_dir: "desc", page: 1, page_size: 50,
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getProwlerFindings(jobId, params);
      setData(res);
    } finally {
      setLoading(false);
    }
  }, [jobId, params]);

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
                  <tr key={f.id}>
                    <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                    <td><span className={`stat stat-${f.status}`}>{f.status}</span></td>
                    <td className="mono">{f.service}</td>
                    <td>
                      <div style={{ fontSize: 13 }}>{f.check_title}</div>
                      {f.status_extended && <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 3 }}>{f.status_extended}</div>}
                    </td>
                    <td className="mono">{f.region}</td>
                    <td className="mono" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.resource_name || f.resource_arn?.split("/").pop() || "—"}
                    </td>
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

// ── Secrets Tab ───────────────────────────────────────────────────────────────

function SecretsTab({ jobId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [params, setParams] = useState({ search: "", sort_by: "date", sort_dir: "desc", page: 1, page_size: 50 });

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await getTruffleFindings(jobId, params)); }
    finally { setLoading(false); }
  }, [jobId, params]);

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

function truncateArn(arn) {
  const parts = arn?.split(":") || [];
  if (parts.length >= 6) return parts.slice(4).join(":").replace("role/", "");
  return arn;
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
