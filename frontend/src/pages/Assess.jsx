import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Play, RefreshCw, Plus, Shield, Github, CheckCircle2 } from "lucide-react";
import { getProfiles, startScan, getScanStatus, listScans } from "../api";

export default function Assess() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState([]);

  // Baseline assessment (native AWS checks)
  const [baselineTarget, setBaselineTarget] = useState("All");
  const [scanning, setScanning] = useState(false);
  const [lastRun, setLastRun] = useState(null);

  // Prowler + Secrets jobs
  const [jobs, setJobs] = useState([]);
  const [jobsLoading, setJobsLoading] = useState(true);

  useEffect(() => {
    getProfiles().then((d) => setProfiles(d.profiles)).catch(() => {});
  }, []);

  const loadJobs = async () => {
    try {
      setJobs(await listScans());
    } finally {
      setJobsLoading(false);
    }
  };

  useEffect(() => {
    loadJobs();
    const t = setInterval(loadJobs, 5000); // poll for running scans
    return () => clearInterval(t);
  }, []);

  const runBaseline = async () => {
    const targets = baselineTarget === "All" ? profiles : [baselineTarget];
    if (targets.length === 0) return;
    setScanning(true);
    try {
      const { run_ids } = await startScan(targets);
      await pollRuns(run_ids);
      setLastRun(new Date().toISOString());
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ maxWidth: 980 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-hi)" }}>Assess</h1>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 4 }}>
          Launch security scans. Results roll up into the{" "}
          <a onClick={() => navigate("/")} style={{ color: "var(--accent)", cursor: "pointer" }}>
            Dashboard
          </a>
          .
        </p>
      </div>

      {/* ── Baseline Assessment ─────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 24, marginBottom: 20 }}>
        <SectionHead
          icon={<Shield size={16} color="var(--accent)" />}
          title="Baseline Assessment"
          subtitle="Read-only AWS security checks across configured client profiles."
        />
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select
            className="select"
            value={baselineTarget}
            onChange={(e) => setBaselineTarget(e.target.value)}
          >
            <option value="All">All profiles</option>
            {profiles.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={runBaseline} disabled={scanning || !profiles.length}>
            <Play size={14} />
            {scanning ? "Scanning…" : baselineTarget === "All" ? "Scan all profiles" : `Scan ${baselineTarget}`}
          </button>
          {lastRun && !scanning && (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-dim)" }}>
              <CheckCircle2 size={14} color="var(--green, #2ecc71)" /> Completed {formatDate(lastRun)} — view on Dashboard
            </span>
          )}
        </div>
      </div>

      {/* ── Prowler + GitHub Secrets ────────────────────────────────────────── */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16 }}>
          <SectionHead
            icon={<Github size={16} color="var(--accent)" />}
            title="Prowler + GitHub Posture"
            subtitle="Cloud + GitHub benchmark (Prowler), TruffleHog secret scanning with exposure correlation, and OpenSSF Scorecard. GitHub scans use your gh login."
          />
          <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
            <button className="btn btn-ghost" onClick={loadJobs}>
              <RefreshCw size={14} /> Refresh
            </button>
            <button className="btn btn-primary" onClick={() => navigate("/assess/new")}>
              <Plus size={14} /> New Scan
            </button>
          </div>
        </div>

        {jobsLoading ? (
          <div style={{ color: "var(--text-dim)", padding: 32, textAlign: "center" }}>Loading…</div>
        ) : jobs.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center" }}>
            <p style={{ color: "var(--text-dim)", marginBottom: 16 }}>No Prowler / secrets scans yet.</p>
            <button className="btn btn-primary" onClick={() => navigate("/assess/new")}>
              <Plus size={14} /> Start your first scan
            </button>
          </div>
        ) : (
          <div style={{ overflow: "hidden", marginTop: 18, border: "1px solid var(--border)", borderRadius: 6 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Region</th>
                  <th>GitHub Org</th>
                  <th>Prowler</th>
                  <th>GH Prowler</th>
                  <th>TruffleHog</th>
                  <th>Scorecard</th>
                  <th>Status</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr
                    key={j.job_id}
                    style={{ cursor: "pointer" }}
                    onClick={() => navigate(`/assess/${j.job_id}`)}
                  >
                    <td><span className="mono">{j.profile || truncateArn(j.role_arn)}</span></td>
                    <td className="mono">{j.aws_region}</td>
                    <td className="mono">{j.github_org || "—"}</td>
                    <td><span className={`stat stat-${j.prowler_status}`}>{j.prowler_status}</span></td>
                    <td><span className={`stat stat-${j.prowler_github_status}`}>{j.prowler_github_status || "—"}</span></td>
                    <td><span className={`stat stat-${j.truffle_status}`}>{j.truffle_status}</span></td>
                    <td><span className={`stat stat-${j.scorecard_status}`}>{j.scorecard_status || "—"}</span></td>
                    <td><span className={`stat stat-${j.status}`}>{j.status}</span></td>
                    <td className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>
                      {formatDate(j.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

async function pollRuns(runIds, attempts = 60) {
  for (let i = 0; i < attempts; i++) {
    const statuses = await Promise.all(runIds.map((id) => getScanStatus(id).catch(() => null)));
    if (statuses.every((s) => s && s.status !== "running")) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
}

function SectionHead({ icon, title, subtitle }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {icon}
        <span style={{ fontSize: 15, fontWeight: 600, color: "var(--text-hi)" }}>{title}</span>
      </div>
      {subtitle && (
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 5 }}>{subtitle}</p>
      )}
    </div>
  );
}

function truncateArn(arn) {
  const parts = arn?.split(":") || [];
  if (parts.length >= 6) return parts.slice(4).join(":").replace("role/", "");
  return arn;
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}
