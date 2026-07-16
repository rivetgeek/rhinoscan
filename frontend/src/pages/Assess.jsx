import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Play, RefreshCw, Shield, Github } from "lucide-react";
import { getProfiles, getEngines, startScans, listRuns } from "../api";

export default function Assess() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState([]);
  const [engines, setEngines] = useState([]);

  // Scan composer state
  const [selectedProfiles, setSelectedProfiles] = useState(new Set());
  const [githubOrg, setGithubOrg] = useState("");
  const [selectedEngines, setSelectedEngines] = useState(new Set());
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState(null);

  // Runs list
  const [runs, setRuns] = useState([]);
  const [runsLoading, setRunsLoading] = useState(true);

  useEffect(() => {
    getProfiles().then((d) => setProfiles(d.profiles)).catch(() => {});
    getEngines().then((d) => {
      setEngines(d.engines);
      setSelectedEngines(new Set(d.engines.map((e) => e.name)));
    }).catch(() => {});
  }, []);

  const loadRuns = async () => {
    try {
      const d = await listRuns();
      setRuns(d.runs);
    } finally {
      setRunsLoading(false);
    }
  };

  useEffect(() => {
    loadRuns();
    const t = setInterval(loadRuns, 5000); // poll for running scans
    return () => clearInterval(t);
  }, []);

  const targets = useMemo(() => {
    const list = [...selectedProfiles];
    if (githubOrg.trim()) list.push(`github:${githubOrg.trim()}`);
    return list;
  }, [selectedProfiles, githubOrg]);

  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      await startScans(targets, [...selectedEngines]);
      await loadRuns();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setStarting(false);
    }
  };

  const toggle = (set, setter) => (value) => {
    const next = new Set(set);
    next.has(value) ? next.delete(value) : next.add(value);
    setter(next);
  };
  const toggleProfile = toggle(selectedProfiles, setSelectedProfiles);
  const toggleEngine = toggle(selectedEngines, setSelectedEngines);

  const awsEngines = engines.filter((e) => e.target_type === "aws");
  const githubEngines = engines.filter((e) => e.target_type === "github");

  return (
    <div style={{ maxWidth: 1080 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-hi)" }}>Assess</h1>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 4 }}>
          Pick targets and engines, launch a scan. Findings from every engine roll up into the{" "}
          <a onClick={() => navigate("/")} style={{ color: "var(--accent)", cursor: "pointer" }}>
            Dashboard
          </a>
          .
        </p>
      </div>

      {/* ── Scan composer ───────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 24, marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 28 }}>
          {/* Targets */}
          <div>
            <GroupHead icon={<Shield size={14} color="var(--accent)" />} label="AWS profiles" />
            {profiles.length === 0 && (
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No profiles found in ~/.aws/config.</div>
            )}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {profiles.map((p) => (
                <Chip key={p} active={selectedProfiles.has(p)} onClick={() => toggleProfile(p)}>
                  {p}
                </Chip>
              ))}
            </div>

            <GroupHead icon={<Github size={14} color="var(--accent)" />} label="GitHub org" style={{ marginTop: 18 }} />
            <input
              className="input"
              placeholder="org name (optional)"
              value={githubOrg}
              onChange={(e) => setGithubOrg(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>

          {/* Engines */}
          <div>
            <GroupHead label="AWS engines" />
            {awsEngines.map((e) => (
              <EngineRow key={e.name} engine={e} checked={selectedEngines.has(e.name)} onToggle={() => toggleEngine(e.name)} />
            ))}
            <GroupHead label="GitHub engines" style={{ marginTop: 14 }} />
            {githubEngines.map((e) => (
              <EngineRow key={e.name} engine={e} checked={selectedEngines.has(e.name)} onToggle={() => toggleEngine(e.name)} />
            ))}
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 22, paddingTop: 18, borderTop: "1px solid var(--border)" }}>
          <button
            className="btn btn-primary"
            onClick={start}
            disabled={starting || targets.length === 0 || selectedEngines.size === 0}
          >
            <Play size={14} />
            {starting
              ? "Starting…"
              : `Scan ${targets.length || "—"} target${targets.length === 1 ? "" : "s"}`}
          </button>
          {error && <span style={{ fontSize: 12, color: "var(--red)" }}>{error}</span>}
        </div>
      </div>

      {/* ── Runs ────────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 20px" }}>
          <span style={{ fontSize: 15, fontWeight: 600, color: "var(--text-hi)" }}>Runs</span>
          <button className="btn btn-ghost" onClick={loadRuns}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>

        {runsLoading ? (
          <div style={{ color: "var(--text-dim)", padding: 32, textAlign: "center" }}>Loading…</div>
        ) : runs.length === 0 ? (
          <div style={{ color: "var(--text-dim)", padding: 40, textAlign: "center" }}>
            No scans yet — compose one above.
          </div>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>Target</th>
                <th>Engines</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.run_id} style={{ cursor: "pointer" }} onClick={() => navigate(`/assess/${r.run_id}`)}>
                  <td className="mono">{r.target}</td>
                  <td>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {(r.engines || []).map((e) => (
                        <span key={e} className={`stat stat-${r.engine_status?.[e] || "pending"}`} title={e}>
                          {shortEngine(e)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td><span className={`stat stat-${r.status}`}>{r.status}</span></td>
                  <td className="mono">{r.finding_count ?? "—"}</td>
                  <td className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    {formatDate(r.started_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function shortEngine(name) {
  return {
    "baseline": "baseline",
    "prowler-aws": "prowler",
    "prowler-github": "gh-prowler",
    "trufflehog": "secrets",
    "scorecard": "scorecard",
  }[name] || name;
}

function GroupHead({ icon, label, style }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10, ...style }}>
      {icon}
      <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)" }}>
        {label}
      </span>
    </div>
  );
}

function Chip({ active, onClick, children }) {
  return (
    <span
      className="mono"
      onClick={onClick}
      style={{
        fontSize: 12,
        padding: "4px 10px",
        borderRadius: 4,
        cursor: "pointer",
        border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
        color: active ? "var(--accent)" : "var(--text)",
        background: active ? "color-mix(in srgb, var(--accent) 12%, transparent)" : "transparent",
      }}
    >
      {children}
    </span>
  );
}

function EngineRow({ engine, checked, onToggle }) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", cursor: "pointer", fontSize: 13 }}>
      <input type="checkbox" checked={checked} onChange={onToggle} />
      <span style={{ color: "var(--text)" }}>{engine.label}</span>
    </label>
  );
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}
