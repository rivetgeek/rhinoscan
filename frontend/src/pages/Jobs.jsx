import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, RefreshCw } from "lucide-react";
import { listScans } from "../api";

export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const load = async () => {
    try {
      const data = await listScans();
      setJobs(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 5000); // poll for running scans
    return () => clearInterval(t);
  }, []);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-hi)" }}>Scan Jobs</h1>
          <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 4 }}>
            Each scan runs Prowler + TruffleHog against a client environment.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-ghost" onClick={load}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={() => navigate("/new")}>
            <Plus size={14} /> New Scan
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ color: "var(--text-dim)", padding: 40, textAlign: "center" }}>Loading…</div>
      ) : jobs.length === 0 ? (
        <div className="card" style={{ padding: 60, textAlign: "center" }}>
          <p style={{ color: "var(--text-dim)", marginBottom: 16 }}>No scans yet.</p>
          <button className="btn btn-primary" onClick={() => navigate("/new")}>
            <Plus size={14} /> Start your first scan
          </button>
        </div>
      ) : (
        <div className="card" style={{ overflow: "hidden" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Target</th>
                <th>Region</th>
                <th>GitHub Org</th>
                <th>Prowler</th>
                <th>TruffleHog</th>
                <th>Status</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr
                  key={j.job_id}
                  style={{ cursor: "pointer" }}
                  onClick={() => navigate(`/scans/${j.job_id}`)}
                >
                  <td>
                    <span className="mono">{truncateArn(j.role_arn)}</span>
                  </td>
                  <td className="mono">{j.aws_region}</td>
                  <td className="mono">{j.github_org || "—"}</td>
                  <td><span className={`stat stat-${j.prowler_status}`}>{j.prowler_status}</span></td>
                  <td><span className={`stat stat-${j.truffle_status}`}>{j.truffle_status}</span></td>
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
  );
}

function truncateArn(arn) {
  // arn:aws:iam::123456789012:role/RoleName → 123456789012/RoleName
  const parts = arn?.split(":") || [];
  if (parts.length >= 6) return parts.slice(4).join(":").replace("role/", "");
  return arn;
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}
