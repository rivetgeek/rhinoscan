import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, Crosshair, ChevronRight, ChevronDown, Download } from "lucide-react";
import {
  getProfiles,
  getFindings,
  getFindingsSummary,
  exportUrl,
} from "../api";

export default function Dashboard() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState([]);
  const [source, setSource] = useState("All"); // "All" | target
  const [summary, setSummary] = useState(null);
  const [data, setData] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState(null);
  const [originFilter, setOriginFilter] = useState(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  const target = source === "All" ? undefined : source;

  // AWS profiles from ~/.aws/config plus every target that has findings (so
  // scanned github:<org> targets are selectable, not just AWS profiles).
  const selectableTargets = Array.from(
    new Set([...profiles, ...(summary?.targets || [])])
  ).sort();

  const load = async () => {
    const [sum, f] = await Promise.all([
      getFindingsSummary({ target }),
      getFindings({
        target,
        category: categoryFilter || undefined,
        origin: originFilter || undefined,
        page,
        page_size: 100,
      }),
    ]);
    setSummary(sum);
    setData(f);
    setLoading(false);
  };

  useEffect(() => {
    getProfiles().then((d) => setProfiles(d.profiles)).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
  }, [source, categoryFilter, originFilter, page]);

  useEffect(() => {
    const t = setInterval(load, 10000); // keep numbers live while scans run
    return () => clearInterval(t);
  }, [source, categoryFilter, originFilter, page]);

  const pickCategory = (c) => {
    setPage(1);
    setCategoryFilter(c === categoryFilter ? null : c);
  };
  const pickOrigin = (o) => {
    setPage(1);
    setOriginFilter(o === originFilter ? null : o);
  };

  return (
    <div>
      <Header
        source={source}
        setSource={(s) => { setPage(1); setSource(s); }}
        profiles={selectableTargets}
        onRefresh={load}
        onAssess={() => navigate("/assess")}
        target={target}
      />

      {loading && !data ? (
        <div style={{ color: "var(--text-dim)", padding: 40, textAlign: "center" }}>Loading…</div>
      ) : (
        <>
          <SummaryCards summary={summary} />
          <OriginFilter summary={summary} active={originFilter} onPick={pickOrigin} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, marginTop: 12 }}>
            <FindingsTable
              data={data}
              page={page}
              setPage={setPage}
              categoryFilter={categoryFilter}
              clearCategory={() => pickCategory(categoryFilter)}
            />
            <CategoryBreakdown
              summary={summary}
              active={categoryFilter}
              onPick={pickCategory}
            />
          </div>
        </>
      )}
    </div>
  );
}

function Header({ source, setSource, profiles, onRefresh, onAssess, target }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-hi)" }}>Dashboard</h1>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 4 }}>
          Aggregated security findings — view by target or across all.
        </p>
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <select className="select" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="All">All targets</option>
          {profiles.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <a className="btn btn-ghost" href={exportUrl({ target })} download title="Hephaestus export (NDJSON)">
          <Download size={14} /> Export
        </a>
        <button className="btn btn-ghost" onClick={onRefresh}>
          <RefreshCw size={14} /> Refresh
        </button>
        <button className="btn btn-primary" onClick={onAssess}>
          <Crosshair size={14} /> Run a scan
        </button>
      </div>
    </div>
  );
}

function SummaryCards({ summary }) {
  const sev = summary?.by_severity || {};
  const cards = [
    { label: "Critical", value: sev.Critical || 0, color: "var(--red)" },
    { label: "High", value: sev.High || 0, color: "var(--accent)" },
    { label: "Medium", value: sev.Medium || 0, color: "var(--yellow)" },
    // Combined so the four severity cards sum to the total finding count
    // (matching the source badges); Low/Informational are otherwise omitted.
    { label: "Low / Info", value: (sev.Low || 0) + (sev.Informational || 0), color: "var(--text-dim)" },
    { label: "Targets scanned", value: summary?.accounts_scanned || 0, color: "var(--text-hi)" },
    { label: "Last scan", value: fmtDate(summary?.last_scan), color: "var(--text-hi)", small: true },
  ];
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12 }}>
      {cards.map((c) => (
        <div key={c.label} className="card" style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)" }}>
            {c.label}
          </div>
          <div style={{ fontSize: c.small ? 14 : 26, fontWeight: 600, color: c.color, marginTop: 6 }}>
            {c.value}
          </div>
        </div>
      ))}
    </div>
  );
}

function OriginFilter({ summary, active, onPick }) {
  const byOrigin = summary?.by_origin || {};
  const entries = Object.entries(byOrigin).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return null;
  return (
    <div style={{ display: "flex", gap: 6, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
      <span style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)", marginRight: 4 }}>
        Source
      </span>
      {entries.map(([origin, count]) => (
        <span
          key={origin}
          onClick={() => onPick(origin)}
          style={{ cursor: "pointer", opacity: active && active !== origin ? 0.4 : 1 }}
        >
          <OriginBadge origin={origin} suffix={` ${count}`} active={active === origin} />
        </span>
      ))}
    </div>
  );
}

function FindingsTable({ data, page, setPage, categoryFilter, clearCategory }) {
  const [expanded, setExpanded] = useState(null);
  const findings = data?.findings || [];
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      {categoryFilter && (
        <div style={{ padding: "8px 14px", fontSize: 12, color: "var(--text-dim)", borderBottom: "1px solid var(--border)" }}>
          Filtered to <b style={{ color: "var(--accent)" }}>{categoryFilter}</b>
          <button className="btn btn-ghost" style={{ marginLeft: 10, padding: "2px 8px" }} onClick={clearCategory}>
            Clear
          </button>
        </div>
      )}
      <div style={{ overflowX: "auto" }}>
      <table className="tbl">
        <thead>
          <tr>
            <th style={{ width: 28 }}></th>
            <th>Severity</th>
            <th>Source</th>
            <th>Category</th>
            <th>Title</th>
            <th>Resource</th>
            <th>Target</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {findings.length === 0 && (
            <tr><td colSpan={8} style={{ textAlign: "center", color: "var(--text-dim)", padding: 30 }}>No findings — run a scan.</td></tr>
          )}
          {findings.map((f) => (
            <React.Fragment key={f.id}>
              <tr style={{ cursor: "pointer" }} onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <td>{expanded === f.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                <td><span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                <td><OriginBadge origin={f.origin} /></td>
                <td>{f.category}</td>
                <td>{f.title}</td>
                <td className="mono">
                  {/* max-width is ignored on auto-layout table cells; truncate in an inner block instead */}
                  <div style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.resource}>
                    {f.resource}
                  </div>
                </td>
                <td className="mono">{f.profile}</td>
                <td className="mono" style={{ fontSize: 11 }}>{fmtDate(f.timestamp)}</td>
              </tr>
              {expanded === f.id && (
                <tr>
                  <td colSpan={8} style={{ background: "var(--bg)" }}>
                    <div style={{ padding: "6px 4px 10px", display: "flex", flexDirection: "column", gap: 10 }}>
                      <Detail label="Description" value={f.description} />
                      <Detail label="Remediation" value={f.remediation} />
                      <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                        <Detail label="Source" value={f.origin || "Baseline"} />
                        <Detail label="Check" value={f.source} mono />
                        <Detail label="AWS API" value={f.api || "—"} mono />
                      </div>
                      <RawResults raw={f.raw} />
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      </div>
      {data && data.total > data.page_size && (
        <div className="pager" style={{ padding: "10px 14px" }}>
          <button className="btn btn-ghost" disabled={page === 1} onClick={() => setPage(page - 1)} style={{ padding: "5px 10px" }}>
            ‹
          </button>
          <span>Page {page} of {Math.ceil(data.total / data.page_size)} ({data.total} total)</span>
          <button
            className="btn btn-ghost"
            disabled={page >= Math.ceil(data.total / data.page_size)}
            onClick={() => setPage(page + 1)}
            style={{ padding: "5px 10px" }}
          >
            ›
          </button>
        </div>
      )}
    </div>
  );
}

const ORIGIN_COLORS = {
  Baseline: "var(--accent)",
  Prowler: "var(--yellow)",
  GitHub: "var(--text-hi)",
  Secrets: "var(--red)",
  Scorecard: "var(--green, #2ecc71)",
};

function OriginBadge({ origin, suffix = "", active }) {
  const o = origin || "Baseline";
  const color = ORIGIN_COLORS[o] || "var(--text-dim)";
  return (
    <span
      className="mono"
      style={{
        fontSize: 11,
        padding: "1px 7px",
        borderRadius: 4,
        border: `1px solid ${color}`,
        color,
        whiteSpace: "nowrap",
        background: active ? `color-mix(in srgb, ${color} 15%, transparent)` : "transparent",
      }}
    >
      {o}{suffix}
    </span>
  );
}

function RawResults({ raw }) {
  if (raw == null || (typeof raw === "object" && Object.keys(raw).length === 0)) {
    return null;
  }
  const text = JSON.stringify(raw, null, 2);
  return (
    <div>
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--text-dim)", marginBottom: 3 }}>
        Raw API response
      </div>
      <pre
        className="mono"
        style={{
          margin: 0,
          padding: 10,
          background: "var(--bg-hi, #0c0c0c)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          fontSize: 11,
          lineHeight: 1.5,
          color: "var(--text)",
          maxHeight: 280,
          overflow: "auto",
          whiteSpace: "pre",
        }}
      >
        {text}
      </pre>
    </div>
  );
}

function CategoryBreakdown({ summary, active, onPick }) {
  const byCat = summary?.by_category || {};
  const entries = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="card" style={{ padding: 18, height: "fit-content" }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-hi)", marginBottom: 14 }}>
        By Category
      </div>
      {entries.length === 0 && <div style={{ fontSize: 12, color: "var(--text-dim)" }}>No findings.</div>}
      {entries.map(([cat, count]) => (
        <div
          key={cat}
          onClick={() => onPick(cat)}
          style={{ cursor: "pointer", marginBottom: 10, opacity: active && active !== cat ? 0.4 : 1 }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
            <span style={{ color: active === cat ? "var(--accent)" : "var(--text)" }}>{cat}</span>
            <span className="mono" style={{ color: "var(--text-dim)" }}>{count}</span>
          </div>
          <div style={{ height: 6, background: "var(--bg)", borderRadius: 3, overflow: "hidden" }}>
            <div style={{ width: `${(count / max) * 100}%`, height: "100%", background: active === cat ? "var(--accent)" : "var(--border-hi)" }} />
          </div>
        </div>
      ))}
    </div>
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

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}
