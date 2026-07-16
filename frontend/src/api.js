const BASE = import.meta.env.VITE_API_URL || "";

export async function api(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...opts.headers },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const createScan = (body) =>
  api("/api/scans", { method: "POST", body: JSON.stringify(body) });

export const listScans = () => api("/api/scans");
export const getScan = (id) => api(`/api/scans/${id}`);

export const getProwlerFindings = (id, params = {}) => {
  const qs = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  ).toString();
  return api(`/api/scans/${id}/prowler${qs ? "?" + qs : ""}`);
};

export const getProwlerFinding = (id, findingId) =>
  api(`/api/scans/${id}/prowler/${findingId}`);

export const getTruffleFindings = (id, params = {}) => {
  const qs = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  ).toString();
  return api(`/api/scans/${id}/truffle${qs ? "?" + qs : ""}`);
};

export const getScorecard = (id) => api(`/api/scans/${id}/scorecard`);

export const getAlerts = (id) => api(`/api/scans/${id}/alerts`);
export const getRawFindings = (id) => api(`/api/scans/${id}/findings/raw`);

// ── RhinoScan native baseline assessment ──────────────────────────────────────

const qs = (params = {}) => {
  const s = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  ).toString();
  return s ? "?" + s : "";
};

export const getProfiles = () => api("/profiles");

export const startScan = (profiles) =>
  api("/scan", { method: "POST", body: JSON.stringify({ profiles }) });

export const getScanStatus = (runId) => api(`/scan/${runId}`);

export const getFindings = (params = {}) => api(`/findings${qs(params)}`);

export const getFindingsSummary = (params = {}) =>
  api(`/findings/summary${qs(params)}`);

export const reportUrl = (runId) =>
  `${BASE}/report/${runId}`;
