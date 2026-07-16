const BASE = import.meta.env.VITE_API_URL || "";
const V1 = "/api/v1";

export async function api(path, opts = {}) {
  const res = await fetch(`${BASE}${V1}${path}`, {
    headers: { "Content-Type": "application/json", ...opts.headers },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

const qs = (params = {}) => {
  const s = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  ).toString();
  return s ? "?" + s : "";
};

// ── Targets + engines ─────────────────────────────────────────────────────────

export const getProfiles = () => api("/profiles");
export const getEngines = () => api("/engines");

// ── Scans (runs) ──────────────────────────────────────────────────────────────

export const startScans = (targets, engines) =>
  api("/scans", { method: "POST", body: JSON.stringify({ targets, engines }) });

export const listRuns = (limit = 50) => api(`/scans${qs({ limit })}`);
export const getRun = (runId) => api(`/scans/${runId}`);

// ── Engine raw-detail views ───────────────────────────────────────────────────

export const getProwlerFindings = (runId, params = {}) =>
  api(`/scans/${runId}/prowler${qs(params)}`);

export const getProwlerFinding = (runId, findingId) =>
  api(`/scans/${runId}/prowler/${findingId}`);

export const getSecretFindings = (runId, params = {}) =>
  api(`/scans/${runId}/secrets${qs(params)}`);

export const getScorecard = (runId) => api(`/scans/${runId}/scorecard`);
export const getAlerts = (runId) => api(`/scans/${runId}/alerts`);

// ── Unified findings ──────────────────────────────────────────────────────────

export const getFindings = (params = {}) => api(`/findings${qs(params)}`);
export const getFindingsSummary = (params = {}) => api(`/findings/summary${qs(params)}`);

// ── Report + export (direct download links) ───────────────────────────────────

export const reportUrl = (runId) => `${BASE}${V1}/report/${runId}`;
export const exportUrl = (params = {}) => `${BASE}${V1}/export${qs(params)}`;
