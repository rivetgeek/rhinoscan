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

export const getTruffleFindings = (id, params = {}) => {
  const qs = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  ).toString();
  return api(`/api/scans/${id}/truffle${qs ? "?" + qs : ""}`);
};

export const getAlerts = (id) => api(`/api/scans/${id}/alerts`);
export const getRawFindings = (id) => api(`/api/scans/${id}/findings/raw`);
