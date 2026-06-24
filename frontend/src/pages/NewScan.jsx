import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, ArrowLeft } from "lucide-react";
import { createScan } from "../api";

export default function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    role_arn: "",
    aws_region: "us-east-1",
    github_org: "",
    github_token: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async () => {
    if (!form.role_arn) return setError("Role ARN is required.");
    setLoading(true);
    setError(null);
    try {
      const res = await createScan({
        role_arn: form.role_arn,
        aws_region: form.aws_region,
        github_org: form.github_org || undefined,
        github_token: form.github_token || undefined,
      });
      navigate(`/scans/${res.job_id}`);
    } catch (e) {
      setError(e.message);
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 560 }}>
      <button
        className="btn btn-ghost"
        style={{ marginBottom: 24, paddingLeft: 8 }}
        onClick={() => navigate("/")}
      >
        <ArrowLeft size={14} /> Back
      </button>

      <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-hi)", marginBottom: 6 }}>
        New Scan
      </h1>
      <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 28 }}>
        Configure the target environment. AWS scan is required; GitHub scan is optional.
      </p>

      <div className="card" style={{ padding: 28 }}>
        <Section title="AWS Configuration">
          <Field label="IAM Role ARN" required>
            <input
              className="input"
              style={{ width: "100%" }}
              placeholder="arn:aws:iam::123456789012:role/RhinoScanRole"
              value={form.role_arn}
              onChange={set("role_arn")}
            />
            <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 6 }}>
              The role must trust your scanner's AWS identity and have SecurityAudit + IAMReadOnlyAccess.
            </div>
          </Field>

          <Field label="Primary Region">
            <select className="select" value={form.aws_region} onChange={set("aws_region")}>
              {["us-east-1","us-east-2","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-southeast-1","ap-northeast-1"].map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </Field>
        </Section>

        <Section title="GitHub Configuration" subtitle="Optional — enables TruffleHog secret scanning">
          <Field label="GitHub Organization">
            <input
              className="input"
              style={{ width: "100%" }}
              placeholder="acme-corp"
              value={form.github_org}
              onChange={set("github_org")}
            />
          </Field>

          <Field label="GitHub Token">
            <input
              className="input"
              style={{ width: "100%" }}
              type="password"
              placeholder="ghp_… or fine-grained token with repo read access"
              value={form.github_token}
              onChange={set("github_token")}
            />
          </Field>
        </Section>

        {error && (
          <div style={{
            padding: "10px 14px",
            background: "var(--red-lo)",
            border: "1px solid #e74c3c40",
            borderRadius: 4,
            color: "var(--red)",
            fontSize: 13,
            marginBottom: 16,
          }}>
            {error}
          </div>
        )}

        <button
          className="btn btn-primary"
          style={{ width: "100%", justifyContent: "center", padding: "11px 0" }}
          onClick={submit}
          disabled={loading}
        >
          <Shield size={15} />
          {loading ? "Starting scan…" : "Start Scan"}
        </button>
      </div>
    </div>
  );
}

function Section({ title, subtitle, children }) {
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ marginBottom: 16, paddingBottom: 10, borderBottom: "1px solid var(--border)" }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-hi)" }}>{title}</div>
        {subtitle && <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 3 }}>{subtitle}</div>}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>{children}</div>
    </div>
  );
}

function Field({ label, required, children }) {
  return (
    <div>
      <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: "var(--text-dim)", marginBottom: 6, textTransform: "uppercase", letterSpacing: ".06em" }}>
        {label}{required && <span style={{ color: "var(--accent)", marginLeft: 3 }}>*</span>}
      </label>
      {children}
    </div>
  );
}
