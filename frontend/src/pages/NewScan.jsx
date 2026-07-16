import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, ArrowLeft } from "lucide-react";
import { createScan, getProfiles } from "../api";

export default function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    profile: "",
    aws_region: "us-west-2",
    github_org: "",
  });
  const [profiles, setProfiles] = useState([]);
  const [profilesError, setProfilesError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    getProfiles()
      .then((res) => setProfiles(res.profiles || []))
      .catch((e) => setProfilesError(e.message));
  }, []);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async () => {
    if (!form.profile) return setError("Select an AWS profile.");
    setLoading(true);
    setError(null);
    try {
      const res = await createScan({
        profile: form.profile,
        aws_region: form.aws_region,
        github_org: form.github_org || undefined,
      });
      navigate(`/assess/${res.job_id}`);
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
        onClick={() => navigate("/assess")}
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
          <Field label="AWS Profile" required>
            <select
              className="select"
              style={{ width: "100%" }}
              value={form.profile}
              onChange={set("profile")}
              disabled={!profiles.length}
            >
              <option value="">
                {profilesError
                  ? "Could not load profiles"
                  : profiles.length
                  ? "Select a profile…"
                  : "Loading profiles…"}
              </option>
              {profiles.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
            <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 6 }}>
              {profilesError
                ? profilesError
                : "Profiles are read from ~/.aws/config. Credentials (SSO, source_profile, role_arn) are resolved by boto3."}
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

        <Section title="GitHub Configuration" subtitle="Optional — enables Prowler GitHub, TruffleHog secrets, and OpenSSF Scorecard">
          <Field label="GitHub Organization">
            <input
              className="input"
              style={{ width: "100%" }}
              placeholder="acme-corp"
              value={form.github_org}
              onChange={set("github_org")}
            />
            <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 6 }}>
              The GitHub token is read from your <span className="mono">gh</span> login
              (<span className="mono">gh auth login</span> / <span className="mono">GH_TOKEN</span>) — no token needed here.
            </div>
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
