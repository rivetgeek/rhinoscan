import React from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import { Shield, LayoutDashboard, Crosshair } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Assess from "./pages/Assess";
import ScanDetail from "./pages/ScanDetail";

export default function App() {
  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <Sidebar />
      <main style={{ flex: 1, overflow: "auto", padding: "32px" }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assess" element={<Assess />} />
          <Route path="/assess/:runId" element={<ScanDetail />} />
          <Route path="/assess/:runId/:tab" element={<ScanDetail />} />
        </Routes>
      </main>
    </div>
  );
}

function Sidebar() {
  const linkStyle = ({ isActive }) => ({
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "9px 14px",
    borderRadius: "5px",
    color: isActive ? "var(--text-hi)" : "var(--text-dim)",
    background: isActive ? "var(--border)" : "transparent",
    fontSize: "13px",
    fontWeight: isActive ? 500 : 400,
    transition: "all .15s",
  });

  return (
    <nav style={{
      width: 220,
      background: "var(--surface)",
      borderRight: "1px solid var(--border)",
      display: "flex",
      flexDirection: "column",
      padding: "0 12px",
      flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{
        padding: "24px 4px 20px",
        borderBottom: "1px solid var(--border)",
        marginBottom: "12px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={20} color="var(--accent)" />
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-hi)", letterSpacing: ".02em" }}>
              RhinoScan
            </div>
            <div style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: ".06em", textTransform: "uppercase" }}>
              Gray Rhino Security
            </div>
          </div>
        </div>
      </div>

      <NavLink to="/" end style={linkStyle}>
        <LayoutDashboard size={15} /> Dashboard
      </NavLink>
      <NavLink to="/assess" style={linkStyle}>
        <Crosshair size={15} /> Assess
      </NavLink>

      <div style={{ flex: 1 }} />

      <div style={{ padding: "16px 4px", borderTop: "1px solid var(--border)" }}>
        <div style={{ fontSize: 10, color: "var(--text-dim)", letterSpacing: ".06em" }}>
          grayrhinosecurity.com
        </div>
      </div>
    </nav>
  );
}
