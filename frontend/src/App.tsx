import { useState } from "react";

type Finding = {
  id: string;
  title: string;
  category: string;
  severity: number;
  confidence: number;
  description: string;
  recommendation: string;
};

type ScanResult = {
  target: string;
  scanned_at: string;
  findings: Finding[];
  score: number;
  level: "Low" | "Medium" | "High" | "Critical";
};

export default function App() {
  const [url, setUrl] = useState("https://example.com");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  async function runScan() {
    setError("");
    setLoading(true);
    setResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) throw new Error(await res.text());
      const data = (await res.json()) as ScanResult;
      setResult(data);
    } catch (e: any) {
      setError(e?.message || "Error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 900, margin: "40px auto", fontFamily: "system-ui" }}>
      <h1>Security Risk Assessment Tool</h1>
      <p style={{ opacity: 0.8 }}>
        Passive checks only: HTTPS/TLS, Security Headers, Cookies, basic info leakage.
      </p>

      <div style={{ display: "flex", gap: 12, marginTop: 12 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1, padding: 10, fontSize: 16 }}
          placeholder="https://example.com"
        />
        <button onClick={runScan} disabled={loading} style={{ padding: "10px 16px" }}>
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {error && <p style={{ color: "crimson" }}>{error}</p>}

      {result && (
        <div style={{ marginTop: 20 }}>
          <h2>Result</h2>
          <p><b>Target:</b> {result.target}</p>
          <p><b>Risk Score:</b> {result.score}/100</p>
          <p><b>Risk Level:</b> {result.level}</p>

          <h3>Findings ({result.findings.length})</h3>
          <ul style={{ paddingLeft: 18 }}>
            {result.findings
              .slice()
              .sort((a, b) => b.severity - a.severity)
              .map((f) => (
                <li key={f.id} style={{ marginBottom: 14 }}>
                  <b>{f.title}</b>{" "}
                  <span style={{ opacity: 0.8 }}>
                    — {f.category} — Severity: {f.severity}/10
                  </span>
                  <div style={{ marginTop: 6 }}>{f.description}</div>
                  <div style={{ marginTop: 6 }}>
                    <i>Recommendation:</i> {f.recommendation}
                  </div>
                </li>
              ))}
          </ul>
        </div>
      )}
    </div>
  );
}

