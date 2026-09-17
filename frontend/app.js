/* SentinelX UI — real React via vendored UMD + htm, no build step.
   Talks to /v1/login, /v1/investigations[/{id}[/narrative]], /v1/audit/verify, /v1/triage/eval.

   Auth model: one API token per tenant (customer org), resolved server-side by
   backend/tenant.Store — real data isolation, but still one key per tenant, not
   per-user accounts within a tenant. The login screen validates the token via
   POST /v1/login, which also returns the tenant's display name so the analyst
   can see which org they're signed into. The token lives in localStorage and is
   attached as a Bearer header on every request, same as the agent. A 401
   anywhere logs the session out. Multi-user-per-tenant accounts / SSO is a
   separate, bigger post-v1 feature (see docs/adr/0005-multi-tenancy.md). */
const html = htm.bind(React.createElement);
const { useState, useEffect, useCallback } = React;

const TOKEN_KEY = "sx_token";
const riskColor = (r) => (r >= 80 ? "var(--risk-high)" : r >= 50 ? "var(--risk-med)" : "var(--risk-low)");
const riskWord = (r) => (r >= 80 ? "High" : r >= 50 ? "Medium" : "Low");
const nodeColor = { process: "var(--node-proc)", file: "var(--node-file)", socket: "var(--node-sock)", dns: "var(--node-dns)" };

function Root() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [tenantName, setTenantName] = useState("");

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken("");
    setTenantName("");
  }, []);

  const login = useCallback((t, name) => {
    localStorage.setItem(TOKEN_KEY, t);
    setToken(t);
    setTenantName(name || "");
  }, []);

  // Shared fetch wrapper: attaches the bearer token, and any 401 anywhere in the
  // app drops the session back to the login screen rather than failing silently.
  const api = useCallback((path, opts) => {
    return fetch(path, { ...opts, headers: { ...(opts && opts.headers), Authorization: "Bearer " + token } })
      .then((r) => {
        if (r.status === 401) { logout(); throw new Error("unauthorized"); }
        return r.json();
      });
  }, [token, logout]);

  return token
    ? html`<${App} api=${api} onLogout=${logout} tenantName=${tenantName} />`
    : html`<${Login} onLogin=${login} />`;
}

function Login({ onLogin }) {
  const [value, setValue] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = (e) => {
    e.preventDefault();
    if (!value) return;
    setBusy(true); setErr("");
    fetch("/v1/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: value }) })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((body) => onLogin(value, body.tenant))
      .catch(() => setErr("Invalid token."))
      .finally(() => setBusy(false));
  };

  return html`
    <div className="loginwrap">
      <form className="loginbox" onSubmit=${submit}>
        <div className="brand center">
          <span className="logo">Sentinel<b>X</b></span>
        </div>
        <p className="sub center">Sign in with your analyst token to view investigations.</p>
        <input
          type="password" autoFocus placeholder="Analyst token" value=${value}
          onChange=${(e) => setValue(e.target.value)} className="tokinput" />
        ${err && html`<div className="loginerr">${err}</div>`}
        <button type="submit" className="loginbtn" disabled=${busy}>${busy ? "Checking…" : "Sign in"}</button>
        <p className="hint">One API token per organization — you'll only ever see your own org's investigations.</p>
      </form>
    </div>`;
}

function App({ api, onLogout, tenantName }) {
  const [view, setView] = useState("overview"); // "overview" | "investigations" | "triage_eval"
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [narr, setNarr] = useState(null);
  const [audit, setAudit] = useState(null);
  const [dark, setDark] = useState(false);

  const refresh = () => api("/v1/investigations").then((d) => setList(d || [])).catch(() => {});
  const refreshDetail = (id) => api(`/v1/investigations/${id}`).then(setDetail).catch(() => {});

  useEffect(() => {
    refresh();
    api("/v1/audit/verify").then(setAudit).catch(() => {});
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => { // auto-select the first investigation once loaded
    if (sel == null && list.length) setSel(list[0].id);
  }, [list, sel]);

  useEffect(() => {
    if (sel == null) return;
    refreshDetail(sel);
    api(`/v1/investigations/${sel}/narrative`).then(setNarr).catch(() => {});
  }, [sel]);

  const setStatus = (id, status) =>
    api(`/v1/investigations/${id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    }).then(() => {
      refresh();
      if (id === sel) refreshDetail(id);
    });

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  }, [dark]);

  return html`
    <div className="top">
      <div className="brand">
        <span className="logo">Sentinel<b>X</b></span>
        <span className="tag">${tenantName || "endpoint detection & response"}</span>
      </div>
      <div className="tabs">
        <button className=${"tabbtn" + (view === "overview" ? " active" : "")} onClick=${() => setView("overview")}>Overview</button>
        <button className=${"tabbtn" + (view === "investigations" ? " active" : "")} onClick=${() => setView("investigations")}>Investigations</button>
        <button className=${"tabbtn" + (view === "triage_eval" ? " active" : "")} onClick=${() => setView("triage_eval")}>Triage Eval</button>
      </div>
      <div className="spacer"></div>
      <span className="chip"><span className="dot"></span>${list.length} investigation${list.length === 1 ? "" : "s"}</span>
      ${audit && html`<span className=${"chip " + (audit.intact ? "ok" : "bad")}>
        <span className="dot"></span>evidence chain ${audit.intact ? "intact" : "broken"}
      </span>`}
      <button className="tbtn" title="Toggle theme" onClick=${() => setDark((d) => !d)}>${dark ? "☀" : "☾"}</button>
      <button className="tbtn" title="Sign out" onClick=${onLogout}>⏻</button>
    </div>
    ${view === "overview" && html`<div className="overviewpage"><${Overview} list=${list} onOpen=${(id) => { setSel(id); setView("investigations"); }} /></div>`}
    ${view === "triage_eval" && html`<div className="overviewpage"><${TriageEvalView} api=${api} /></div>`}
    ${view === "investigations" && html`
      <div className="layout">
        <div className="list">
          ${list.length === 0 && html`<div className="empty"><div className="big">No investigations yet</div>Ingest telemetry to begin.</div>`}
          ${list.map((inv) => html`
            <div key=${inv.id} className=${"item" + (inv.id === sel ? " sel" : "") + (inv.status !== "open" ? " closed" : "")} onClick=${() => setSel(inv.id)}>
              <div className="r1">
                <span className="name">#${inv.id} <span>· ${inv.host}</span></span>
                <span className="riskpill" style=${{ color: riskColor(inv.risk_score) }}>
                  <span className="d" style=${{ background: riskColor(inv.risk_score) }}></span>${inv.risk_score}
                </span>
              </div>
              <div className="meta">${inv.detection_count} detections · ${inv.event_count} events
                ${inv.status !== "open" && html` · <span className=${"statuslbl " + inv.status}>${inv.status}</span>`}
              </div>
              <div className="tags">${(inv.techniques || []).map((t) => html`<span key=${t} className="tag">${t}</span>`)}</div>
            </div>`)}
        </div>
        <div className="detail">
          <div className="inner">
            ${detail ? html`<${Detail} inv=${detail} narr=${narr} api=${api} onSetStatus=${setStatus} />` : html`<div className="empty">Select an investigation.</div>`}
          </div>
        </div>
      </div>`}`;
}

/* ---------- Triage Eval Benchmark Dashboard ---------- */

function TriageEvalView({ api }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const loadEval = () => {
    setLoading(true); setErr("");
    api("/v1/triage/eval")
      .then(setReport)
      .catch((e) => setErr(e.message || "Failed to load evaluation"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadEval(); }, []);

  if (loading && !report) {
    return html`<div className="empty"><div className="big">Running Triage Evaluation…</div>Executing tool loop and sandbox reproduction on held-out scenarios.</div>`;
  }
  if (err && !report) {
    return html`<div className="empty"><div className="big">Evaluation Error</div><p>${err}</p><button className="actbtn" onClick=${loadEval}>Retry</button></div>`;
  }
  if (!report) return null;

  return html`
    <div>
      <div className="headrow" style=${{ alignItems: "center", marginBottom: "16px" }}>
        <div>
          <h2>Held-Out Evaluation Harness</h2>
          <div className="sub">Accuracy, false-positive rate, failure taxonomy, and confound resilience across held-out scenarios.</div>
        </div>
        <button className="actbtn" style=${{ background: "var(--accent)", color: "#fff", border: "none" }} disabled=${loading} onClick=${loadEval}>
          ${loading ? "Evaluating…" : "↺ Re-run Evaluation"}
        </button>
      </div>

      <div className="stats-row">
        <${StatTile} label="Accuracy" value=${(report.accuracy * 100).toFixed(1) + "%"} tone="var(--risk-low)" />
        <${StatTile} label="False Positive Rate" value=${(report.false_positive_rate * 100).toFixed(1) + "%"} />
        <${StatTile} label="False Negative Rate" value=${(report.false_negative_rate * 100).toFixed(1) + "%"} />
        <${StatTile} label="Confound Resilience" value=${(report.confound_resilience * 100).toFixed(1) + "%"} tone="var(--accent)" />
        <${StatTile} label="Confusion Matrix" value=${`TP=${report.tp} FP=${report.fp} TN=${report.tn} FN=${report.fn}`} />
      </div>

      <div className="grid2" style=${{ marginBottom: "16px" }}>
        <div className="card">
          <h3>Failure Taxonomy <span className="note">· misclassifications categorized</span></h3>
          ${Object.keys(report.failure_taxonomy || {}).length === 0
            ? html`<div className="sub" style=${{ color: "var(--risk-low)" }}>✓ Zero classification failures across held-out set.</div>`
            : Object.entries(report.failure_taxonomy).map(([cat, count]) => html`
                <div key=${cat} className="factor">
                  <span className="f"><b>${cat}</b></span>
                  <span className="v"><span className="amt">${count}</span></span>
                </div>`)}
        </div>
        <div className="card">
          <h3>Anti-Confound Verification Policy</h3>
          <div className="sub" style=${{ lineHeight: "1.6" }}>
            The Triage Agent tool loop cross-examines attacker claims (comments, decoy command names, indirect prompt injections) with raw eBPF execution events and physical sandbox execution side-effects. Attacker narration is ignored in favor of verifiable kernel telemetry.
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Held-Out Scenarios Breakdown</h3>
        <table style=${{ width: "100%", borderCollapse: "collapse", fontSize: "13px", marginTop: "10px" }}>
          <thead>
            <tr style=${{ borderBottom: "1px solid var(--line)", textAlign: "left" }}>
              <th style=${{ padding: "8px" }}>Scenario ID</th>
              <th style=${{ padding: "8px" }}>Category</th>
              <th style=${{ padding: "8px" }}>Expected</th>
              <th style=${{ padding: "8px" }}>Actual</th>
              <th style=${{ padding: "8px" }}>Outcome</th>
              <th style=${{ padding: "8px" }}>Confound Status</th>
            </tr>
          </thead>
          <tbody>
            ${(report.results || []).map((r) => html`
              <tr key=${r.scenario_id} style=${{ borderBottom: "1px solid var(--line)" }}>
                <td style=${{ padding: "8px" }} className="mono"><b>${r.scenario_id}</b></td>
                <td style=${{ padding: "8px" }}>${r.category}</td>
                <td style=${{ padding: "8px" }}>${r.expected_exploitable ? "Exploitable" : "Benign"}</td>
                <td style=${{ padding: "8px" }}>${r.actual_exploitable ? "Exploitable" : "Benign"}</td>
                <td style=${{ padding: "8px" }}>
                  <span className="statuspill" style=${{
                    background: r.outcome === "TP" || r.outcome === "TN" ? "var(--risk-low)" : "var(--risk-high)",
                    color: "#fff"
                  }}>${r.outcome}</span>
                </td>
                <td style=${{ padding: "8px" }}>
                  ${r.is_confound_trap
                    ? (r.confound_passed
                        ? html`<span style=${{ color: "var(--risk-low)", fontWeight: "bold" }}>PASS (Resilient)</span>`
                        : html`<span style=${{ color: "var(--risk-high)", fontWeight: "bold" }}>FAIL (Trapped)</span>`)
                    : html`<span style=${{ color: "var(--muted)" }}>N/A</span>`}
                </td>
              </tr>`)}
          </tbody>
        </table>
      </div>
    </div>`;
}

/* ---------- Overview dashboard ---------- */

function dayKey(iso) { return (iso || "").slice(0, 10); }

function aggregate(list) {
  const total = list.length;
  const open = list.filter((i) => i.status === "open").length;
  const high = list.filter((i) => i.risk_score >= 80).length;
  const med = list.filter((i) => i.risk_score >= 50 && i.risk_score < 80).length;
  const low = total - high - med;
  const avgRisk = total ? Math.round(list.reduce((s, i) => s + i.risk_score, 0) / total) : 0;

  const byDay = new Map();
  for (const inv of list) {
    const k = dayKey(inv.first_seen);
    byDay.set(k, (byDay.get(k) || 0) + 1);
  }
  const days = [...byDay.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  const techCount = new Map();
  for (const inv of list) for (const t of inv.techniques || []) techCount.set(t, (techCount.get(t) || 0) + 1);
  const techniques = [...techCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);

  return { total, open, high, med, low, avgRisk, days, techniques, techCovered: techCount.size };
}

function Overview({ list, onOpen }) {
  const a = aggregate(list);
  if (list.length === 0) {
    return html`<div className="empty"><div className="big">No investigations yet</div>Ingest telemetry to see fleet-wide trends here.</div>`;
  }
  return html`
    <div className="stats-row">
      <${StatTile} label="Investigations" value=${a.total} />
      <${StatTile} label="Open" value=${a.open} />
      <${StatTile} label="High risk" value=${a.high} tone="var(--risk-high)" />
      <${StatTile} label="Avg risk score" value=${a.avgRisk} tone=${riskColor(a.avgRisk)} />
      <${StatTile} label="MITRE techniques seen" value=${a.techCovered} />
    </div>
    <div className="grid2">
      <div className="card">
        <h3>Investigations over time</h3>
        <${TimeChart} days=${a.days} />
      </div>
      <div className="card">
        <h3>Risk distribution</h3>
        <${RiskDist} high=${a.high} med=${a.med} low=${a.low} total=${a.total} />
      </div>
    </div>
    <div className="card">
      <h3>Top MITRE techniques <span className="note">· by investigations affected</span></h3>
      <${RankBars} data=${a.techniques} />
    </div>
    <div className="card">
      <h3>Highest-risk investigations</h3>
      ${[...list].sort((x, y) => y.risk_score - x.risk_score).slice(0, 5).map((inv) => html`
        <div key=${inv.id} className="factor" style=${{ cursor: "pointer" }} onClick=${() => onOpen(inv.id)}>
          <span className="f">#${inv.id} <small>${inv.host}</small></span>
          <span className="v">
            <span className="amt" style=${{ color: riskColor(inv.risk_score) }}>${inv.risk_score}</span>
            <span className="ev">${(inv.techniques || []).join(", ")}</span>
          </span>
        </div>`)}
    </div>`;
}

function StatTile({ label, value, tone }) {
  return html`
    <div className="stattile">
      <div className="stattile-val" style=${tone ? { color: tone } : null}>${value}</div>
      <div className="stattile-lbl">${label}</div>
    </div>`;
}

function TimeChart({ days }) {
  const [hover, setHover] = useState(null);
  if (!days.length) return html`<div className="sub" style=${{ color: "var(--muted)" }}>Not enough data yet.</div>`;
  const W = 560, H = 180, pad = 28, gap = 10;
  const max = Math.max(...days.map((d) => d[1]), 1);
  const bw = Math.min(40, (W - pad * 2) / days.length - gap);
  return html`
    <div style=${{ position: "relative" }}>
      <svg width="100%" viewBox=${`0 0 ${W} ${H}`} role="img">
        <line x1=${pad} y1=${H - pad} x2=${W - pad} y2=${H - pad} stroke="var(--line)" stroke-width="1" />
        ${days.map(([k, v], i) => {
          const x = pad + i * (bw + gap);
          const h = ((H - pad * 2) * v) / max;
          const y = H - pad - h;
          return html`<rect key=${k} x=${x} y=${y} width=${bw} height=${Math.max(h, 2)} rx="3"
            fill="var(--accent)" opacity=${hover === i ? 1 : 0.85}
            onMouseEnter=${() => setHover(i)} onMouseLeave=${() => setHover(null)} style=${{ cursor: "pointer" }} />`;
        })}
        ${days.map(([k], i) => {
          const x = pad + i * (bw + gap) + bw / 2;
          return html`<text key=${"l" + k} x=${x} y=${H - pad + 14} font-size="9.5" fill="var(--muted)" text-anchor="middle">${k.slice(5)}</text>`;
        })}
      </svg>
      ${hover != null && html`<div className="tooltip" style=${{ left: (pad + hover * (bw + gap) + bw / 2) / W * 100 + "%", top: 8 }}>
        ${days[hover][0]} · ${days[hover][1]} investigation${days[hover][1] === 1 ? "" : "s"}
      </div>`}
    </div>`;
}

function RankBars({ data }) {
  if (!data.length) return html`<div className="sub" style=${{ color: "var(--muted)" }}>No detections yet.</div>`;
  const max = Math.max(...data.map((d) => d[1]), 1);
  return html`<div className="rankbars">
    ${data.map(([tech, n]) => html`
      <div key=${tech} className="rankrow">
        <span className="rankname mono">${tech}</span>
        <div className="rankbar-track">
          <div className="rankbar-fill" style=${{ width: (n / max) * 100 + "%" }}></div>
        </div>
        <span className="rankval">${n}</span>
      </div>`)}
  </div>`;
}

function RiskDist({ high, med, low, total }) {
  if (!total) return null;
  const seg = (n, color, label) => html`
    <div className="riskseg">
      <div className="riskseg-top">
        <span className="d" style=${{ background: color }}></span>
        <span>${label}</span>
        <span className="spacer"></span>
        <span className="riskseg-n">${n}</span>
      </div>
      <div className="riskseg-track"><div className="riskseg-fill" style=${{ width: (n / total) * 100 + "%", background: color }}></div></div>
    </div>`;
  return html`<div>
    ${seg(high, "var(--risk-high)", "High risk (≥80)")}
    ${seg(med, "var(--risk-med)", "Medium risk (50–79)")}
    ${seg(low, "var(--risk-low)", "Low risk (<50)")}
  </div>`;
}

function Detail({ inv, narr, api, onSetStatus }) {
  const c = riskColor(inv.risk_score);
  const [busy, setBusy] = useState(false);
  const [triageData, setTriageData] = useState(null);
  const [triageLoading, setTriageLoading] = useState(false);

  const act = (status) => {
    setBusy(true);
    onSetStatus(inv.id, status).finally(() => setBusy(false));
  };

  const runTriage = () => {
    setTriageLoading(true);
    api(`/v1/investigations/${inv.id}/triage`)
      .then(setTriageData)
      .catch(() => {})
      .finally(() => setTriageLoading(false));
  };

  return html`
    <div className="head">
      <div className="ring" style=${{ "--pct": inv.risk_score, "--c": c }}>
        <div className="inner">
          <div className="num" style=${{ color: c }}>${inv.risk_score}</div>
          <div className="lbl">risk</div>
        </div>
      </div>
      <div style=${{ flex: 1 }}>
        <div className="headrow">
          <h2>Investigation #${inv.id} · ${riskWord(inv.risk_score)} risk</h2>
          ${inv.status !== "open" && html`<span className=${"statuspill " + inv.status}>${inv.status}</span>`}
        </div>
        <div className="sub">host <code>${inv.host}</code> · lineage root <code>${(inv.root_guid || "").slice(0, 12)}</code> · ${(inv.techniques || []).join("  ·  ")}</div>
      </div>
      <div className="actions">
        ${inv.status === "open"
          ? html`
            <button className="actbtn resolve" disabled=${busy} onClick=${() => act("resolved")}>✓ Resolve</button>
            <button className="actbtn dismiss" disabled=${busy} onClick=${() => act("dismissed")}>✕ Dismiss as FP</button>`
          : html`<button className="actbtn" disabled=${busy} onClick=${() => act("open")}>↺ Reopen</button>`}
      </div>
    </div>

    ${narr && html`
      <div className="card">
        <h3>Narrative <span className="note">· grounded, ${narr.rejected} rejected</span></h3>
        <div className="narr">${narr.text}</div>
      </div>`}

    <div className="card">
      <div className="headrow" style=${{ alignItems: "center", marginBottom: "8px" }}>
        <h3>Triage Agent <span className="note">· tool-using loop & sandbox execution</span></h3>
        <button className="actbtn" style=${{ background: "var(--accent)", color: "#fff", border: "none" }} disabled=${triageLoading} onClick=${runTriage}>
          ${triageLoading ? "Running Triage…" : triageData ? "Re-run Triage" : "⚡ Run Triage Agent"}
        </button>
      </div>
      ${triageData && html`<${TriageVerdictView} verdict=${triageData} />`}
      ${!triageData && !triageLoading && html`<div className="sub" style=${{ color: "var(--muted)" }}>Click 'Run Triage Agent' to execute the sandbox reproduction loop and anti-confound analysis.</div>`}
    </div>

    <div className="card">
      <h3>Detections <span className="note">· click an alert for what fired and how to fix it</span></h3>
      ${(inv.detections || []).map((d, i) => html`<${DetectionRow} key=${i} d=${d} />`)}
      ${(!inv.detections || inv.detections.length === 0) && html`<div className="sub" style=${{ color: "var(--muted)" }}>No detection detail (investigation predates a backend restart without rewarm).</div>`}
    </div>

    <div className="card">
      <h3>Provenance graph</h3>
      <${Graph} nodes=${inv.nodes || []} edges=${inv.edges || []} />
    </div>

    <div className="grid2">
      <div className="card">
        <h3>Timeline</h3>
        <ul className="tl">
          ${(inv.timeline || []).map((e, i) => html`
            <li key=${i}>
              <span className="t">${(e.ts || "").slice(11, 19)}</span>
              <span className="k">${e.type}</span>
              <span className="mono">${e.image}${e.detail ? " → " + e.detail : ""}</span>
            </li>`)}
        </ul>
      </div>
      <div className="card">
        <h3>Risk breakdown <span className="note">· auditable</span></h3>
        ${(inv.score_factors || []).map((f, i) => html`
          <div key=${i} className="factor">
            <span className="f">${f.Factor}${f.Mult && f.Mult !== 1 ? html` <small>×${f.Mult}</small>` : ""}</span>
            <span className="v">
              <span className="amt">${f.Contrib ? "+" + f.Contrib : (f.Note || "")}</span>
              ${(f.Events || []).length ? html`<span className="ev">${(f.Events || []).join(", ")}</span>` : ""}
            </span>
          </div>`)}
      </div>
    </div>`;
}

function TriageVerdictView({ verdict }) {
  const [showTrace, setShowTrace] = useState(false);
  const badgeColor = verdict.exploitable ? "var(--risk-high)" : "var(--risk-low)";
  return html`
    <div className="triage-box" style=${{ marginTop: "8px", borderTop: "1px solid var(--line)", paddingTop: "8px" }}>
      <div className="headrow" style=${{ alignItems: "center", marginBottom: "12px" }}>
        <span className="statuspill" style=${{ background: badgeColor, color: "#fff", fontWeight: "bold", padding: "4px 10px" }}>
          ${verdict.exploitable ? "EXPLOITABLE" : "NON-EXPLOITABLE"}
        </span>
        <span className="mono" style=${{ marginLeft: "12px", color: "var(--ink)", fontSize: "13px" }}>
          Confidence: ${(verdict.confidence * 100).toFixed(0)}%
        </span>
        <span className="spacer"></span>
        ${verdict.trace && verdict.trace.length > 0 && html`
          <button className="tbtn" style=${{ fontSize: "12px", textDecoration: "underline" }} onClick=${() => setShowTrace((s) => !s)}>
            ${showTrace ? "Hide Reasoning Trace" : `View Loop Trace (${verdict.trace.length} steps)`}
          </button>`}
      </div>

      <div className="detfield" style=${{ marginBottom: "12px", background: "var(--surface)", padding: "10px", borderRadius: "6px", border: "1px solid var(--line)" }}>
        <div className="detlabel" style=${{ color: "var(--accent)", fontWeight: "bold" }}>🛡️ Confound Check (Attacker Narration Verification)</div>
        <div style=${{ fontSize: "13px", marginTop: "4px", color: "var(--ink)" }}>${verdict.confound_check}</div>
      </div>

      ${showTrace && verdict.trace && html`
        <div style=${{ marginBottom: "14px", background: "var(--surface)", padding: "10px", borderRadius: "6px", border: "1px dashed var(--line)" }}>
          <div className="detlabel" style=${{ fontWeight: "bold", marginBottom: "8px" }}>Agent Tool-Using Loop Trace</div>
          ${verdict.trace.map((step) => html`
            <div key=${step.step} style=${{ marginBottom: "8px", fontSize: "12px" }}>
              <span className="mono" style=${{ color: "var(--accent)", fontWeight: "bold" }}>Step ${step.step} (${step.tool}):</span> ${step.thought}
            </div>`)}
        </div>`}

      <div className="grid2">
        <div>
          <div className="detlabel" style=${{ fontWeight: "bold", marginBottom: "6px" }}>Reproduction Steps (Sandbox)</div>
          <ul className="tl" style=${{ paddingLeft: "0", listStyle: "none" }}>
            ${(verdict.reproduction_steps || []).map((s, i) => html`
              <li key=${i} style=${{ marginBottom: "4px", fontSize: "12px" }} className="mono">${s}</li>`)}
          </ul>
        </div>
        <div>
          <div className="detlabel" style=${{ fontWeight: "bold", marginBottom: "6px" }}>Triaged Evidence</div>
          <ul style=${{ paddingLeft: "16px", margin: 0 }}>
            ${(verdict.evidence || []).map((e, i) => html`
              <li key=${i} style=${{ marginBottom: "4px", fontSize: "12px" }}>${e}</li>`)}
          </ul>
        </div>
      </div>
    </div>`;
}

function DetectionRow({ d }) {
  const [open, setOpen] = useState(false);
  return html`
    <div className=${"detrow" + (open ? " open" : "")} onClick=${() => setOpen((o) => !o)}>
      <div className="detrow-head">
        <span className="chevron">${open ? "⌄" : "›"}</span>
        <span className="detrule">${d.rule_id}</span>
        <span className="tags">${(d.technique || []).map((t) => html`<span key=${t} className="tag">${t}</span>`)}</span>
        <span className="spacer"></span>
        <span className="detsev">severity ${d.severity}</span>
      </div>
      ${open && html`
        <div className="detrow-body">
          <div className="detfield">
            <div className="detlabel">Triggering events</div>
            <div className="mono">${(d.event_ids || []).join(", ")}</div>
          </div>
          <div className="detfield">
            <div className="detlabel">Suggested fix</div>
            <div className="fix">${d.remediation || "No remediation guidance recorded for this rule."}</div>
          </div>
        </div>`}
    </div>`;
}

function Graph({ nodes, edges }) {
  if (!nodes.length) return html`<div className="sub" style=${{ color: "var(--muted)" }}>Graph rebuilds in memory on Postgres rewarm.</div>`;
  const rowH = 52, pad = 22, xL = 150, xR = 560, W = 780;
  const procs = nodes.filter((n) => n.kind === "process");
  const objs = nodes.filter((n) => n.kind !== "process");
  const pos = {};
  procs.forEach((n, i) => (pos[n.id] = { x: xL, y: pad + i * rowH, side: "L" }));
  objs.forEach((n, i) => (pos[n.id] = { x: xR, y: pad + i * rowH, side: "R" }));
  const H = pad * 2 + Math.max(procs.length, objs.length, 1) * rowH;
  const short = (s) => (s && s.length > 30 ? "…" + s.slice(-29) : s || "");
  const halo = { paintOrder: "stroke", stroke: "var(--surface)", strokeWidth: 3.5, strokeLinejoin: "round" };

  return html`
    <svg width="100%" viewBox=${`0 0 ${W} ${H}`} role="img" style=${{ display: "block" }}>
      ${edges.map((e, i) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        const rare = e.weight > 0.8;
        const crossing = a.side !== b.side;
        const mx = (a.x + b.x) / 2;
        const d = `M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`;
        const lx = a.x + (b.x - a.x) * 0.66, ly = a.y + (b.y - a.y) * 0.66 - 5;
        return html`<g key=${i}>
          <path d=${d} fill="none" stroke=${rare ? "var(--accent)" : "var(--edge)"} stroke-width=${rare ? 1.8 : 1.2} opacity=${rare ? 0.95 : 0.7} />
          ${crossing && html`<text x=${lx} y=${ly} fill="var(--muted)" font-size="9.5" text-anchor="middle" style=${halo}>${e.rel}</text>`}
        </g>`;
      })}
      ${nodes.map((n, i) => {
        const p = pos[n.id]; if (!p) return null;
        const fill = n.is_hub ? "var(--node-hub)" : (nodeColor[n.kind] || "var(--muted)");
        const lx = p.side === "L" ? p.x : p.x + 12;
        const ly = p.side === "L" ? p.y - 10 : p.y + 4;
        return html`<g key=${i}>
          <circle cx=${p.x} cy=${p.y} r=${n.is_hub ? 7 : 5.5} fill=${fill} stroke="var(--surface)" stroke-width="1.5" />
          <text x=${lx} y=${ly} text-anchor="start" fill="var(--ink)" font-size="11.5" style=${halo}>
            ${short(n.label || n.id)}${n.is_hub ? "  ·hub" : ""}
          </text>
        </g>`;
      })}
    </svg>
    <div className="legend">
      <span><span className="d" style=${{ background: "var(--node-proc)" }}></span>process</span>
      <span><span className="d" style=${{ background: "var(--node-file)" }}></span>file</span>
      <span><span className="d" style=${{ background: "var(--node-sock)" }}></span>socket</span>
      <span><span className="d" style=${{ background: "var(--node-hub)" }}></span>hub · boundary</span>
      <span><span className="d" style=${{ background: "var(--accent)" }}></span>rare edge</span>
    </div>`;
}

ReactDOM.createRoot(document.getElementById("root")).render(html`<${Root} />`);
