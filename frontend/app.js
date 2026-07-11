/* SentinelX UI — real React via vendored UMD + htm, no build step.
   Talks to /v1/login, /v1/investigations[/{id}[/narrative]], /v1/audit/verify.

   Auth model: v1 is a single-tenant self-hosted deploy, so there is one shared
   analyst token (SENTINELX_TOKEN on the backend) rather than per-user accounts.
   The login screen validates that token via POST /v1/login and this file keeps
   it in localStorage, attaching it as a Bearer header on every request — the
   same mechanism the agent uses. A 401 anywhere logs the session out. Real
   multi-analyst accounts / SSO is a bigger post-v1 feature (see docs/adr). */
const html = htm.bind(React.createElement);
const { useState, useEffect, useCallback } = React;

const TOKEN_KEY = "sx_token";
const riskColor = (r) => (r >= 80 ? "var(--risk-high)" : r >= 50 ? "var(--risk-med)" : "var(--risk-low)");
const riskWord = (r) => (r >= 80 ? "High" : r >= 50 ? "Medium" : "Low");
const nodeColor = { process: "var(--node-proc)", file: "var(--node-file)", socket: "var(--node-sock)", dns: "var(--node-dns)" };

function Root() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken("");
  }, []);

  const login = useCallback((t) => {
    localStorage.setItem(TOKEN_KEY, t);
    setToken(t);
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

  return token ? html`<${App} api=${api} onLogout=${logout} />` : html`<${Login} onLogin=${login} />`;
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
      .then(() => onLogin(value))
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
        <p className="hint">Single shared credential for this deployment (<code>SENTINELX_TOKEN</code>) — not a multi-user account system.</p>
      </form>
    </div>`;
}

function App({ api, onLogout }) {
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [narr, setNarr] = useState(null);
  const [audit, setAudit] = useState(null);
  const [dark, setDark] = useState(false);

  const refresh = () => api("/v1/investigations").then((d) => setList(d || [])).catch(() => {});

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
    api(`/v1/investigations/${sel}`).then(setDetail).catch(() => {});
    api(`/v1/investigations/${sel}/narrative`).then(setNarr).catch(() => {});
  }, [sel]);

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  }, [dark]);

  return html`
    <div className="top">
      <div className="brand">
        <span className="logo">Sentinel<b>X</b></span>
        <span className="tag">endpoint detection & response</span>
      </div>
      <div className="spacer"></div>
      <span className="chip"><span className="dot"></span>${list.length} investigation${list.length === 1 ? "" : "s"}</span>
      ${audit && html`<span className=${"chip " + (audit.intact ? "ok" : "bad")}>
        <span className="dot"></span>evidence chain ${audit.intact ? "intact" : "broken"}
      </span>`}
      <button className="tbtn" title="Toggle theme" onClick=${() => setDark((d) => !d)}>${dark ? "☀" : "☾"}</button>
      <button className="tbtn" title="Sign out" onClick=${onLogout}>⏻</button>
    </div>
    <div className="layout">
      <div className="list">
        ${list.length === 0 && html`<div className="empty"><div className="big">No investigations yet</div>Ingest telemetry to begin.</div>`}
        ${list.map((inv) => html`
          <div key=${inv.id} className=${"item" + (inv.id === sel ? " sel" : "")} onClick=${() => setSel(inv.id)}>
            <div className="r1">
              <span className="name">#${inv.id} <span>· ${inv.host}</span></span>
              <span className="riskpill" style=${{ color: riskColor(inv.risk_score) }}>
                <span className="d" style=${{ background: riskColor(inv.risk_score) }}></span>${inv.risk_score}
              </span>
            </div>
            <div className="meta">${inv.detection_count} detections · ${inv.event_count} events</div>
            <div className="tags">${(inv.techniques || []).map((t) => html`<span key=${t} className="tag">${t}</span>`)}</div>
          </div>`)}
      </div>
      <div className="detail">
        <div className="inner">
          ${detail ? html`<${Detail} inv=${detail} narr=${narr} />` : html`<div className="empty">Select an investigation.</div>`}
        </div>
      </div>
    </div>`;
}

function Detail({ inv, narr }) {
  const c = riskColor(inv.risk_score);
  return html`
    <div className="head">
      <div className="ring" style=${{ "--pct": inv.risk_score, "--c": c }}>
        <div className="inner">
          <div className="num" style=${{ color: c }}>${inv.risk_score}</div>
          <div className="lbl">risk</div>
        </div>
      </div>
      <div>
        <h2>Investigation #${inv.id} · ${riskWord(inv.risk_score)} risk</h2>
        <div className="sub">host <code>${inv.host}</code> · lineage root <code>${(inv.root_guid || "").slice(0, 12)}</code> · ${(inv.techniques || []).join("  ·  ")}</div>
      </div>
    </div>

    ${narr && html`
      <div className="card">
        <h3>Narrative <span className="note">· grounded, ${narr.rejected} rejected</span></h3>
        <div className="narr">${narr.text}</div>
      </div>`}

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

/* Clickable alert row: collapsed shows the rule + technique + severity; expanded
   reveals exactly which events triggered it and the analyst-facing fix. This is
   the "what's triggering the threat and how do I fix it" drill-down. */
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

/* Two-column provenance layout: processes left, objects right, curved edges,
   haloed labels so nothing collides even where edges cross. */
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
        // Only label the informative crossing edges (exec/write/connect), placed
        // out in the whitespace near the object end; lineage (spawned) is implied
        // by the vertical chain, so it stays unlabeled to reduce clutter.
        const lx = a.x + (b.x - a.x) * 0.66, ly = a.y + (b.y - a.y) * 0.66 - 5;
        return html`<g key=${i}>
          <path d=${d} fill="none" stroke=${rare ? "var(--accent)" : "var(--edge)"} stroke-width=${rare ? 1.8 : 1.2} opacity=${rare ? 0.95 : 0.7} />
          ${crossing && html`<text x=${lx} y=${ly} fill="var(--muted)" font-size="9.5" text-anchor="middle" style=${halo}>${e.rel}</text>`}
        </g>`;
      })}
      ${nodes.map((n, i) => {
        const p = pos[n.id]; if (!p) return null;
        const fill = n.is_hub ? "var(--node-hub)" : (nodeColor[n.kind] || "var(--muted)");
        // Process labels sit ABOVE the node so horizontal edge lines never strike
        // through the text; object labels sit to the right in open space.
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
