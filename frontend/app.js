/* SentinelX UI — real React via vendored UMD + htm, no build step.
   Talks to the backend API: /v1/investigations[/{id}[/narrative]], /v1/audit/verify. */
const html = htm.bind(React.createElement);
const { useState, useEffect } = React;

const riskClass = (r) => (r >= 80 ? "high" : r >= 50 ? "med" : "low");
const kindColor = { process: "var(--proc)", file: "var(--file)", socket: "var(--sock)", dns: "var(--dns)" };

function App() {
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [narr, setNarr] = useState(null);
  const [audit, setAudit] = useState(null);

  const refresh = () =>
    fetch("/v1/investigations").then((r) => r.json()).then((d) => setList(d || []));

  useEffect(() => {
    refresh();
    fetch("/v1/audit/verify").then((r) => r.json()).then(setAudit).catch(() => {});
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (sel == null) return;
    fetch(`/v1/investigations/${sel}`).then((r) => r.json()).then(setDetail);
    fetch(`/v1/investigations/${sel}/narrative`).then((r) => r.json()).then(setNarr);
  }, [sel]);

  return html`
    <div className="top">
      <h1><span className="brand">Sentinel</span>X</h1>
      <span className="badge">${list.length} investigation${list.length === 1 ? "" : "s"}</span>
      ${audit &&
        html`<span className=${"badge " + (audit.intact ? "ok" : "bad")}>
          evidence chain ${audit.intact ? "intact" : "BROKEN"} · ${audit.entries} entries
        </span>`}
    </div>
    <div className="layout">
      <div className="list">
        ${list.length === 0 && html`<div className="empty">No investigations yet.<br/>Ingest telemetry to begin.</div>`}
        ${list.map(
          (inv) => html`
            <div key=${inv.id} className=${"card" + (inv.id === sel ? " sel" : "")} onClick=${() => setSel(inv.id)}>
              <div className="row">
                <strong>#${inv.id} · ${inv.host}</strong>
                <span className=${"risk " + riskClass(inv.risk_score)}>${inv.risk_score}</span>
              </div>
              <div className="sub" style=${{ margin: "4px 0 0" }}>
                ${inv.detection_count} detections · ${inv.event_count} events
              </div>
              <div className="tags">${(inv.techniques || []).map((t) => html`<span key=${t} className="tag">${t}</span>`)}</div>
            </div>`
        )}
      </div>
      <div className="detail">
        ${detail ? html`<${Detail} inv=${detail} narr=${narr} />` : html`<div className="empty">Select an investigation.</div>`}
      </div>
    </div>`;
}

function Detail({ inv, narr }) {
  return html`
    <h2>Investigation #${inv.id}
      <span className=${"risk " + riskClass(inv.risk_score)} style=${{ marginLeft: 8 }}>risk ${inv.risk_score}/100</span>
    </h2>
    <div className="sub">host ${inv.host} · root <span className="mono">${inv.root_guid}</span> · ${(inv.techniques || []).join(", ")}</div>

    ${narr &&
      html`<div className="panel"><h3>Narrative <span style=${{ color: "var(--muted)", textTransform: "none" }}>(grounded · ${narr.rejected} rejected)</span></h3>
        <div className="narr">${narr.text}</div></div>`}

    <div className="panel"><h3>Provenance graph</h3><${Graph} nodes=${inv.nodes || []} edges=${inv.edges || []} /></div>

    <div className="grid">
      <div className="panel"><h3>Timeline</h3>
        <ul className="tl">
          ${(inv.timeline || []).map(
            (e, i) => html`<li key=${i}>
              <span className="t">${(e.ts || "").slice(11, 19)}</span>
              <span className="k">${e.type}</span>
              <span className="mono">${e.image}${e.detail ? " → " + e.detail : ""}</span>
            </li>`
          )}
        </ul>
      </div>
      <div className="panel"><h3>Risk breakdown (auditable)</h3>
        ${(inv.score_factors || []).map(
          (f, i) => html`<div key=${i} className="factor">
            <span>${f.Factor}${f.Mult && f.Mult !== 1 ? ` ×${f.Mult}` : ""}</span>
            <span className="ev">${f.Contrib ? "+" + f.Contrib : f.Note || ""} ${(f.Events || []).join(",")}</span>
          </div>`
        )}
      </div>
    </div>`;
}

/* Deterministic layered layout: processes down the center by time, objects to
   the right, edges as lines. Enough to read an attack chain without a lib. */
function Graph({ nodes, edges }) {
  if (!nodes.length) return html`<div className="sub">No graph (Postgres-loaded investigations rebuild the graph in memory on rewarm).</div>`;
  const W = 720, rowH = 42, pad = 20;
  const procs = nodes.filter((n) => n.kind === "process");
  const objs = nodes.filter((n) => n.kind !== "process");
  const pos = {};
  procs.forEach((n, i) => (pos[n.id] = { x: 150, y: pad + i * rowH }));
  objs.forEach((n, i) => (pos[n.id] = { x: 470, y: pad + i * rowH }));
  const H = pad * 2 + Math.max(procs.length, objs.length) * rowH;
  const short = (s) => (s.length > 34 ? "…" + s.slice(-33) : s);

  return html`
    <svg width="100%" viewBox=${`0 0 ${W} ${H}`} style=${{ background: "var(--panel2)", borderRadius: 8 }}>
      ${edges.map((e, i) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        return html`<g key=${i}>
          <line x1=${a.x} y1=${a.y} x2=${b.x} y2=${b.y} stroke=${e.weight > 0.8 ? "var(--accent)" : "var(--line)"} stroke-width=${e.weight > 0.8 ? 1.8 : 1} />
          <text x=${(a.x + b.x) / 2} y=${(a.y + b.y) / 2 - 3} fill="var(--muted)" font-size="9" text-anchor="middle">${e.rel}</text>
        </g>`;
      })}
      ${nodes.map((n, i) => {
        const p = pos[n.id]; if (!p) return null;
        return html`<g key=${i}>
          <circle cx=${p.x} cy=${p.y} r=${n.is_hub ? 8 : 6} fill=${n.is_hub ? "var(--hub)" : (kindColor[n.kind] || "var(--muted)")} />
          <text x=${p.x + 12} y=${p.y + 4} fill="var(--text)" font-size="11">${short(n.label || n.id)}${n.is_hub ? " (hub)" : ""}</text>
        </g>`;
      })}
    </svg>
    <div className="legend">
      <span><span className="dot" style=${{ background: "var(--proc)" }}></span>process</span>
      <span><span className="dot" style=${{ background: "var(--file)" }}></span>file</span>
      <span><span className="dot" style=${{ background: "var(--sock)" }}></span>socket</span>
      <span><span className="dot" style=${{ background: "var(--hub)" }}></span>hub (boundary)</span>
      <span><span className="dot" style=${{ background: "var(--accent)" }}></span>rare edge</span>
    </div>`;
}

ReactDOM.createRoot(document.getElementById("root")).render(html`<${App} />`);
