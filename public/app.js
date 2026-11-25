const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const api = async (url, opt) => { const r = await fetch(url, opt); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.statusText); return j; };
const post = (url, body, m = 'POST') => api(url, { method: m, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const ls = { get: (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} } };
let tt; const toast = (m) => { $('toast').textContent = m; $('toast').classList.add('on'); clearTimeout(tt); tt = setTimeout(() => $('toast').classList.remove('on'), 2600); };

/* ---------- tema, navigazione ---------- */
const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
applyTheme(ls.get('theme', null));
$('theme').onclick = () => { const dark = (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light')) === 'dark'; const t = dark ? 'light' : 'dark'; ls.set('theme', t); applyTheme(t); };
function view(v) {
  document.querySelectorAll('.nav[data-v]').forEach((x) => x.classList.toggle('on', x.dataset.v === v));
  for (const k of ['an', 'rep', 'cfg']) $('v-' + k).classList.toggle('hide', k !== v);
  if (v === 'rep' && !$('rep').innerHTML) loadList(); if (v === 'cfg') loadCfg();
}
document.querySelectorAll('.nav[data-v]').forEach((b) => b.onclick = () => { if (b.dataset.v === 'rep') { $('rep').innerHTML = ''; } view(b.dataset.v); });

async function quota() {
  try { const u = await api('/api/usage'); const p = Math.min(100, u.used / u.limit * 100);
    $('gMonth').textContent = u.month; $('gBar').style.width = p + '%'; $('gBar').style.background = p > 85 ? 'var(--crit)' : p > 60 ? 'var(--high)' : '';
    $('gTxt').textContent = `${u.used} / ${u.limit} usati · ${u.remaining} residui`; $('aiHint').textContent = `Residuo mese: ${u.remaining} token. Senza AI il costo è 0.`;
    if ($('quota')) $('quota').textContent = `${u.used}/${u.limit}`; if ($('u_used')) $('u_used').value = u.used; } catch {}
}
quota();

/* ---------- picker cartella ---------- */
let cur = '';
async function browse(p) {
  try { const d = await api('/api/fs' + (p ? '?path=' + encodeURIComponent(p) : '')); cur = d.path; $('mpath').textContent = d.path + (d.isGit ? '  ✔ git' : '');
    $('mlist').innerHTML = (d.parent ? `<div class="dirx" data-p="${esc(d.parent)}">⬆ ..</div>` : '') + d.dirs.map((x) => `<div class="dirx" data-p="${esc(d.path.replace(/\/$/, '') + '/' + x)}">📁 ${esc(x)}</div>`).join('') || '<div class="empty">Nessuna sottocartella</div>';
    $('mlist').querySelectorAll('.dirx').forEach((e) => e.onclick = () => browse(e.dataset.p)); } catch (e) { toast(e.message); }
}
$('pick').onclick = () => { $('modal').classList.add('on'); browse($('path').value || ''); };
$('mclose').onclick = () => $('modal').classList.remove('on');
$('mok').onclick = () => { $('path').value = cur; $('modal').classList.remove('on'); loadBranches(); };
$('path').onchange = loadBranches;
const recents = () => { const r = ls.get('recent', []); $('recent').innerHTML = r.length ? '<span class="hint">Recenti:</span>' + r.map((p) => `<button class="chip" data-p="${esc(p)}">${esc(p.split('/').slice(-2).join('/'))}</button>`).join('') : ''; $('recent').querySelectorAll('.chip').forEach((c) => c.onclick = () => { $('path').value = c.dataset.p; loadBranches(); }); };
recents();

const flow = () => { $('fBase').textContent = $('base').value || 'base'; $('fBranch').textContent = $('branch').value || 'branch'; };
async function loadBranches() {
  try {
    const d = await api('/api/branches?path=' + encodeURIComponent($('path').value));
    const opts = d.branches.map((b) => `<option>${esc(b.name)}</option>`).join('');
    $('branch').innerHTML = opts; $('branch').value = d.current; $('base').innerHTML = opts;
    if (d.suggestedBase) { $('base').value = d.suggestedBase; $('baseHint').textContent = '✨ base dedotta automaticamente'; }
    flow(); ls.set('recent', [$('path').value, ...ls.get('recent', []).filter((x) => x !== $('path').value)].slice(0, 4)); recents();
  } catch (e) { $('baseHint').textContent = e.message; }
}
$('branch').onchange = async () => { flow(); try { const d = await api(`/api/branches?path=${encodeURIComponent($('path').value)}&branch=${encodeURIComponent($('branch').value)}`); if (d.suggestedBase) { $('base').value = d.suggestedBase; $('baseHint').textContent = '✨ base dedotta automaticamente'; flow(); } } catch {} };
$('base').onchange = () => { $('baseHint').textContent = ''; flow(); };

/* ---------- documenti (drag & drop) ---------- */
const drop = $('drop'); let docFiles = [];
const showFiles = () => { $('fileList').innerHTML = docFiles.map((f, i) => `<span class="pill">📄 ${esc(f.name)} <a href="#" data-i="${i}" style="text-decoration:none;color:var(--mut)">✕</a></span>`).join(''); $('fileList').querySelectorAll('a').forEach((a) => a.onclick = (e) => { e.preventDefault(); docFiles.splice(+a.dataset.i, 1); showFiles(); }); };
drop.onclick = () => $('docs').click();
$('docs').onchange = () => { docFiles.push(...$('docs').files); showFiles(); };
drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); }; drop.ondragleave = () => drop.classList.remove('over');
drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); docFiles.push(...e.dataTransfer.files); showFiles(); };

/* ---------- avvio analisi ---------- */
const STEPS = ['Raccolta modifiche', 'Scansione regole', 'Verifica CVE', 'Analisi per commit', 'Simboli rimossi', 'Triage AI'];
const stepOf = (m) => STEPS.findIndex((s) => m.toLowerCase().includes(s.split(' ')[0].toLowerCase()) || (s === 'Analisi per commit' && /commit/i.test(m)) || (s === 'Simboli rimossi' && /simbol/i.test(m)));
function drawProg(msg, done) {
  const i = done ? STEPS.length : stepOf(msg);
  $('prog').innerHTML = `<div class="card">${STEPS.map((s, k) => `<div class="${k < i ? 'done' : k === i ? 'now' : ''}">${k < i ? '✔' : k === i ? '<span class="spin"></span>' : '○'} ${s}</div>`).join('')}</div>`;
}
$('run').onclick = async () => {
  if (!$('path').value || !$('branch').value) return toast('Scegli prima repository e branch');
  $('run').disabled = true; drawProg('Raccolta');
  try {
    const docs = []; for (const f of docFiles) docs.push({ name: f.name, text: await f.text() });
    if ($('docsText').value.trim()) docs.push({ name: 'note', text: $('docsText').value });
    const { job } = await post('/api/analyze', { path: $('path').value, branch: $('branch').value, base: $('base').value, docs, useAI: $('useAI').checked });
    for (;;) {
      await new Promise((r) => setTimeout(r, 450));
      const j = await api('/api/jobs/' + job); drawProg(j.progress);
      if (j.status === 'error') throw new Error(j.error);
      if (j.status === 'done') { drawProg('', true); quota(); await new Promise((r) => setTimeout(r, 350)); $('prog').innerHTML = ''; $('rep').innerHTML = ' '; view('rep'); showReport(j.reportId); break; }
    }
  } catch (e) { $('prog').innerHTML = ''; toast('❌ ' + e.message); } finally { $('run').disabled = false; }
};

/* ---------- lista report ---------- */
async function loadList() {
  const l = await api('/api/reports');
  $('repList').innerHTML = `<h2>Report</h2><p class="sub">Analisi salvate.</p>` + (l.length ? `<div class="grid g2">${l.map((r) => `<div class="card" style="cursor:pointer;margin:0" data-id="${r.id}"><div class="row"><b class="grow">${esc(r.branch)}</b>${score(r.summary).html}</div><div class="hint">← ${esc(r.base)} · ${new Date(r.createdAt).toLocaleString()}</div><div class="hint mono" style="margin-top:6px">${esc(r.repo)}</div><div class="row" style="margin-top:8px"><span class="pill">${r.summary.commits} commit</span><span class="pill">${r.summary.files} file</span><span class="pill">${r.summary.findings} segnalazioni</span></div></div>`).join('')}</div>` : '<div class="card empty">Nessun report: avvia la prima analisi.</div>');
  $('repList').querySelectorAll('[data-id]').forEach((c) => c.onclick = () => showReport(c.dataset.id));
}
const W = { critical: 25, high: 10, medium: 3, low: 1, info: 0 }, COL = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--info)' };
function score(s) {
  const pen = Object.entries(s.bySeverity || {}).reduce((n, [k, v]) => n + (W[k] || 0) * v, 0), v = Math.max(0, 100 - pen);
  const c = v >= 80 ? 'var(--ok)' : v >= 50 ? 'var(--high)' : 'var(--crit)';
  return { v, c, html: `<span class="pill" style="color:${c}">salute ${v}</span>` };
}

/* ---------- report ---------- */
let R = null, tab = 'ov', selFile = null, fSev = 'all', fCat = 'all', fQ = '', fSt = 'all', fFQ = '';
const CATS = { security: '🔒 Sicurezza', error: '🐞 Errori', regression: '↩ Regressioni', quality: '🧹 Qualità' };
const ICON = { pass: '✔', warn: '!', fail: '✕', manual: '👁' };
async function showReport(id) { R = await api('/api/reports/' + id); tab = 'ov'; selFile = null; fSev = fCat = fSt = 'all'; fQ = fFQ = ''; $('repList').innerHTML = ''; drawReport(); }
function drawReport() {
  const r = R, s = r.summary, sc = score(s), done = r.checklist.filter((c) => c.checked).length;
  const tabs = [['ov', 'Panoramica'], ['fl', 'Modifiche', s.files], ['cm', 'Commit', s.commits], ['fd', 'Segnalazioni', s.findings], ['dp', 'Dipendenze', (r.deps || []).length], ['ck', 'Checklist', `${done}/${r.checklist.length}`]];
  $('rep').innerHTML = `
  <div class="row" style="margin-bottom:6px"><button class="btn" id="back">← Report</button><div class="grow"></div><button class="btn" id="copy">⧉ Copia link</button><a class="btn" href="/api/reports/${r.id}.md" download="report-${r.id}.md">⬇ Markdown</a></div>
  <h2><span class="pill ac" style="font-size:16px">${esc(r.base)}</span> ← ${esc(r.branch)}</h2>
  <p class="sub mono">${esc(r.repo)} · merge-base ${r.mergeBase.slice(0, 8)}${r.baseDetected ? ' · base dedotta' : ''}${r.behind ? ` · ⚠ indietro di ${r.behind} commit` : ''}${r.dirty ? ` · ⚠ ${r.dirty} file non committati` : ''}</p>
  <div class="tabs">${tabs.map(([k, n, c]) => `<button class="tab ${tab === k ? 'on' : ''}" data-t="${k}">${n}${c !== undefined ? `<em>${c}</em>` : ''}</button>`).join('')}</div>
  <div id="pane"></div>`;
  $('back').onclick = () => { $('rep').innerHTML = ''; loadList(); };
  $('copy').onclick = () => { navigator.clipboard?.writeText(location.origin + '/#' + r.id); toast('Link copiato'); };
  $('rep').querySelectorAll('.tab').forEach((t) => t.onclick = () => { tab = t.dataset.t; drawReport(); });
  ({ ov: pOv, fl: pFiles, cm: pCommits, fd: pFind, dp: pDeps, ck: pCheck })[tab]();
}
function pOv() {
  const r = R, s = r.summary, sc = score(s), tot = Math.max(1, s.findings), done = r.checklist.filter((c) => c.checked).length;
  const catN = {}; r.findings.forEach((f) => catN[f.category] = (catN[f.category] || 0) + 1);
  const topC = [...r.commits].filter((c) => c.analysis).sort((a, b) => b.analysis.risk - a.analysis.risk).slice(0, 3).filter((c) => c.analysis.risk > 0);
  $('pane').innerHTML = `
  <div class="grid g2">
   <div class="card row" style="gap:22px"><div class="ring" style="--v:${sc.v};--c:${sc.c}"><div><div><b>${sc.v}</b><br><small>salute</small></div></div></div>
    <div class="grow"><h3 style="margin-bottom:4px">Esito</h3><div class="hint">${s.findings} segnalazioni su ${s.files} file e ${s.commits} commit.</div>
     <div class="stack">${['critical', 'high', 'medium', 'low', 'info'].map((k) => `<i style="width:${(s.bySeverity[k] || 0) / tot * 100}%;background:${COL[k]}" title="${k}"></i>`).join('')}</div>
     <div class="row">${['critical', 'high', 'medium', 'low', 'info'].map((k) => s.bySeverity[k] ? `<span class="tag ${k}">${k} ${s.bySeverity[k]}</span>` : '').join('')}</div></div></div>
   <div class="card"><h3>Modifiche vs ${esc(r.base)}</h3><div class="grid g4">
    <div class="tile"><b>${s.files}</b><span>file</span></div><div class="tile"><b class="add">+${s.added}</b><span>righe</span></div><div class="tile"><b class="del">−${s.deleted}</b><span>righe</span></div><div class="tile"><b>${s.commits}</b><span>commit</span></div></div>
    <div class="row" style="margin-top:10px">${Object.entries(s.byStatus).map(([k, v]) => `<span class="pill"><span class="st ${k}">${k}</span> ${v}</span>`).join('')}</div></div>
  </div>
  <div class="grid g3">
   <div class="card"><h3>Per categoria</h3>${Object.entries(CATS).map(([k, n]) => `<div class="row" style="margin:6px 0"><span class="grow">${n}</span><b>${catN[k] || 0}</b></div>`).join('')}</div>
   <div class="card"><h3>Commit più rischiosi</h3>${topC.length ? topC.map((c) => `<div style="margin:6px 0"><span class="mono">${c.short}</span> ${esc(c.subject)} <span class="tag ${c.analysis.risk >= 8 ? 'critical' : c.analysis.risk >= 4 ? 'high' : 'medium'}">${c.analysis.risk}</span></div>`).join('') : '<div class="hint">Nessun commit a rischio 👍</div>'}</div>
   <div class="card"><h3>Token AI</h3>${r.ai.used ? `<b style="font-size:24px">${r.ai.spent}</b> <span class="hint">spesi · mese ${r.ai.monthlyUsedBefore + r.ai.spent}/${r.ai.monthlyLimit}</span><div class="hint">${r.ai.calls} chiamate (${r.ai.cached} da cache) · ${r.ai.skipped} elementi non inviati</div>${r.ai.errors.length ? `<div class="hint" style="color:var(--high)">⚠ ${esc(r.ai.errors.join('; '))}</div>` : ''}` : `<b style="font-size:24px">0</b> <div class="hint">${esc(r.ai.note || 'AI non usata')}</div>`}</div>
  </div>
  <div class="card"><h3>Checklist · ${done}/${r.checklist.length} verificate</h3><div class="row">${r.checklist.map((c) => `<span class="ico ${c.status}" title="${esc(c.title)}">${ICON[c.status]}</span>`).join('')}</div></div>`;
}
function pFiles() {
  const r = R; const q = fFQ.toLowerCase();
  const list = r.files.filter((f) => (fSt === 'all' || f.status === fSt) && f.path.toLowerCase().includes(q));
  if (!selFile || !r.files.find((f) => f.path === selFile)) selFile = list[0]?.path;
  const byDir = {}; list.forEach((f) => { const d = f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '.'; (byDir[d] ||= []).push(f); });
  const f = r.files.find((x) => x.path === selFile);
  $('pane').innerHTML = `<div class="row" style="margin-bottom:12px"><input class="grow" id="fq" placeholder="Cerca file…" value="${esc(fFQ)}">${['all', 'A', 'M', 'D', 'R'].map((k) => `<button class="chip ${fSt === k ? 'on' : ''}" data-s="${k}">${k === 'all' ? 'Tutti' : k}</button>`).join('')}</div>
  <div class="split"><div class="card tree" style="margin:0">${Object.entries(byDir).map(([d, fs]) => `<div class="dir">${esc(d)}</div>${fs.map((x) => `<div class="f ${x.path === selFile ? 'on' : ''}" data-p="${esc(x.path)}"><span class="st ${x.status}">${x.status}</span><span class="nm">${esc(x.path.split('/').pop())}</span><span class="add mono">+${x.add}</span><span class="del mono">−${x.del}</span></div>`).join('')}`).join('') || '<div class="empty">Nessun file</div>'}</div>
  <div class="card" style="margin:0">${f ? `<div class="row" style="margin-bottom:10px"><span class="st ${f.status}">${f.status}</span><b class="mono grow">${f.oldPath ? esc(f.oldPath) + ' → ' : ''}${esc(f.path)}</b><span class="add">+${f.add}</span><span class="del">−${f.del}</span></div>
   ${f.binary ? '<div class="empty">File binario</div>' : `<div class="diff mono">${f.changes.map((l) => `<div class="${l.k === '+' ? 'p' : 'm'}"><span class="ln">${l.n}</span><span class="sg">${l.k}</span>${esc(l.t)}</div>`).join('')}${f.truncated ? '<div><span class="ln"></span>… troncato</div>' : ''}</div>`}` : '<div class="empty">Seleziona un file</div>'}</div></div>`;
  $('fq').oninput = (e) => { fFQ = e.target.value; const p = e.target.selectionStart; pFiles(); $('fq').focus(); $('fq').setSelectionRange(p, p); };
  $('pane').querySelectorAll('[data-s]').forEach((c) => c.onclick = () => { fSt = c.dataset.s; pFiles(); });
  $('pane').querySelectorAll('.f').forEach((c) => c.onclick = () => { selFile = c.dataset.p; pFiles(); });
}
function pCommits() {
  const r = R;
  $('pane').innerHTML = `<p class="hint">Analisi per singolo commit a 0 token${r.summary.commitsAnalyzed < r.summary.commits ? ` · analizzati ${r.summary.commitsAnalyzed}/${r.summary.commits}` : ''}</p><div class="tl">${[...r.commits].reverse().map((c) => { const a = c.analysis, rk = a ? (a.risk >= 8 ? 8 : a.risk >= 4 ? 4 : a.risk >= 2 ? 2 : 0) : 0;
    return `<details class="c r${rk}"><summary class="card" style="margin:0"><div class="row"><span class="mono">${c.short}</span><b class="grow">${esc(c.subject)}${c.merge ? ' <span class="pill">merge</span>' : ''}</b>${a && a.risk ? `<span class="tag ${rk >= 8 ? 'critical' : rk >= 4 ? 'high' : 'medium'}">rischio ${a.risk}</span>` : ''}${a?.noTests ? '<span class="pill">senza test</span>' : ''}</div><div class="hint">${esc(c.author)} · ${new Date(c.date).toLocaleDateString()} · ${c.files} file · <span class="add">+${c.add}</span> <span class="del">−${c.del}</span></div></summary>
    <div class="card" style="margin:6px 0 0">${a ? `${a.files.map((f) => `<div class="mono"><span class="st ${f.status}">${f.status}</span> ${esc(f.oldPath ? f.oldPath + ' → ' : '')}${esc(f.path)}</div>`).join('')}${a.findings.map((f) => `<div style="margin-top:8px"><span class="tag ${f.severity}">${f.severity}</span> <span class="mono">${esc(f.file)}${f.line ? ':' + f.line : ''}</span> ${esc(f.message)}${f.fixedLater ? ' <span class="pill" style="color:var(--ok)">✔ corretto dopo</span>' : ''}</div>`).join('')}` : '<span class="hint">Non analizzato (oltre il limite)</span>'}</div></details>`; }).join('')}</div>`;
}
function pFind() {
  const r = R, q = fQ.toLowerCase();
  const list = r.findings.filter((f) => (fSev === 'all' || f.severity === fSev) && (fCat === 'all' || f.category === fCat) && (`${f.file} ${f.message} ${f.rule}`).toLowerCase().includes(q));
  $('pane').innerHTML = `<div class="row" style="margin-bottom:8px"><input class="grow" id="fq" placeholder="Cerca per file, regola, testo…" value="${esc(fQ)}"></div>
  <div class="row" style="margin-bottom:12px">${['all', 'critical', 'high', 'medium', 'low', 'info'].map((k) => `<button class="chip ${fSev === k ? 'on' : ''}" data-sev="${k}">${k === 'all' ? 'Tutte' : k}</button>`).join('')}<span class="hint">|</span>${['all', ...Object.keys(CATS)].map((k) => `<button class="chip ${fCat === k ? 'on' : ''}" data-cat="${k}">${k === 'all' ? 'Tutte le categorie' : CATS[k]}</button>`).join('')}</div>
  <div class="card">${list.map((f) => `<div class="item"><span class="tag ${f.severity}" style="height:fit-content">${f.severity}</span><div class="grow"><div>${esc(f.message)}</div><div class="hint mono">${esc(f.file)}${f.line ? ':' + f.line : ''} · ${esc(f.rule)}${f.commit ? ' · commit ' + esc(f.commit) : ''}</div>${f.code ? `<div class="code mono">${esc(f.code)}</div>` : ''}${f.ai ? `<div class="hint">🤖 AI: ${esc(f.ai)}${f.aiNote ? ' – ' + esc(f.aiNote) : ''}</div>` : ''}</div></div>`).join('') || '<div class="empty">Nessuna segnalazione con questi filtri 🎉</div>'}</div>`;
  $('fq').oninput = (e) => { fQ = e.target.value; const p = e.target.selectionStart; pFind(); $('fq').focus(); $('fq').setSelectionRange(p, p); };
  $('pane').querySelectorAll('[data-sev]').forEach((c) => c.onclick = () => { fSev = c.dataset.sev; pFind(); });
  $('pane').querySelectorAll('[data-cat]').forEach((c) => c.onclick = () => { fCat = c.dataset.cat; pFind(); });
}
function pDeps() {
  const d = R.deps || [];
  $('pane').innerHTML = `<div class="card">${d.length ? `<p class="hint">CVE da OSV.dev, solo dipendenze nuove o cambiate${R.cve?.error ? ' · <span style="color:var(--high)">⚠ ' + esc(R.cve.error) + '</span>' : ''}</p><table><tr><th>Pacchetto</th><th>Da</th><th>A</th><th>CVE</th></tr>${d.map((x) => `<tr><td class="mono">${esc(x.ecosystem)}:${esc(x.name)}</td><td>${esc(x.from || '—')}</td><td>${esc(x.to)}</td><td>${x.vulns === null ? '<span class="hint">non verificato</span>' : x.vulns.length ? x.vulns.map((v) => `<div><span class="tag ${v.severity}">${esc(v.cve || v.id)}</span> <span class="hint">${esc(v.summary)}${v.fixed ? ' · fix ' + esc(v.fixed) : ''}</span></div>`).join('') : '<span class="add">nessuna</span>'}</td></tr>`).join('')}</table>` : '<div class="empty">Nessuna dipendenza modificata.</div>'}</div>`;
}
function pCheck() {
  const r = R, done = r.checklist.filter((c) => c.checked).length;
  $('pane').innerHTML = `<div class="card"><div class="bar"><i style="width:${done / r.checklist.length * 100}%"></i></div><div class="hint" style="margin-bottom:6px">${done}/${r.checklist.length} verificate da te</div>${r.checklist.map((c) => `<label class="item" style="cursor:pointer;margin:0;color:var(--tx);font-size:14px;font-weight:400"><input type="checkbox" data-c="${c.id}" ${c.checked ? 'checked' : ''} style="margin-top:6px"><span class="ico ${c.status}">${ICON[c.status]}</span><div class="grow"><div>${esc(c.title)}</div><div class="hint">${esc(c.detail)}</div></div></label>`).join('')}</div>`;
  $('pane').querySelectorAll('input[data-c]').forEach((i) => i.onchange = async () => { await post(`/api/reports/${r.id}/check`, { item: i.dataset.c, checked: i.checked }); R.checklist.find((c) => c.id === i.dataset.c).checked = i.checked; pCheck(); });
}
if (location.hash.length > 3) { $('rep').innerHTML = ' '; view('rep'); showReport(location.hash.slice(1)).catch(() => {}); }

/* ---------- config ---------- */
const AIF = ['provider', 'baseUrl', 'model', 'apiKey', 'authHeader', 'authScheme', 'apiVersion', 'timeoutMs'], BF = ['monthlyTokens', 'perAnalysisTokens', 'maxContextTokens', 'maxOutputTokens', 'maxCalls', 'maxRounds', 'docTokens'];
async function loadCfg() {
  quota(); const c = await api('/api/config');
  AIF.forEach((k) => $('c_' + k).value = c.ai[k] ?? ''); $('c_extraHeaders').value = JSON.stringify(c.ai.extraHeaders || {}); $('c_enabled').checked = c.ai.enabled;
  BF.forEach((k) => $('b_' + k).value = c.budget[k]); $('b_cache').checked = c.budget.cache;
  $('a_maxCommits').value = c.analysis.maxCommits; $('a_cveOn').checked = c.analysis.cve.enabled; $('a_osvUrl').value = c.analysis.cve.osvUrl; $('a_cacheHours').value = c.analysis.cve.cacheHours;
}
$('save').onclick = async () => {
  try {
    const ai = { enabled: $('c_enabled').checked, extraHeaders: $('c_extraHeaders').value || '{}' }; AIF.forEach((k) => ai[k] = $('c_' + k).value); ai.timeoutMs = +ai.timeoutMs || 60000;
    const budget = { cache: $('b_cache').checked }; BF.forEach((k) => budget[k] = +$('b_' + k).value);
    await post('/api/config', { ai, budget, analysis: { maxCommits: +$('a_maxCommits').value, cve: { enabled: $('a_cveOn').checked, osvUrl: $('a_osvUrl').value, cacheHours: +$('a_cacheHours').value } } }, 'PUT');
    $('cmsg').textContent = 'Valori incoerenti riportati nei limiti: mese ≥ analisi ≥ chiamata'; toast('✔ Configurazione salvata'); loadCfg();
  } catch (e) { toast('❌ ' + e.message); }
};
$('test').onclick = async () => { $('cmsg').textContent = 'test…'; try { const r = await post('/api/config/test', {}); $('cmsg').textContent = ''; toast('✔ Connessione ok'); quota(); } catch (e) { $('cmsg').textContent = ''; toast('❌ ' + e.message); } };
$('u_set').onclick = async () => { await post('/api/usage', { used: +$('u_used').value }, 'PUT'); quota(); toast('Consumo aggiornato'); };
$('u_reset').onclick = async () => { await post('/api/usage', { used: 0 }, 'PUT'); quota(); toast('Consumo azzerato'); };
