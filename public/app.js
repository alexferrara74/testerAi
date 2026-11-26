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
async function privacy() {
  try { const p = await api('/api/privacy'); const d = p.destinations;
    $('netTxt').innerHTML = p.offline ? 'Offline: nessuna connessione' : d.length ? d.map((x) => `${x.purpose.toUpperCase()} → ${esc(x.host)}`).join('<br>') : 'Nessuna uscita attiva';
    if ($('p_dir')) { $('p_dir').textContent = p.dataDir; $('p_env').textContent = [p.proxyEnv ? 'Proxy da ambiente: ' + p.proxyEnv : 'Nessun proxy nell\'ambiente', p.caEnv ? 'CA extra: ' + p.caEnv : ''].filter(Boolean).join(' · ');
      $('p_dest').innerHTML = '<b>Destinazioni consentite ora</b>' + (p.offline ? '<div class="hint">nessuna (offline)</div>' : d.map((x) => `<div class="hint">• <b>${esc(x.host)}</b> (${x.purpose}) — invia: ${esc(x.sends)}</div>`).join('') || '<div class="hint">nessuna</div>');
      $('p_log').innerHTML = p.log.map((e) => `<div>${esc(e.t.slice(11, 19))} ${esc(e.purpose)} ${esc(e.host)}${esc(e.path || '')} ${e.blocked ? '<span style="color:var(--crit)">BLOCCATA: ' + esc(e.blocked) + '</span>' : e.bytes + ' B → ' + e.status}</div>`).join('') || '<span class="hint">nessuna connessione registrata</span>'; } } catch {}
}
privacy();

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
let PH = [['collect', 'Raccolta modifiche'], ['rules', 'Regole statiche'], ['cve', 'Verifica CVE'], ['commits', 'Analisi per commit'], ['review', 'Revisione riga per riga'], ['impact', 'Impatto sugli endpoint'], ['symbols', 'Simboli rimossi / firme'], ['ai', 'Revisione AI']], maxPh = 0, t0 = 0;
function drawProg(j, done) {
  if (j?.phases) PH = j.phases;
  const cur = done ? PH.length : Math.max(maxPh, PH.findIndex((p) => p[0] === j?.phase)); maxPh = Math.max(maxPh, cur < 0 ? 0 : cur); // mai indietro: l'elenco non sparisce
  const sec = Math.round((Date.now() - t0) / 1000);
  $('prog').innerHTML = `<div class="card">${PH.map(([k, n], i) => `<div class="${i < maxPh ? 'done' : i === maxPh ? 'now' : ''}">${i < maxPh ? '✔' : i === maxPh ? '<span class="spin"></span>' : '○'} ${esc(n)}${i === maxPh && j?.detail ? ` <span class="hint">· ${esc(j.detail)}</span>` : ''}</div>`).join('')}<div class="hint" style="margin-top:8px">⏱ ${sec}s${sec > 20 ? ' · repository grande: la risalita dei chiamanti può richiedere un po\'' : ''}</div></div>`;
}
$('run').onclick = async () => {
  if (!$('path').value || !$('branch').value) return toast('Scegli prima repository e branch');
  $('run').disabled = true; maxPh = 0; t0 = Date.now(); drawProg({ phase: 'collect' });
  try {
    const docs = []; for (const f of docFiles) docs.push({ name: f.name, text: await f.text() });
    if ($('docsText').value.trim()) docs.push({ name: 'note', text: $('docsText').value });
    const { job } = await post('/api/analyze', { path: $('path').value, branch: $('branch').value, base: $('base').value, docs, useAI: $('useAI').checked });
    for (;;) {
      await new Promise((r) => setTimeout(r, 450));
      const j = await api('/api/jobs/' + job); drawProg(j);
      if (j.status === 'error') throw new Error(j.error);
      if (j.status === 'done') { drawProg(null, true); quota(); await new Promise((r) => setTimeout(r, 350)); $('prog').innerHTML = ''; $('rep').innerHTML = ' '; view('rep'); showReport(j.reportId); break; }
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
let R = null, tab = 'rv', rvF = 'todo', rvQ = '', rvOpen = {}, tab0 = 1, selFile = null, fSev = 'all', fCat = 'all', fQ = '', fSt = 'all', fFQ = '';
const CATS = { security: '🔒 Sicurezza', error: '🐞 Errori', regression: '↩ Regressioni', quality: '🧹 Qualità' };
const ICON = { pass: '✔', warn: '!', fail: '✕', manual: '👁' };
async function showReport(id) { R = await api('/api/reports/' + id); tab = 'rv'; selFile = null; rvF = 'todo'; rvQ = ''; rvOpen = {}; fSev = fCat = fSt = 'all'; fQ = fFQ = ''; $('repList').innerHTML = ''; drawReport(); }
function drawReport() {
  const r = R, s = r.summary, sc = score(s), done = r.checklist.filter((c) => c.checked).length;
  const rs = r.review?.stats || { total: 0, toDecide: 0 }; const tabs = [['rv', 'Revisione', `${rs.total - rs.toDecide}/${rs.total}`], ['im', 'Impatto', (r.impact?.endpoints || []).length], ['ov', 'Panoramica'], ['fl', 'Modifiche', s.files], ['cm', 'Commit', s.commits], ['fd', 'Segnalazioni', s.findings], ['dp', 'Dipendenze', (r.deps || []).length], ['ck', 'Checklist', `${done}/${r.checklist.length}`]];
  $('rep').innerHTML = `
  <div class="row" style="margin-bottom:6px"><button class="btn" id="back">← Report</button><div class="grow"></div><button class="btn" id="copy">⧉ Copia link</button><a class="btn" href="/api/reports/${r.id}.md" download="report-${r.id}.md">⬇ Markdown</a></div>
  <h2><span class="pill ac" style="font-size:16px">${esc(r.base)}</span> ← ${esc(r.branch)}</h2>
  <p class="sub mono">${esc(r.repo)} · merge-base ${r.mergeBase.slice(0, 8)}${r.baseDetected ? ' · base dedotta' : ''}${r.behind ? ` · ⚠ indietro di ${r.behind} commit` : ''}${r.dirty ? ` · ⚠ ${r.dirty} file non committati` : ''}</p>
  <div class="tabs">${tabs.map(([k, n, c]) => `<button class="tab ${tab === k ? 'on' : ''}" data-t="${k}">${n}${c !== undefined ? `<em>${c}</em>` : ''}</button>`).join('')}</div>
  <div id="pane"></div>`;
  $('back').onclick = () => { $('rep').innerHTML = ''; loadList(); };
  $('copy').onclick = () => { navigator.clipboard?.writeText(location.origin + '/#' + r.id); toast('Link copiato'); };
  $('rep').querySelectorAll('.tab').forEach((t) => t.onclick = () => { tab = t.dataset.t; drawReport(); });
  ({ rv: pReview, im: pImpact, ov: pOv, fl: pFiles, cm: pCommits, fd: pFind, dp: pDeps, ck: pCheck })[tab]();
}
function pImpact() {
  const im = R.impact || { endpoints: [] }, eps = im.endpoints, RK = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
  $('pane').innerHTML = `<p class="hint">Per ogni modifica fatta in un punto <b>già esistente</b> si risalgono i chiamanti fino agli endpoint (HTTP, eventi, job). Analisi statica, 0 token · ${im.analyzed || 0} modifiche analizzate${im.error ? ' · ⚠ ' + esc(im.error) : ''}${im.disabled ? ' · <b>disattivata</b> in configurazione' : ''}</p>
  ${eps.length ? eps.map((e) => `<div class="card"><div class="row"><span class="tag ${RK[e.risk]}">${e.risk}</span><b class="mono grow">${esc(e.label)}</b><span class="hint mono">${esc(e.file)}:${e.line}</span></div>
   ${e.chains.map((c) => `<div class="row mono" style="margin:6px 0">${c.map((n, k) => `<span class="pill ${k === 0 ? 'ac' : ''}">${esc(n)}</span>${k < c.length - 1 ? '<span class="hint">→</span>' : ''}`).join('')}<span class="hint">⇒</span><span class="pill" style="border-color:var(--ac)">${esc(e.label)}</span></div>`).join('')}
   <div class="hint">${e.items.length} modifiche coinvolte: ${e.items.map((id) => { const it = R.review.items.find((x) => x.id === id); return it ? `<span class="mono">${esc(it.file)}:${it.newStart || 1}</span> (${esc(it.commit)})` : id; }).join(', ')}</div></div>`).join('') : `<div class="card empty">${im.analyzed ? 'Nessuna delle modifiche in punti esistenti raggiunge un endpoint riconosciuto 👍<br><span class="hint">Riconosco route Express/Fastify/Koa, Flask/FastAPI, Spring, NestJS, Go, Next.js, eventi e job.</span>' : 'Nessuna modifica in punti esistenti da analizzare.'}</div>`}`;
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
   <div class="card"><h3>Token AI</h3>${r.ai.used ? `<b style="font-size:24px">${r.ai.spent}</b> <span class="hint">spesi · mese ${r.ai.monthlyUsedBefore + r.ai.spent}/${r.ai.monthlyLimit}</span><div class="hint">${r.ai.calls} chiamate (${r.ai.cached} da cache) · ${r.ai.skipped} elementi non inviati${r.ai.impactReviewed ? ` · ${r.ai.impactReviewed} impatti valutati a contesto chiuso` : ''}</div>${r.ai.errors.length ? `<div class="hint" style="color:var(--high)">⚠ ${esc(r.ai.errors.join('; '))}</div>` : ''}` : `<b style="font-size:24px">0</b> <div class="hint">${esc(r.ai.note || 'AI non usata')}</div>`}</div>
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

/* ---------- revisione: checklist riga per riga ---------- */
const LV = { problem: ['Problema', 'critical'], check: ['Da verificare', 'medium'], trivial: ['Banale', 'info'] };
async function decide(keys, state) {
  const sy = window.scrollY;
  const res = await post(`/api/reports/${R.id}/review`, { keys, state }, 'POST');
  const set = new Set(keys); R.review.items.forEach((i) => { if (set.has(i.key) && i.state !== 'superseded') i.state = state; });
  R.review.stats = res.stats; R.checklist = res.checklist; drawReport(); window.scrollTo(0, sy);
}
function pReview() {
  const r = R, st = r.review.stats, all = r.review.items, q = rvQ.toLowerCase();
  const active = all.filter((i) => i.state !== 'superseded');
  const match = (i) => (rvF === 'all' || (rvF === 'todo' && i.state === 'open') || (rvF === 'problem' && i.level === 'problem') || (rvF === 'fix' && i.state === 'fix') || (rvF === 'aware' && i.state === 'aware')) && (`${i.file} ${i.tags.map((t) => t.label).join(' ')}`).toLowerCase().includes(q);
  const pct = (n) => (st.total ? n / st.total * 100 : 0);
  const fixes = active.filter((i) => i.state === 'fix');
  const ready = st.total > 0 && !st.blocking && !st.toDecide;
  const groups = r.commits.map((c) => ({ c, its: active.filter((i) => i.commit === c.short && match(i)), tot: active.filter((i) => i.commit === c.short) })).filter((g) => g.its.length);
  const sup = all.filter((i) => i.state === 'superseded');
  $('pane').innerHTML = `
  ${r.review.resolved?.length ? `<div class="card" style="border-color:var(--ok)"><b style="color:var(--ok)">✔ ${r.review.resolved.length} fix verificati</b> <span class="hint">le modifiche marcate «da fixare» non risultano più nel branch:</span>${r.review.resolved.map((x) => `<div class="hint mono">${esc(x.file)} — ${esc(x.label)}</div>`).join('')}</div>` : ''}
  <div class="card"><div class="row"><div class="grow"><h3 style="margin-bottom:2px">${ready ? '✅ Tutto deciso, nessun problema bloccante' : `Decisioni: ${st.total - st.toDecide}/${st.total}`}</h3>
   <div class="hint">${st.blocking ? `<b style="color:var(--crit)">${st.blocking} problemi bloccanti</b> da fixare nel codice o da accettare · ` : ''}${st.fix} da fixare · ${st.aware} consapevoli · ${st.open} da decidere${st.superseded ? ` · ${st.superseded} già riscritte in commit successivi` : ''}</div></div>
   <button class="btn" id="rvTriv">✔ Banali → consapevole</button><button class="btn p" id="rvRe">↻ Ri-analizza dopo i fix</button></div>
   <div class="stack" style="height:10px"><i style="width:${pct(st.aware)}%;background:var(--ok)"></i><i style="width:${pct(st.fix)}%;background:var(--high)"></i></div>
   ${r.review.truncated ? `<div class="hint" style="color:var(--high)">⚠ ${r.review.truncated} voci banali non mostrate (limite)</div>` : ''}</div>
  ${fixes.length ? `<details class="card"><summary><b>🔧 Da fixare (${fixes.length})</b> <span class="hint">clic per l'elenco · poi committa e «Ri-analizza»</span></summary><div style="margin-top:10px">${fixes.map((i) => `<div class="mono" style="margin:4px 0">☐ ${esc(i.file)}:${i.newStart} <span class="hint">(${i.commit})</span> — ${esc(i.tags.filter((t) => t.sev !== 'none').map((t) => t.label).join('; '))}</div>`).join('')}<button class="btn" id="rvCopy" style="margin-top:8px">⧉ Copia come TODO</button></div></details>` : ''}
  <div class="row" style="margin-bottom:12px"><input class="grow" id="rvq" placeholder="Cerca file o tipo di modifica…" value="${esc(rvQ)}">${[['todo', 'Da decidere'], ['problem', 'Problemi'], ['fix', 'Da fixare'], ['aware', 'Consapevole'], ['all', 'Tutte']].map(([k, n]) => `<button class="chip ${rvF === k ? 'on' : ''}" data-f="${k}">${n}</button>`).join('')}</div>
  ${groups.length ? groups.map(({ c, its, tot }) => { const dn = tot.filter((i) => i.state !== 'open').length, op = rvOpen[c.short] !== false;
    return `<div class="card"><div class="row" data-ct="${c.short}" style="cursor:pointer"><span>${op ? '▾' : '▸'}</span><span class="mono">${c.short}</span><b class="grow">${esc(c.subject)}</b><span class="pill">${dn}/${tot.length}</span><button class="btn" data-all="${c.short}" style="padding:4px 10px">✔ Tutto ok</button></div>
    ${op ? its.map((i) => item(i)).join('') : ''}</div>`; }).join('') : `<div class="card empty">${all.length ? 'Nessuna modifica con questo filtro 🎉' : 'Nessuna modifica da rivedere'}</div>`}
  ${sup.length ? `<details class="card"><summary class="hint">${sup.length} modifiche riscritte o annullate in commit successivi (non richiedono decisione)</summary>${sup.map((i) => `<div class="mono hint" style="margin:4px 0">${i.commit} ${esc(i.file)}:${i.newStart} — ${esc(i.tags.filter((t) => t.sev !== 'none').map((t) => t.label).join('; ') || 'modifica banale')}</div>`).join('')}</details>` : ''}`;
  $('rvq').oninput = (e) => { rvQ = e.target.value; const p = e.target.selectionStart; pReview(); $('rvq').focus(); $('rvq').setSelectionRange(p, p); };
  $('pane').querySelectorAll('[data-f]').forEach((c) => c.onclick = () => { rvF = c.dataset.f; pReview(); });
  $('pane').querySelectorAll('[data-ct]').forEach((c) => c.onclick = (e) => { if (e.target.closest('button')) return; rvOpen[c.dataset.ct] = rvOpen[c.dataset.ct] === false; pReview(); });
  $('pane').querySelectorAll('[data-all]').forEach((b) => b.onclick = () => { const its = active.filter((i) => i.commit === b.dataset.all && i.level !== 'problem' && i.state === 'open'); if (!its.length) return toast('Restano solo problemi: decidili uno per uno'); decide(its.map((i) => i.key), 'aware'); });
  $('pane').querySelectorAll('[data-act]').forEach((b) => b.onclick = () => decide([b.dataset.k], b.dataset.act));
  $('rvTriv').onclick = () => { const its = active.filter((i) => i.level === 'trivial' && i.state === 'open'); its.length ? decide(its.map((i) => i.key), 'aware') : toast('Nessuna voce banale da decidere'); };
  if ($('rvCopy')) $('rvCopy').onclick = () => { navigator.clipboard?.writeText(fixes.map((i) => `- [ ] ${i.file}:${i.newStart} (${i.commit}) ${i.tags.filter((t) => t.sev !== 'none').map((t) => t.label).join('; ')}`).join('\n')); toast('TODO copiato'); };
  $('rvRe').onclick = async () => { $('rvRe').disabled = true; toast('Ri-analisi in corso…'); try { const { job } = await post('/api/analyze', { path: r.repo, branch: r.branch, base: r.base, useAI: false }); for (;;) { await new Promise((x) => setTimeout(x, 500)); const j = await api('/api/jobs/' + job); if (j.status === 'error') throw new Error(j.error); if (j.status === 'done') { await showReport(j.reportId); toast('Ri-analisi completata'); break; } } } catch (e) { toast('❌ ' + e.message); $('rvRe').disabled = false; } };
}
function impactBlock(i) {
  const m = i.impact; if (!m) return '';
  if (m.isNew || m.note) return `<div class="hint">🧭 ${esc(m.note || '')}</div>`;
  const cls = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }[m.risk];
  return `<div style="border:1px solid var(--bd);border-radius:10px;padding:8px 10px;background:var(--panel2)"><div class="row"><b>🧭 Impatto</b><span class="tag ${cls}">${m.risk}</span><span class="hint">${m.callers} punti di chiamata${m.fn ? ' di <span class="mono">' + esc(m.fn) + '</span>' : ''}</span></div>
   ${m.endpoints.length ? m.endpoints.slice(0, 4).map((e) => `<div class="mono" style="margin-top:4px">${e.chain.map(esc).join(' → ')} <b>⇒ ${esc(e.label)}</b></div>`).join('') : '<div class="hint">Nessun endpoint raggiunto (chiamanti interni o non risolvibili staticamente).</div>'}
   ${m.reasons.map((x) => `<div class="hint">• ${esc(x)}</div>`).join('')}
   ${m.ai ? `<div style="margin-top:6px">🤖 <span class="tag ${m.ai.v === 'risk' ? 'high' : m.ai.v === 'ok' ? 'low' : 'medium'}">${m.ai.v === 'risk' ? 'rischio confermato' : m.ai.v === 'ok' ? 'nessun rischio' : 'incerto'}</span> <span class="hint">${esc(m.ai.why)}</span></div>` : ''}
   ${m.untouched.length ? `<div class="hint">Chiamanti non toccati dal branch: <span class="mono">${m.untouched.slice(0, 4).map(esc).join(', ')}</span></div>` : ''}${m.tests.length ? `<div class="hint">Test: <span class="mono">${m.tests.slice(0, 3).map(esc).join(', ')}</span></div>` : ''}</div>`;
}
function item(i) {
  const [lvl, cls] = LV[i.level], real = i.tags.filter((t) => t.sev !== 'none'), open = i.level !== 'trivial';
  const stCls = i.state === 'aware' ? 'var(--ok)' : i.state === 'fix' ? 'var(--high)' : 'var(--bd)';
  return `<div class="item" style="border-left:3px solid ${stCls};padding-left:12px;margin:8px 0;flex-direction:column;gap:6px;background:${i.state === 'open' ? 'transparent' : 'var(--panel2)'}">
   <div class="row"><span class="tag ${cls}">${lvl}</span><span class="mono grow">${esc(i.fileStatus === 'D' ? '(eliminato) ' : '')}${esc(i.oldPath ? i.oldPath + ' → ' : '')}${esc(i.file)}${i.newStart ? ':' + i.newStart : ''}</span>
    ${i.state === 'aware' ? '<span class="pill" style="color:var(--ok)">✔ consapevole</span>' : i.state === 'fix' ? '<span class="pill" style="color:var(--high)">🔧 da fixare</span>' : ''}</div>
   ${impactBlock(i)}
   ${real.length ? `<div class="row">${real.map((t) => `<span class="tag ${t.sev}" title="${esc(t.hint)}">${esc(t.label)}</span>`).join('')}</div>${real.filter((t) => t.hint).slice(0, 3).map((t) => `<div class="hint">↳ ${esc(t.hint)}${t.detail ? ` <span class="mono">${esc(t.detail)}</span>` : ''}</div>`).join('')}` : `<div class="hint">${esc(i.tags[0]?.label || '')}</div>`}
   ${i.lines.length ? `<details ${open ? 'open' : ''}><summary class="hint">Righe modificate (${i.lines.length}${i.extra ? '+' + i.extra : ''})</summary><div class="diff mono" style="max-height:240px;margin-top:4px">${i.lines.map((l) => `<div class="${l.k === '+' ? 'p' : 'm'}"><span class="ln">${l.n}</span><span class="sg">${l.k}</span>${esc(l.t)}</div>`).join('')}</div></details>` : ''}
   <div class="row"><button class="btn" data-act="aware" data-k="${i.key}" style="padding:5px 12px">✔ Sono consapevole</button><button class="btn" data-act="fix" data-k="${i.key}" style="padding:5px 12px">🔧 Da fixare</button>${i.state !== 'open' ? `<button class="btn" data-act="open" data-k="${i.key}" style="padding:5px 12px">↺ Annulla</button>` : ''}</div></div>`;
}

/* ---------- config ---------- */
const PRESETS = {
  copilot: { v: { provider: 'copilot', baseUrl: 'https://api.githubcopilot.com', model: 'gpt-4o', authHeader: 'Authorization', authScheme: 'Bearer', apiVersion: '', copilotTokenUrl: 'https://api.github.com/copilot_internal/v2/token' }, h: 'Serve una licenza GitHub Copilot. Inserisci nel campo API key il token GitHub (OAuth Copilot, es. ghu_…): non viene mai letto in automatico dal PC. Poi premi «Carica modelli». Copilot Business/Enterprise: cambia Base URL in https://api.business.githubcopilot.com o https://api.enterprise.githubcopilot.com. Integrazione non-ufficiale: verifica che le policy aziendali/ToS la consentano.' },
  ghmodels: { v: { provider: 'openai', baseUrl: 'https://models.github.ai/inference', model: 'openai/gpt-4.1-mini', authHeader: 'Authorization', authScheme: 'Bearer', apiVersion: '' }, h: 'API ufficiale GitHub Models: API key = Personal Access Token con permesso models:read.' },
  azure: { v: { provider: 'openai', baseUrl: 'https://<risorsa>.openai.azure.com/openai/deployments/<deployment>', model: '<deployment>', authHeader: 'api-key', authScheme: '', apiVersion: '2024-10-21' }, h: 'Sostituisci <risorsa> e <deployment>.' },
  openai: { v: { provider: 'openai', baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini', authHeader: 'Authorization', authScheme: 'Bearer', apiVersion: '' }, h: '' },
  anthropic: { v: { provider: 'anthropic', baseUrl: 'https://api.anthropic.com', model: 'claude-haiku-4-5', authHeader: 'Authorization', authScheme: 'Bearer', apiVersion: '' }, h: 'API key Anthropic nel campo API key.' },
  ollama: { v: { provider: 'ollama', baseUrl: 'http://127.0.0.1:11434', model: 'qwen2.5-coder', authHeader: 'Authorization', authScheme: 'Bearer', apiVersion: '' }, h: 'Modello locale: nessun dato lascia il PC.' },
};
$('c_preset').onchange = () => { const p = PRESETS[$('c_preset').value]; if (!p) return; for (const [k, v] of Object.entries(p.v)) $('c_' + k).value = v; manualModel('Inserisci la API key e premi «Carica modelli»'); $('c_presetHint').textContent = p.h; $('c_enabled').checked = true; };
/* ----- elenco modelli dal provider: si sceglie, non si digita ----- */
const modelValue = () => ($('c_modelSel').classList.contains('hide') ? $('c_model').value : $('c_modelSel').value);
function showModels(list, current) {
  const sel = $('c_modelSel'); const ids = list.map((m) => m.id);
  sel.innerHTML = (current && !ids.includes(current) ? `<option value="${esc(current)}">${esc(current)} (corrente)</option>` : '') + list.map((m) => `<option value="${esc(m.id)}">${esc(m.name && m.name !== m.id ? m.name + ' — ' + m.id : m.id)}</option>`).join('');
  sel.value = current || ids[0] || '';
  sel.classList.remove('hide'); $('c_model').classList.add('hide'); $('c_modelHint').textContent = `${list.length} modelli disponibili`;
}
function manualModel(msg) { $('c_modelSel').classList.add('hide'); $('c_model').classList.remove('hide'); $('c_modelHint').textContent = msg || ''; }
async function loadModels(silent) {
  $('c_modelHint').textContent = 'caricamento…';
  try {
    if (!silent) { const ai = { enabled: true, extraHeaders: $('c_extraHeaders').value || '{}' }; AIF.forEach((k) => ai[k] = $('c_' + k).value); ai.model = modelValue(); ai.timeoutMs = +ai.timeoutMs || 60000; await post('/api/config', { ai }, 'PUT'); $('c_enabled').checked = true; privacy(); }
    const r = await post('/api/models', {});
    if (!r.ok) { manualModel(`${r.error}${r.hint ? ' — ' + r.hint : ''}`); if (!silent) toast('❌ ' + r.error); return; }
    if (!r.models.length) return manualModel('Nessun modello restituito: indicalo a mano.');
    showModels(r.models, modelValue()); if (!silent) toast(`✔ ${r.models.length} modelli trovati`);
  } catch (e) { manualModel(e.message); if (!silent) toast('❌ ' + e.message); }
}
$('c_load').onclick = () => loadModels(false);
const AIF = ['provider', 'baseUrl', 'model', 'apiKey', 'authHeader', 'authScheme', 'apiVersion', 'copilotTokenUrl', 'timeoutMs'], BF = ['monthlyTokens', 'perAnalysisTokens', 'maxContextTokens', 'maxOutputTokens', 'maxCalls', 'maxRounds', 'docTokens'];
async function loadCfg() {
  quota(); privacy(); const c = await api('/api/config'); manualModel('');
  $('p_offline').checked = c.privacy.offline; $('p_sendCode').checked = c.privacy.sendCode; $('p_redact').checked = c.privacy.redactSecrets; $('p_http').checked = c.privacy.allowHttp; $('p_proxy').value = c.privacy.proxyUrl || ''; $('p_ca').value = c.privacy.caFile || '';
  AIF.forEach((k) => $('c_' + k).value = c.ai[k] ?? ''); $('c_extraHeaders').value = JSON.stringify(c.ai.extraHeaders || {}); $('c_enabled').checked = c.ai.enabled;
  BF.forEach((k) => $('b_' + k).value = c.budget[k]); $('b_cache').checked = c.budget.cache;
  if (c.ai.enabled && (c.ai.apiKey || c.ai.provider === 'ollama')) loadModels(true);
  $('a_maxCommits').value = c.analysis.maxCommits; $('a_wt').checked = c.analysis.includeWorktree; $('a_impOn').checked = c.analysis.impact.enabled; $('a_impDepth').value = c.analysis.impact.maxDepth; $('a_maxReview').value = c.analysis.maxReviewItems; $('a_cveOn').checked = c.analysis.cve.enabled; $('a_osvUrl').value = c.analysis.cve.osvUrl; $('a_cacheHours').value = c.analysis.cve.cacheHours;
}
$('save').onclick = async () => {
  try {
    const ai = { enabled: $('c_enabled').checked, extraHeaders: $('c_extraHeaders').value || '{}' }; AIF.forEach((k) => ai[k] = $('c_' + k).value); ai.model = modelValue(); ai.timeoutMs = +ai.timeoutMs || 60000;
    const budget = { cache: $('b_cache').checked }; BF.forEach((k) => budget[k] = +$('b_' + k).value);
    await post('/api/config', { ai, budget, privacy: { offline: $('p_offline').checked, sendCode: $('p_sendCode').checked, redactSecrets: $('p_redact').checked, allowHttp: $('p_http').checked, proxyUrl: $('p_proxy').value, caFile: $('p_ca').value }, analysis: { includeWorktree: $('a_wt').checked, impact: { enabled: $('a_impOn').checked, maxDepth: +$('a_impDepth').value }, maxCommits: +$('a_maxCommits').value, maxReviewItems: +$('a_maxReview').value, cve: { enabled: $('a_cveOn').checked, osvUrl: $('a_osvUrl').value, cacheHours: +$('a_cacheHours').value } } }, 'PUT');
    $('cmsg').textContent = 'Valori incoerenti riportati nei limiti: mese ≥ analisi ≥ chiamata'; toast('✔ Configurazione salvata'); loadCfg(); privacy();
  } catch (e) { toast('❌ ' + e.message); }
};
$('test').onclick = async () => {
  $('cmsg').textContent = 'test in corso…'; $('diag').innerHTML = '';
  try {
    const r = await post('/api/config/test', {}); $('cmsg').textContent = '';
    $('diag').innerHTML = `<div class="card" style="border-color:${r.ok ? 'var(--ok)' : 'var(--crit)'}"><b>${r.ok ? '✔ Collegamento funzionante' : '✕ Collegamento non riuscito'}</b>${r.steps.map((x, i) => `<div style="margin-top:8px"><span class="ico ${x.ok ? 'pass' : 'fail'}" style="display:inline-grid;vertical-align:middle">${x.ok ? '✔' : '✕'}</span> <b>${i + 1}. ${esc(x.name)}</b><div class="hint" style="margin-left:34px">${esc(x.detail)}</div>${x.hint ? `<div style="margin-left:34px;color:var(--high)">💡 ${esc(x.hint)}</div>` : ''}</div>`).join('')}</div>`;
    if (r.ok) toast('✔ Connessione ok'); quota(); privacy();
  } catch (e) { $('cmsg').textContent = ''; toast('❌ ' + e.message); }
};
$('u_set').onclick = async () => { await post('/api/usage', { used: +$('u_used').value }, 'PUT'); quota(); toast('Consumo aggiornato'); };
$('u_reset').onclick = async () => { await post('/api/usage', { used: 0 }, 'PUT'); quota(); toast('Consumo azzerato'); };
