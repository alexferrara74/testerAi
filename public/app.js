const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const api = async (url, opt) => { const r = await fetch(url, opt); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.statusText); return j; };
const post = (url, body, m = 'POST') => api(url, { method: m, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

document.querySelectorAll('#nav button').forEach((b) => b.onclick = () => {
  document.querySelectorAll('#nav button').forEach((x) => x.classList.toggle('on', x === b));
  for (const t of ['an', 'rep', 'cfg']) $('t-' + t).classList.toggle('hide', t !== b.dataset.t);
  if (b.dataset.t === 'rep') loadList(); if (b.dataset.t === 'cfg') loadCfg();
});

/* --- folder picker --- */
let cur = '';
async function browse(p) {
  try { const d = await api('/api/fs' + (p ? '?path=' + encodeURIComponent(p) : '')); cur = d.path; $('mpath').textContent = d.path + (d.isGit ? '  ✔ git' : '');
    $('mlist').innerHTML = (d.parent ? `<div class="dir" data-p="${esc(d.parent)}">⬆ ..</div>` : '') + d.dirs.map((x) => `<div class="dir" data-p="${esc(d.path.replace(/\/$/, '') + '/' + x)}">📁 ${esc(x)}</div>`).join('');
    $('mlist').querySelectorAll('.dir').forEach((e) => e.onclick = () => browse(e.dataset.p)); } catch (e) { alert(e.message); }
}
$('pick').onclick = () => { $('modal').classList.add('on'); browse($('path').value || ''); };
$('mclose').onclick = () => $('modal').classList.remove('on');
$('mok').onclick = () => { $('path').value = cur; $('modal').classList.remove('on'); loadBranches(); };
$('path').onchange = loadBranches;

async function loadBranches() {
  try {
    const d = await api('/api/branches?path=' + encodeURIComponent($('path').value));
    const opts = d.branches.map((b) => `<option>${esc(b.name)}</option>`).join('');
    $('branch').innerHTML = opts; $('branch').value = d.current; $('base').innerHTML = opts;
    if (d.suggestedBase) { $('base').value = d.suggestedBase; $('baseHint').textContent = 'dedotto automaticamente: ' + d.suggestedBase; }
  } catch (e) { $('baseHint').textContent = e.message; }
}
$('branch').onchange = async () => { try { const d = await api(`/api/branches?path=${encodeURIComponent($('path').value)}&branch=${encodeURIComponent($('branch').value)}`); if (d.suggestedBase) { $('base').value = d.suggestedBase; $('baseHint').textContent = 'dedotto automaticamente: ' + d.suggestedBase; } } catch {} };

/* --- analyze --- */
$('run').onclick = async () => {
  $('run').disabled = true; $('prog').textContent = 'in corso…';
  try {
    const docs = [];
    for (const f of $('docs').files) docs.push({ name: f.name, text: await f.text() });
    if ($('docsText').value.trim()) docs.push({ name: 'note', text: $('docsText').value });
    const { job } = await post('/api/analyze', { path: $('path').value, branch: $('branch').value, base: $('base').value, docs, useAI: $('useAI').checked });
    for (;;) {
      await new Promise((r) => setTimeout(r, 600));
      const j = await api('/api/jobs/' + job); $('prog').textContent = j.progress;
      if (j.status === 'error') throw new Error(j.error);
      if (j.status === 'done') { quota(); document.querySelector('[data-t=rep]').click(); showReport(j.reportId); break; }
    }
  } catch (e) { $('prog').textContent = '❌ ' + e.message; } finally { $('run').disabled = false; }
};

/* --- reports --- */
async function loadList() {
  const l = await api('/api/reports');
  $('list').innerHTML = l.length ? `<table>${l.map((r) => `<tr><td><a href="#" data-id="${r.id}">${esc(r.branch)} ← ${esc(r.base)}</a></td><td class="hint">${esc(r.repo)}</td><td class="hint">${new Date(r.createdAt).toLocaleString()}</td><td>${r.summary.findings} segnalazioni</td></tr>`).join('')}</table>` : '<p class="hint">Nessun report.</p>';
  $('list').querySelectorAll('a').forEach((a) => a.onclick = (e) => { e.preventDefault(); showReport(a.dataset.id); });
}
const ICON = { pass: '✅', warn: '⚠️', fail: '❌', manual: '👁️' };
async function showReport(id) {
  const r = await api('/api/reports/' + id); const s = r.summary;
  const sev = (k) => s.bySeverity[k] || 0;
  const cats = { security: '🔒 Sicurezza', error: '🐞 Errori', regression: '↩️ Regressioni', quality: '🧹 Qualità' };
  $('rep').innerHTML = `
  <div class="card"><b>${esc(r.branch)}</b> ← <b>${esc(r.base)}</b> <span class="hint">merge-base ${r.mergeBase.slice(0, 8)}${r.baseDetected ? ' · base dedotto' : ''}</span>
   <a class="s" style="float:right" href="/api/reports/${id}.md" download="report-${id}.md">⬇ Markdown</a>
   <p><span class="stat"><b>${s.commits}</b>commit</span><span class="stat"><b>${s.files}</b>file</span><span class="stat"><b class="add">+${s.added}</b>righe</span><span class="stat"><b class="del">-${s.deleted}</b>righe</span>
   <span class="stat"><b>${s.findings}</b>segnalazioni</span> ${['critical', 'high', 'medium', 'low', 'info'].map((k) => sev(k) ? `<span class="tag ${k}">${k} ${sev(k)}</span> ` : '').join('')}</p>
   <div class="hint">AI: ${r.ai.used ? `${r.ai.calls} chiamate (${r.ai.cached} da cache) · ${r.ai.spent} token spesi (mese ${r.ai.monthlyUsedBefore + r.ai.spent}/${r.ai.monthlyLimit}) · ${r.ai.skipped} elementi non inviati per budget ${r.ai.errors.length ? '· ⚠ ' + esc(r.ai.errors.join('; ')) : ''}` : esc(r.ai.note)}</div></div>
  <div class="card"><b>✅ Checklist</b>${r.checklist.map((c) => `<div class="chk"><input type="checkbox" style="width:auto" data-c="${c.id}" ${c.checked ? 'checked' : ''}><div><span class="${c.status}">${ICON[c.status]}</span> ${esc(c.title)}<div class="hint">${esc(c.detail)}</div></div></div>`).join('')}</div>
  <div class="card"><b>Modifiche rispetto a ${esc(r.base)}</b> <span class="hint">(${Object.entries(s.byStatus).map(([k, v]) => k + ':' + v).join(' ')})</span>
   ${r.files.map((f) => `<details><summary><span class="${f.status} mono">${f.status}</span> <code>${f.oldPath ? esc(f.oldPath) + ' → ' : ''}${esc(f.path)}</code> <span class="add">+${f.add}</span> <span class="del">-${f.del}</span></summary>
   <pre class="mono" style="margin:4px 0 8px;overflow:auto">${f.changes.map((l) => `<span class="${l.k === '+' ? 'add' : 'del'}">${l.k}${String(l.n).padStart(4)} ${esc(l.t)}</span>`).join('\n')}${f.truncated ? '\n…troncato' : ''}${f.binary ? 'binario' : ''}</pre></details>`).join('')}</div>
  <div class="card"><b>Commit</b><table>${r.commits.map((c) => `<tr><td class="mono">${c.short}</td><td>${esc(c.subject)}${c.merge ? ' <span class="hint">(merge)</span>' : ''}</td><td class="hint">${esc(c.author)}</td><td class="hint">${c.files} file <span class="add">+${c.add}</span> <span class="del">-${c.del}</span></td></tr>`).join('')}</table></div>
  ${Object.entries(cats).map(([k, t]) => { const fs = r.findings.filter((f) => f.category === k); return fs.length ? `<div class="card"><b>${t}</b> (${fs.length})<table>${fs.map((f) => `<tr><td><span class="tag ${f.severity}">${f.severity}</span></td><td class="mono">${esc(f.file)}${f.line ? ':' + f.line : ''}${f.commit ? ' @' + f.commit : ''}</td><td>${esc(f.message)}${f.code ? `<div class="mono hint">${esc(f.code)}</div>` : ''}${f.ai ? `<div class="hint">🤖 ${esc(f.ai)} ${esc(f.aiNote || '')}</div>` : ''}</td></tr>`).join('')}</table></div>` : ''; }).join('')}`;
  $('rep').querySelectorAll('input[data-c]').forEach((i) => i.onchange = () => post(`/api/reports/${id}/check`, { item: i.dataset.c, checked: i.checked }));
}

/* --- config --- */
const AIF = ['provider', 'baseUrl', 'model', 'apiKey', 'authHeader', 'authScheme', 'apiVersion', 'timeoutMs'], BF = ['monthlyTokens', 'perAnalysisTokens', 'maxContextTokens', 'maxOutputTokens', 'maxCalls', 'maxRounds', 'docTokens'];
async function quota() { try { const u = await api('/api/usage'); const t = `Token AI ${u.month}: ${u.used}/${u.limit} (residui ${u.remaining})`; $('q').textContent = t; if ($('quota')) $('quota').textContent = t; } catch {} }
quota();
async function loadCfg() {
  quota();
  const c = await api('/api/config');
  AIF.forEach((k) => $('c_' + k).value = c.ai[k] ?? ''); $('c_extraHeaders').value = JSON.stringify(c.ai.extraHeaders || {}); $('c_enabled').checked = c.ai.enabled;
  BF.forEach((k) => $('b_' + k).value = c.budget[k]); $('b_cache').checked = c.budget.cache;
}
$('save').onclick = async () => {
  try {
    const ai = { enabled: $('c_enabled').checked, extraHeaders: $('c_extraHeaders').value || '{}' }; AIF.forEach((k) => ai[k] = $('c_' + k).value);
    ai.timeoutMs = +ai.timeoutMs || 60000;
    const budget = { cache: $('b_cache').checked }; BF.forEach((k) => budget[k] = +$('b_' + k).value);
    await post('/api/config', { ai, budget }, 'PUT'); $('cmsg').textContent = '✔ salvato'; loadCfg();
  } catch (e) { $('cmsg').textContent = '❌ ' + e.message; }
};
$('test').onclick = async () => { $('cmsg').textContent = 'test…'; try { const r = await post('/api/config/test', {}); $('cmsg').textContent = '✔ ok ' + JSON.stringify(r.tokens); } catch (e) { $('cmsg').textContent = '❌ ' + e.message; } };
