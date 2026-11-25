import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as G from './git.js';
import * as R from './rules.js';
import { retrieveDocs } from './tokens.js';
import { triage } from './ai.js';
import { loadConfig, DATA } from './config.js';

const SEV = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const ignored = (cfg, p) => cfg.analysis.ignorePaths.some((i) => p.includes(i));

export async function analyze({ repo, branch, base, docs = [], useAI = true, onProgress = () => {} }) {
  const cfg = loadConfig();
  if (!G.isGitRepo(repo)) throw new Error('La cartella non e\' un repository git');
  branch = G.safeRef(branch || (await G.listBranches(repo)).current);
  let detected = null;
  if (!base) { detected = await G.detectBase(repo, branch); if (!detected) throw new Error('Impossibile dedurre il branch base: specificalo'); base = detected.base; }
  G.safeRef(base);
  const mb = await G.mergeBase(repo, base, branch);
  onProgress('Raccolta modifiche rispetto a ' + base);

  const [commits, status, stats, diff, behind, dirty] = await Promise.all([
    G.commitsBetween(repo, mb, branch), G.nameStatus(repo, mb, branch), G.numstat(repo, mb, branch),
    G.parseDiff(repo, mb, branch), G.behindCount(repo, base, branch), G.dirtyFiles(repo),
  ]);

  const findings = [];
  const add = (f) => findings.push({ id: 'F' + (findings.length + 1), source: 'rule', ...f });

  /* --- elenco completo delle modifiche rispetto al branch base --- */
  const files = status.map((s) => {
    const st = stats.get(s.path) || { add: 0, del: 0, binary: false };
    const d = diff.get(s.path);
    const lines = [];
    if (d) for (const h of d.hunks) {
      for (const r of h.removed) lines.push({ k: '-', n: r.n, t: r.t.slice(0, 200) });
      for (const a of h.added) lines.push({ k: '+', n: a.n, t: a.t.slice(0, 200) });
    }
    const cap = cfg.analysis.maxHunkLinesPerFile;
    return { ...s, ...st, ignored: ignored(cfg, s.path), changes: lines.slice(0, cap), truncated: lines.length > cap };
  });

  /* --- regole a livello riga --- */
  onProgress('Scansione regole statiche');
  for (const [file, d] of diff) {
    if (ignored(cfg, file)) continue;
    for (const f of R.scanHunks(file, d.hunks)) add(f);
  }

  /* --- regole a livello file/commit --- */
  const changedSrc = files.filter((f) => f.status !== 'D' && R.isSourcePath(f.path) && !f.ignored);
  const changedTests = files.filter((f) => R.isTestPath(f.path));
  for (const f of files) {
    if (f.status !== 'D' && R.isSensitiveFile(f.path)) add({ rule: 'SEC-SENSITIVE-FILE', category: 'security', severity: 'critical', file: f.path, message: 'File sensibile nel branch (.env/chiavi/credenziali)' });
    if (f.status === 'D' && R.isTestPath(f.path)) add({ rule: 'REG-TEST-DELETED', category: 'regression', severity: 'high', file: f.path, message: 'Test eliminato' });
    if (f.binary && f.status !== 'D') add({ rule: 'QLT-BINARY', category: 'quality', severity: 'low', file: f.path, message: 'File binario aggiunto/modificato' });
    if (f.add + f.del > 800 && !f.ignored) add({ rule: 'QLT-BIG-CHANGE', category: 'quality', severity: 'low', file: f.path, message: `Modifica molto estesa (+${f.add}/-${f.del})` });
  }
  const manifests = files.filter((f) => R.isManifest(f.path)), locks = files.filter((f) => R.isLockfile(f.path));
  if (manifests.length && !locks.length) add({ rule: 'DEP-NO-LOCK', category: 'security', severity: 'medium', file: manifests[0].path, message: 'Dipendenze modificate senza aggiornare il lockfile' });
  for (const m of manifests) add({ rule: 'DEP-CHANGED', category: 'security', severity: 'info', file: m.path, message: 'Manifest dipendenze modificato: verificare versioni/CVE' });
  if (changedSrc.length && !changedTests.length) add({ rule: 'REG-NO-TESTS', category: 'regression', severity: 'medium', file: '', message: `${changedSrc.length} file sorgente modificati senza alcun test modificato` });

  for (const c of commits) {
    if (/^(wip|fix|update|test|\.+|tmp|asd)\b\s*$/i.test(c.subject.trim()) || c.subject.trim().length < 5) add({ rule: 'GIT-MSG', category: 'quality', severity: 'low', file: '', commit: c.short, message: `Messaggio di commit poco descrittivo: "${c.subject}"` });
    if (c.files > 50 || c.add + c.del > 1500) add({ rule: 'GIT-BIG-COMMIT', category: 'quality', severity: 'low', file: '', commit: c.short, message: `Commit molto grande (${c.files} file, +${c.add}/-${c.del})` });
  }

  /* --- regressioni: simboli rimossi/cambiati ancora usati --- */
  onProgress('Ricerca simboli rimossi o con firma cambiata');
  let symChecks = 0;
  for (const [file, d] of diff) {
    if (ignored(cfg, file) || !R.isSourcePath(file)) continue;
    for (const h of d.hunks) {
      const rem = new Map(), addd = new Map();
      for (const r of h.removed) { const x = R.defOf(r.t); if (x) rem.set(x.name, { ...x, n: r.n }); }
      for (const a of h.added) { const x = R.defOf(a.t); if (x) addd.set(x.name, { ...x, n: a.n }); }
      for (const [name, o] of rem) {
        if (symChecks++ > 40) break;
        const n = addd.get(name);
        const refs = (await G.grepSymbol(repo, branch, name)).filter((p) => p !== file);
        if (!n) {
          const inSame = diff.get(file).hunks.some((hh) => hh !== h && hh.added.some((a) => R.defOf(a.t)?.name === name)); // spostato
          if (!inSame && refs.length) add({ rule: 'REG-REMOVED-SYMBOL', category: 'regression', severity: 'high', file, line: o.n, message: `Simbolo "${name}" rimosso ma ancora citato in ${refs.length} file (${refs.slice(0, 3).join(', ')})`, code: name });
        } else if (n.params !== o.params && refs.length) {
          add({ rule: 'REG-SIGNATURE', category: 'regression', severity: 'medium', file, line: n.n, message: `Firma di "${name}" cambiata (${o.params || '()'} -> ${n.params || '()'}); usata in ${refs.length} file: ${refs.slice(0, 3).join(', ')}`, code: name });
        }
      }
    }
  }

  /* --- AI (opzionale, a budget) --- */
  const aiInfo = { used: false, provider: cfg.ai.provider, model: cfg.ai.model, maxContextTokens: cfg.budget.maxContextTokens, calls: 0, cached: 0, estIn: 0, estOut: 0, in: 0, out: 0, skipped: 0, errors: [], note: '' };
  if (useAI && cfg.ai.enabled && cfg.ai.model) {
    onProgress('Triage AI (budget ' + cfg.budget.maxContextTokens + ' token/chiamata)');
    const items = []; const byId = new Map(findings.map((f) => [f.id, f]));
    for (const f of findings) {
      if (SEV[f.severity] >= 3 && f.code && f.line) items.push({ id: f.id, priority: 100 + SEV[f.severity] * 10, text: `${f.id}|${f.file}:${f.line}|${f.code}` });
    }
    // Hunk "rischiosi" non gia' coperti da una regola: solo le righe modificate, ritagliate.
    const flagged = new Set(findings.map((f) => f.file));
    let hid = 0;
    for (const [file, d] of diff) {
      if (ignored(cfg, file) || !R.isSourcePath(file)) continue;
      const score = (R.isRiskyPath(file) ? 30 : 0) + Math.min(20, d.hunks.reduce((s, h) => s + h.removed.length, 0)) + (flagged.has(file) ? 0 : 5);
      if (score < 10) continue;
      for (const h of d.hunks.slice(0, 3)) {
        const code = [...h.removed.slice(0, 2).map((r) => '-' + r.t.trim()), ...h.added.slice(0, 3).map((a) => '+' + a.t.trim())].join(' ⏎ ').slice(0, 220);
        if (code.length > 12) items.push({ id: 'H' + ++hid, priority: score, text: `H${hid}|${file}:${h.newStart}|${code}`, file, line: h.newStart, code });
      }
    }
    const kw = [...files.map((f) => path.basename(f.path).replace(/\.\w+$/, '')), ...commits.flatMap((c) => c.subject.split(/\W+/))];
    const docsText = retrieveDocs(docs, kw, cfg.budget.docTokens);
    try {
      const r = await triage(cfg, items, docsText, { snippet: (f, a, b) => G.showLines(repo, branch, f, a, b) });
      Object.assign(aiInfo, { used: true, ...r.usage, skipped: r.skipped, errors: r.errors });
      for (const [id, why] of r.bug) {
        const f = byId.get(id);
        if (f) { f.ai = 'confermato'; f.aiNote = why; } else { const it = items.find((i) => i.id === id); if (it) add({ source: 'ai', rule: 'AI-REVIEW', category: 'error', severity: 'medium', file: it.file, line: it.line, message: why || 'Segnalato dall\'AI', code: it.code }); }
      }
      for (const id of r.fp) { const f = byId.get(id); if (f) { f.ai = 'falso positivo'; f.severityOriginal = f.severity; f.severity = 'info'; } }
    } catch (e) { aiInfo.errors.push(e.message); }
  } else aiInfo.note = useAI ? 'AI non abilitata/configurata: analisi solo statica (0 token).' : 'AI disattivata per questa analisi.';

  findings.sort((a, b) => SEV[b.severity] - SEV[a.severity]);

  /* --- checklist --- */
  const has = (...rules) => findings.filter((f) => rules.includes(f.rule) && f.ai !== 'falso positivo');
  const item = (id, title, bad, detail, manual = false) => ({ id, title, status: manual ? 'manual' : bad.length ? (bad.some((f) => SEV[f.severity] >= 4) ? 'fail' : 'warn') : 'pass', detail: bad.length ? `${bad.length} segnalazioni: ${detail}` : detail, checked: false });
  const checklist = [
    item('c1', `Rivedute tutte le ${files.length} modifiche rispetto a ${base}`, [], `${commits.length} commit, +${files.reduce((s, f) => s + f.add, 0)}/-${files.reduce((s, f) => s + f.del, 0)} righe`, true),
    item('c2', 'Nessun segreto/credenziale nel codice', has('SEC-SECRET-PRIVKEY', 'SEC-SECRET-AWS', 'SEC-SECRET-TOKEN', 'SEC-SECRET-ASSIGN', 'SEC-SENSITIVE-FILE'), 'rimuovere e ruotare le chiavi', false),
    item('c3', 'Nessuna vulnerabilita\' evidente (injection, XSS, TLS, eval)', has('SEC-EVAL', 'SEC-EXEC', 'SEC-SQL-CONCAT', 'SEC-XSS', 'SEC-TLS-OFF', 'SEC-WEAK-HASH', 'SEC-CORS-ANY', 'SEC-CHMOD'), 'vedi sezione Sicurezza'),
    item('c4', 'Nessun conflitto di merge, debugger o test disabilitato', has('ERR-CONFLICT', 'ERR-DEBUGGER', 'ERR-TEST-ONLY'), 'vedi Errori'),
    item('c5', 'Nessun simbolo rimosso/cambiato ancora usato altrove', has('REG-REMOVED-SYMBOL', 'REG-SIGNATURE'), 'verificare i chiamanti'),
    item('c6', 'Le modifiche ai sorgenti sono coperte da test', has('REG-NO-TESTS', 'REG-TEST-DELETED'), 'aggiungere/ripristinare test'),
    item('c7', 'Dipendenze verificate (versioni, lockfile, CVE)', has('DEP-NO-LOCK', 'DEP-CHANGED'), 'controllare i manifest'),
    item('c8', 'Commit chiari e di dimensione ragionevole', has('GIT-MSG', 'GIT-BIG-COMMIT'), 'valutare squash/riscrittura messaggi'),
    { id: 'c9', title: `Branch aggiornato rispetto a ${base}`, status: behind ? 'warn' : 'pass', detail: behind ? `${behind} commit di ${base} non ancora integrati: rischio regressioni al merge` : 'allineato', checked: false },
    { id: 'c10', title: 'Working tree pulito (nessuna modifica non committata)', status: dirty.length ? 'warn' : 'pass', detail: dirty.length ? `${dirty.length} file non committati: non analizzati` : 'pulito', checked: false },
    { id: 'c11', title: 'Revisione AI completata', status: aiInfo.used ? (aiInfo.skipped || aiInfo.errors.length ? 'warn' : 'pass') : 'manual', detail: aiInfo.used ? `${aiInfo.calls} chiamate, ${aiInfo.skipped} elementi non inviati per budget` : aiInfo.note, checked: false },
  ];

  const bySev = {}; for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  const report = {
    id: new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '-' + crypto.randomBytes(2).toString('hex'),
    createdAt: new Date().toISOString(), repo, branch, base, baseDetected: !!detected, mergeBase: mb, behind, dirty: dirty.length,
    summary: { commits: commits.length, files: files.length, added: files.reduce((s, f) => s + f.add, 0), deleted: files.reduce((s, f) => s + f.del, 0), findings: findings.length, bySeverity: bySev,
      byStatus: files.reduce((o, f) => (o[f.status] = (o[f.status] || 0) + 1, o), {}) },
    commits, files, findings, checklist, ai: aiInfo,
  };
  fs.mkdirSync(path.join(DATA, 'reports'), { recursive: true });
  fs.writeFileSync(path.join(DATA, 'reports', report.id + '.json'), JSON.stringify(report));
  return report;
}

export function listReports() {
  const dir = path.join(DATA, 'reports');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort().reverse().slice(0, 50).map((f) => {
    try { const r = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); return { id: r.id, createdAt: r.createdAt, repo: r.repo, branch: r.branch, base: r.base, summary: r.summary }; } catch { return null; }
  }).filter(Boolean);
}
const rpath = (id) => { if (!/^[\w-]+$/.test(id)) throw new Error('id non valido'); return path.join(DATA, 'reports', id + '.json'); };
export const getReport = (id) => JSON.parse(fs.readFileSync(rpath(id), 'utf8'));
export function setChecked(id, itemId, checked) {
  const r = getReport(id); const c = r.checklist.find((x) => x.id === itemId); if (!c) throw new Error('voce non trovata');
  c.checked = !!checked; fs.writeFileSync(rpath(id), JSON.stringify(r)); return r;
}

export function toMarkdown(r) {
  const L = [];
  L.push(`# Report analisi: ${r.branch} ← ${r.base}`, '', `- Repo: \`${r.repo}\``, `- Data: ${r.createdAt}`, `- Merge-base: \`${r.mergeBase.slice(0, 10)}\`${r.baseDetected ? ' (base dedotto automaticamente)' : ''}`,
    `- Commit: ${r.summary.commits} · File: ${r.summary.files} · +${r.summary.added}/-${r.summary.deleted}`, `- Segnalazioni: ${r.summary.findings} ${JSON.stringify(r.summary.bySeverity)}`,
    `- AI: ${r.ai.used ? `${r.ai.calls} chiamate (${r.ai.cached} da cache), token stimati in/out ${r.ai.estIn}/${r.ai.estOut}, reali ${r.ai.in}/${r.ai.out}, non inviati ${r.ai.skipped}` : r.ai.note}`, '', '## Checklist');
  for (const c of r.checklist) L.push(`- [${c.checked ? 'x' : ' '}] ${{ pass: '✅', warn: '⚠️', fail: '❌', manual: '👁️' }[c.status]} **${c.title}** — ${c.detail}`);
  L.push('', '## Modifiche rispetto a ' + r.base, '', '| Stato | File | + | - |', '|---|---|---|---|');
  for (const f of r.files) L.push(`| ${f.status} | ${f.oldPath ? f.oldPath + ' → ' : ''}${f.path} | ${f.add} | ${f.del} |`);
  L.push('', '## Commit', '');
  for (const c of r.commits) L.push(`- \`${c.short}\` ${c.subject} (${c.author}, ${c.files} file, +${c.add}/-${c.del})`);
  L.push('', '## Segnalazioni', '');
  for (const f of r.findings) L.push(`- **${f.severity.toUpperCase()}** [${f.category}] ${f.file}${f.line ? ':' + f.line : ''} — ${f.message}${f.ai ? ` _(AI: ${f.ai}${f.aiNote ? ' – ' + f.aiNote : ''})_` : ''}`);
  return L.join('\n') + '\n';
}
