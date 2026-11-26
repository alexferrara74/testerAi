import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as G from './git.js';
import * as R from './rules.js';
import { retrieveDocs } from './tokens.js';
import { analyzeCommits, findingKey } from './commits.js';
import { changedDeps, checkCves } from './deps.js';
import { computeImpact } from './impact.js';
import { buildReview, reviewStats, reviewChecklistItem, loadStore, saveStore } from './review.js';
import { triage, impactReview, guidedReview, renderPack, newUsage } from './ai.js';
import { distill, words } from './docs.js';
import { loadConfig, DATA } from './config.js';

export const PHASES = [['collect', 'Raccolta modifiche'], ['rules', 'Regole statiche'], ['cve', 'Verifica CVE'], ['commits', 'Analisi per commit'], ['review', 'Revisione riga per riga'], ['impact', 'Impatto sugli endpoint'], ['symbols', 'Simboli rimossi / firme'], ['ai', 'Revisione AI']];
const SEV = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const ignored = (cfg, p) => cfg.analysis.ignorePaths.some((i) => p.includes(i));

export async function analyze({ repo, branch, base, docs = [], note = '', useAI = true, onProgress = () => {} }) {
  const cfg = loadConfig();
  const dist = distill(docs); // regole del documento di analisi (locale, 0 token)
  if (!G.isGitRepo(repo)) throw new Error('La cartella non e\' un repository git');
  branch = G.safeRef(branch || (await G.listBranches(repo)).current);
  let detected = null;
  if (!base) { detected = await G.detectBase(repo, branch); if (!detected) throw new Error('Impossibile dedurre il branch base: specificalo'); base = detected.base; }
  G.safeRef(base);
  const mb = await G.mergeBase(repo, base, branch);
  onProgress('collect', 'rispetto a ' + base);

  // Solo i commit del branch (dal punto di stacco) + le modifiche locali non committate se sei su quel branch.
  const dirty = await G.dirtyFiles(repo);
  const wt = cfg.analysis.includeWorktree && dirty.length > 0 && (await G.currentBranch(repo)) === branch;
  const TO = wt ? G.WT : branch; // stato "finale" analizzato
  const [commits, status, stats, diff, behind] = await Promise.all([
    G.commitsBetween(repo, mb, branch), G.nameStatus(repo, mb, TO), G.numstat(repo, mb, TO),
    G.parseDiff(repo, mb, TO), G.behindCount(repo, base, branch),
  ]);
  if (wt) {
    const [wst, wns] = await Promise.all([G.nameStatus(repo, 'HEAD', G.WT), G.numstat(repo, 'HEAD', G.WT)]);
    let a = 0, d = 0; for (const v of wns.values()) { a += v.add; d += v.del; }
    commits.push({ hash: G.WT, short: 'locale', author: '(modifiche locali)', date: new Date().toISOString(), merge: false, subject: 'Modifiche locali non committate', files: wst.length, add: a, del: d });
  }

  const findings = [];
  const add = (f) => { const x = { id: 'F' + (findings.length + 1), source: 'rule', ...f }; findings.push(x); return x; };

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
  onProgress('rules');
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

  /* --- CVE sulle dipendenze aggiunte/cambiate (0 token, OSV.dev) --- */
  let deps = [], cveInfo = { checked: 0, error: null, disabled: !cfg.analysis.cve.enabled };
  if (cfg.analysis.cve.enabled && manifests.concat(locks).length) {
    onProgress('cve');
    deps = await changedDeps(repo, mb, TO, files.filter((f) => f.status !== 'D').map((f) => f.path));
    cveInfo = { ...cveInfo, ...(await checkCves(deps, cfg.analysis.cve)) };
    for (const d of deps) {
      if (!d.exact) add({ rule: 'DEP-UNPINNED', category: 'security', severity: 'low', file: d.file, message: `${d.name}: versione non bloccata (${d.to}~) senza lockfile: CVE verificate sulla base del range` });
      for (const v of d.vulns || []) add({ rule: 'DEP-CVE', category: 'security', severity: v.severity, file: d.file, message: `${d.name}@${d.to}: ${v.cve || v.id}${v.summary ? ' – ' + v.summary : ''}${v.fixed ? ` (fix: ${v.fixed})` : ''}` });
    }
  }

  /* --- analisi per singolo commit (0 token) + attribuzione dei problemi al commit che li ha introdotti --- */
  onProgress('commits');
  const perCommit = await analyzeCommits(repo, commits, { ignored: (p) => ignored(cfg, p), max: cfg.analysis.maxCommits });
  const finalKeys = new Set(findings.filter((f) => f.code).map(findingKey));
  const introducedBy = new Map();
  for (const c of commits) for (const cf of perCommit.byHash.get(c.hash)?.findings || []) if (cf.code) introducedBy.set(findingKey(cf), c);
  for (const f of findings) { const c = f.code && introducedBy.get(findingKey(f)); if (c) f.commit = c.short; }
  const SECRET = new Set(['SEC-SECRET-PRIVKEY', 'SEC-SECRET-AWS', 'SEC-SECRET-TOKEN', 'SEC-SECRET-ASSIGN']);
  for (const c of commits) {
    const a = perCommit.byHash.get(c.hash);
    if (!a) { c.analysis = null; continue; }
    const fixedLater = a.findings.filter((cf) => cf.code && !finalKeys.has(findingKey(cf)));
    for (const cf of fixedLater) if (SECRET.has(cf.rule)) add({ rule: 'SEC-SECRET-HISTORY', category: 'security', severity: 'high', file: cf.file, line: 0, commit: c.short, message: `Segreto introdotto nel commit ${c.short} e poi rimosso: resta nella cronologia git, va ruotato` });
    const bySev = {}; for (const f of a.findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
    c.analysis = { risk: a.risk, bySeverity: bySev, files: a.files, noTests: a.touchesSrc && !a.touchesTests,
      findings: a.findings.map((f) => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line, message: f.message, code: f.code, fixedLater: !!f.code && !finalKeys.has(findingKey(f)) })) };
  }

  /* --- revisione riga per riga: ogni hunk di ogni commit diventa una voce da decidere (0 token) --- */
  onProgress('review');
  const store = loadStore(repo, branch);
  const review = buildReview({ commits, perCommit: perCommit.byHash, finalDiff: diff, store, ignored: (p) => ignored(cfg, p), max: cfg.analysis.maxReviewItems });
  saveStore(repo, branch, store);
  for (const it of review.items) {
    if (it.state === 'superseded') continue;
    for (const t of it.tags) {
      if (t.rule || (SEV[t.sev] || 0) < 4) continue; // le regole statiche sono gia' tra le segnalazioni
      const first = it.lines.find((l) => l.k === (t.id.startsWith('reg-') && !/op|const|lit|await/.test(t.id) ? '-' : '+')) || it.lines[0];
      add({ rule: 'REV-' + t.id.toUpperCase(), category: t.id.startsWith('reg-') ? 'regression' : 'security', severity: t.sev, file: it.file, line: first?.n || it.newStart, commit: it.commit, message: t.label + (t.detail ? `: ${t.detail}` : ''), code: (first?.t || '').trim().slice(0, 160) });
    }
  }

  /* --- impatto: dalle modifiche in punti esistenti risale i chiamanti fino agli endpoint (0 token) --- */
  let impact = { endpoints: [], analyzed: 0, skipped: 0, disabled: !cfg.analysis.impact.enabled }; let impactPacks = [];
  const aiReady = useAI && cfg.ai.enabled && cfg.ai.model && !cfg.privacy.offline;
  if (cfg.analysis.impact.enabled) {
    onProgress('impact');
    const hashByShort = new Map(commits.map((c) => [c.short, c.hash]));
    try {
      impact = { ...impact, ...(await computeImpact({ repo, ref: TO, items: review.items, hashOf: (sh) => hashByShort.get(sh), changedFiles: new Set(files.map((f) => f.path)), cfg, buildPacks: aiReady })) };
      impactPacks = impact.packs || []; delete impact.packs;
    } catch (e) { impact.error = e.message; }
    for (const it of review.items) {
      const im = it.impact; if (!im || !im.risk || it.state === 'superseded') continue;
      if (!(im.risk === 'high' || im.risk === 'critical' || (im.risk === 'medium' && it.tags.some((t) => t.id.startsWith('reg-'))))) continue;
      const first = it.lines.find((l) => l.k === '+') || it.lines[0];
      im.findingId = add({ rule: 'REG-IMPACT', category: 'regression', severity: im.risk, file: it.file, line: first?.n || it.newStart, commit: it.commit,
        message: `Modifica in «${im.fn || it.file}» (${it.tags.filter((t) => t.sev !== 'none').slice(0, 2).map((t) => t.label).join('; ')}): ${im.reasons.join('; ')}`, code: (first?.t || '').trim().slice(0, 160) }).id;
    }
  }

  /* --- regressioni: simboli rimossi/cambiati ancora usati --- */
  onProgress('symbols');
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
        const refs = (await G.grepSymbol(repo, TO, name)).filter((p) => p !== file);
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
  const aiInfo = { privacy: { sendCode: cfg.privacy.sendCode, redact: cfg.privacy.redactSecrets, offline: cfg.privacy.offline }, used: false, provider: cfg.ai.provider, model: cfg.ai.model, maxContextTokens: cfg.budget.maxContextTokens, monthlyLimit: cfg.budget.monthlyTokens, spent: 0, calls: 0, cached: 0, estIn: 0, estOut: 0, in: 0, out: 0, skipped: 0, errors: [], note: '' };
  if (aiReady && cfg.budget.strategy === 'guided') {
    /* UNA chiamata compatta guidata dal documento: BRIEF + regole pertinenti + una riga per modifica rischiosa */
    const usage = newUsage(cfg); const byFid = new Map(findings.map((f) => [f.id, f]));
    onProgress('ai', 'analisi guidata dal documento');
    const TW = { critical: 100, high: 80, medium: 50, low: 20, info: 5, none: 0 };
    const packOf = new Map(); for (const pk of impactPacks) for (const id of pk.itemIds) packOf.set(id, pk);
    const groups = new Map(); const linked = new Set();
    for (const it of review.items) {
      if (it.state === 'superseded' || it.level === 'trivial') continue;
      const tags = it.tags.filter((t) => t.sev !== 'none').sort((a, b) => SEV[b.sev] - SEV[a.sev]); const im = it.impact; const pk = packOf.get(it.id);
      const key = pk ? pk.key : it.file + '|' + (im?.fn || it.newStart);
      let g = groups.get(key);
      if (!g) { g = { where: `${path.basename(it.file)}:${im?.fn || 'L' + (it.newStart || 1)}`, file: it.file, line: it.newStart, commit: it.commit, tags: [], itemIds: [], findingIds: [], priority: 0, route: '', idents: [], pack: pk }; groups.set(key, g); }
      g.itemIds.push(it.id);
      for (const t of tags) if (!g.tags.includes(t.id) && g.tags.length < 3) g.tags.push(t.id);
      g.priority = Math.max(g.priority, tags[0] ? TW[tags[0].sev] : 0, im?.risk ? TW[im.risk] : 0);
      if (im?.endpoints?.length && !g.route) { const e = im.endpoints[0]; g.route = `${e.chain.join('>')}=>${e.label}${im.endpoints.length > 1 ? '+' + (im.endpoints.length - 1) : ''}`; g.priority += Math.min(30, im.endpoints.length * 10); }
      for (const f of findings) if (f.file === it.file && f.commit === it.commit && f.line >= it.newStart && f.line <= it.newStart + it.lines.length && !g.findingIds.includes(f.id)) { g.findingIds.push(f.id); linked.add(f.id); }
      if (im?.findingId && !g.findingIds.includes(im.findingId)) { g.findingIds.push(im.findingId); linked.add(im.findingId); }
      g.idents.push(...words(it.lines.filter((l) => l.k === '+').map((l) => l.t).join(' ')).slice(0, 8));
    }
    const changes = [...groups.values()].filter((g) => g.priority >= 20 || g.route).sort((a, b) => b.priority - a.priority).slice(0, 40);
    for (const f of findings) if (f.rule.startsWith('REG-') && f.file && !linked.has(f.id) && f.rule !== 'REG-IMPACT' && SEV[f.severity] >= 3) changes.push({ where: `${path.basename(f.file)}:${(f.code || '').slice(0, 30)}`, file: f.file, line: f.line, commit: f.commit, tags: [f.rule.toLowerCase()], itemIds: [], findingIds: [f.id], priority: TW[f.severity], route: '', idents: words(f.message).slice(0, 8) });
    changes.sort((a, b) => b.priority - a.priority); changes.forEach((c, i) => { c.id = 'C' + (i + 1); });
    try {
      const gr = await guidedReview(cfg, { rules: dist.rules, brief: note }, changes, usage, { render: async (pack, tokens) => renderPack(pack, tokens, false) });
      aiInfo.errors.push(...gr.errors);
      for (const c of changes) {
        if (!gr.sent.has(c.id)) continue;
        const v = gr.results.get(c.id); const verdict = v ? v.v : 'ok';
        const rtexts = c.rules.map((id) => dist.rules.find((r) => r.id === id)).filter(Boolean);
        for (const fid of c.findingIds) { const f = byFid.get(fid); if (f) { f.ai = verdict === 'risk' || verdict === 'viol' ? 'confermato' : verdict === 'unsure' ? 'incerto' : 'nessun problema segnalato'; f.aiNote = v?.why || ''; } }
        for (const iid of c.itemIds) { const it = review.items.find((x) => x.id === iid); if (it) { it.ai = { v: verdict, why: v?.why || '', rules: c.rules }; if (it.impact) it.impact.ai = it.ai; } }
        if (verdict === 'viol') add({ source: 'ai', rule: 'DOC-RULE', category: 'regression', severity: 'high', file: c.file, line: c.line, commit: c.commit, message: `Possibile violazione del documento (${c.rules.join(', ') || 'regole'}): ${rtexts[0]?.text || ''}${v?.why ? ' — ' + v.why : ''}`.slice(0, 400), ai: 'confermato' });
        else if (verdict === 'risk' && !c.findingIds.length) add({ source: 'ai', rule: 'AI-IMPACT', category: 'regression', severity: 'medium', file: c.file, line: c.line, commit: c.commit, message: `Rischio segnalato dall'AI su «${c.where}»: ${v?.why || ''}`, ai: 'confermato' });
      }
      Object.assign(aiInfo, { used: gr.sent.size > 0 || usage.cached > 0, ...usage, skipped: gr.skipped, errors: aiInfo.errors, guided: { rulesTotal: dist.rules.length, rulesUsed: gr.rulesUsed.map((r) => ({ id: r.id, text: r.text })), brief: !!note.trim(), changes: changes.length, sent: gr.sent.size, rounds: gr.rounds } });
    } catch (e) { aiInfo.errors.push(e.message); }
  } else if (aiReady) {
    const usage = newUsage(cfg); const byFid = new Map(findings.map((f) => [f.id, f]));
    /* (a) Revisione d'impatto a CONTESTO CHIUSO: l'AI vede solo funzione modificata, metodi collegati, chiamanti diretti e percorso all'endpoint */
    const RW = { critical: 4, high: 3, medium: 2, low: 1 };
    const packs = impactPacks.filter((p) => RW[p.risk] >= 2 || p.tags.length).sort((a, b) => RW[b.risk] - RW[a.risk]);
    if (packs.length) {
      onProgress('ai', 'impatto a contesto chiuso');
      try {
        const ir = await impactReview(cfg, packs, usage);
        aiInfo.impactReviewed = ir.verdicts.size; aiInfo.impactSkipped = ir.skipped; aiInfo.errors.push(...ir.errors);
        for (const pk of packs) {
          const v = ir.verdicts.get(pk.key); if (!v) continue;
          for (const id of pk.itemIds) { const it = review.items.find((x) => x.id === id); if (!it?.impact) continue; it.impact.ai = { v: v.v, why: v.why }; const f = byFid.get(it.impact.findingId); if (f) { f.ai = v.v === 'risk' ? 'confermato' : v.v === 'ok' ? 'falso positivo' : 'incerto'; f.aiNote = v.why; if (v.v === 'ok') { f.severityOriginal = f.severity; f.severity = 'info'; } } }
          if (v.v === 'risk' && !pk.itemIds.some((id) => byFid.has(review.items.find((x) => x.id === id)?.impact?.findingId))) { const it = review.items.find((x) => x.id === pk.itemIds[0]); add({ source: 'ai', rule: 'AI-IMPACT', category: 'regression', severity: 'medium', file: pk.file, line: it?.newStart, commit: it?.commit, message: `Impatto di «${pk.fn}»: ${v.why || 'rischio segnalato dall\'AI'}`, ai: 'confermato' }); }
        }
      } catch (e) { aiInfo.errors.push(e.message); }
    }
    onProgress('ai', 'triage finale');
    // Risparmio token: le regole "certe" (chiavi, conflitti...) NON vanno all'AI. Solo i casi ambigui,
    // poi le regressioni (simbolo+file), infine gli hunk rischiosi, finche' la quota lo permette.
    const CERTAIN = new Set(['SEC-SECRET-PRIVKEY', 'SEC-SECRET-AWS', 'SEC-SECRET-TOKEN', 'ERR-CONFLICT', 'SEC-SENSITIVE-FILE']);
    const noCode = !cfg.privacy.sendCode;
    const items = []; const byId = new Map(findings.map((f) => [f.id, f]));
    const cut = (x, n) => String(x || '').trim().replace(/\s+/g, ' ').slice(0, n);
    for (const f of findings) {
      if (CERTAIN.has(f.rule) || SEV[f.severity] < 3 || f.ai) continue; // gia' valutata dall'AI nel contesto chiuso
      if (f.rule === 'REG-IMPACT') items.push({ id: f.id, priority: 160, text: `${f.id}|${path.basename(f.file)}|${cut(f.message, 100)}` });
      else if (f.code && f.line) items.push({ id: f.id, priority: 200 + SEV[f.severity], text: `${f.id}|${path.basename(f.file)}:${f.line}|${noCode ? f.rule : cut(f.code, 90)}` });
      else if (f.rule.startsWith('REG-')) items.push({ id: f.id, priority: 150, text: `${f.id}|${path.basename(f.file)}|${noCode ? f.rule : cut(f.message, 90)}` });
    }
    const flagged = new Set(findings.map((f) => f.file));
    let hid = 0;
    for (const [file, d] of noCode ? [] : diff) {
      if (ignored(cfg, file) || !R.isSourcePath(file)) continue;
      const score = (R.isRiskyPath(file) ? 30 : 0) + Math.min(20, d.hunks.reduce((s, h) => s + h.removed.length, 0)) + (flagged.has(file) ? 0 : 5);
      if (score < 15) continue;
      const h = d.hunks[0];
      const code = [...h.removed.slice(0, 1).map((r) => '-' + r.t.trim()), ...h.added.slice(0, 2).map((x) => '+' + x.t.trim())].join(' ').slice(0, 100);
      if (code.length > 12) items.push({ id: 'H' + ++hid, priority: score, text: `H${hid}|${path.basename(file)}:${h.newStart}|${code}`, file, line: h.newStart, code });
    }
    const kw = [...files.map((f) => path.basename(f.path).replace(/\.\w+$/, '')), ...commits.flatMap((c) => c.subject.split(/\W+/))];
    const docsText = noCode ? '' : retrieveDocs([...docs, ...(note.trim() ? [{ name: 'note', text: note }] : [])], kw, cfg.budget.docTokens);
    try {
      const r = await triage(cfg, items, docsText, { snippet: (f, a, b) => G.showLines(repo, TO, f, a, b) }, usage);
      Object.assign(aiInfo, { used: true, ...r.usage, skipped: r.skipped + (aiInfo.impactSkipped || 0), errors: [...aiInfo.errors, ...r.errors] });
      for (const [id, why] of r.bug) {
        const f = byId.get(id);
        if (f) { f.ai = 'confermato'; f.aiNote = why; } else { const it = items.find((i) => i.id === id); if (it && it.file) add({ source: 'ai', rule: 'AI-REVIEW', category: 'error', severity: 'medium', file: it.file, line: it.line, message: 'Possibile problema segnalato dall\'AI (da verificare)', code: it.code }); }
      }
      for (const id of r.fp) { const f = byId.get(id); if (f) { f.ai = 'falso positivo'; f.severityOriginal = f.severity; f.severity = 'info'; } }
    } catch (e) { aiInfo.errors.push(e.message); }
    if (!aiInfo.used) Object.assign(aiInfo, { used: usage.calls + usage.cached > 0, ...usage, errors: aiInfo.errors });
  } else aiInfo.note = cfg.privacy.offline ? 'Modalità offline: nessun dato lascia il PC.' : useAI ? 'AI non abilitata/configurata: analisi solo statica (0 token).' : 'AI disattivata per questa analisi.';

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
    item('c12', 'Nessun commit introduce segreti o problemi gravi (anche se corretti dopo)', has('SEC-SECRET-HISTORY'), 'ruotare le credenziali e valutare la riscrittura della storia'),
    { id: 'c13', title: 'Nessuna CVE nelle dipendenze nuove/aggiornate', ...(() => { const v = has('DEP-CVE'); if (cveInfo.disabled) return { status: 'manual', detail: 'verifica CVE disattivata' }; if (cveInfo.error) return { status: 'warn', detail: cveInfo.error }; if (!deps.length) return { status: 'pass', detail: 'nessuna dipendenza modificata' }; return { status: v.length ? (v.some((f) => SEV[f.severity] >= 4) ? 'fail' : 'warn') : 'pass', detail: v.length ? `${v.length} vulnerabilita\' note: aggiornare alla versione corretta` : `${deps.length} dipendenze verificate su OSV` }; })(), checked: false },
    item('c8', 'Commit chiari e di dimensione ragionevole', has('GIT-MSG', 'GIT-BIG-COMMIT'), 'valutare squash/riscrittura messaggi'),
    { id: 'c9', title: `Branch aggiornato rispetto a ${base}`, status: behind ? 'warn' : 'pass', detail: behind ? `${behind} commit di ${base} non ancora integrati: rischio regressioni al merge` : 'allineato', checked: false },
    { id: 'c10', title: 'Modifiche locali non committate', status: wt ? 'warn' : dirty.length ? 'warn' : 'pass', detail: wt ? `${dirty.length} file locali INCLUSI nell'analisi (voce «locale»): ricordati di committarli` : dirty.length ? `${dirty.length} file non committati su un altro branch: non analizzati` : 'nessuna modifica locale', checked: false },
    { ...reviewChecklistItem(reviewStats(review.items)), checked: false },
    item('c15', 'Impatto sugli endpoint verificato (chiamanti non toccati, test nel percorso)', has('REG-IMPACT'), 'vedi scheda Impatto'),
    { id: 'c11', title: 'Revisione AI completata', status: aiInfo.used ? (aiInfo.skipped || aiInfo.errors.length ? 'warn' : 'pass') : 'manual', detail: aiInfo.used ? `${aiInfo.calls} chiamate, ${aiInfo.spent} token spesi, ${aiInfo.skipped} elementi non inviati per budget` : aiInfo.note, checked: false },
  ];

  const bySev = {}; for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  const report = {
    id: new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + '-' + crypto.randomBytes(2).toString('hex'),
    createdAt: new Date().toISOString(), repo, branch, base, baseDetected: !!detected, mergeBase: mb, behind, dirty: dirty.length,
    summary: { impactedEndpoints: impact.endpoints.length, localChanges: wt, commits: commits.length, commitsAnalyzed: perCommit.analyzed, files: files.length, added: files.reduce((s, f) => s + f.add, 0), deleted: files.reduce((s, f) => s + f.del, 0), findings: findings.length, bySeverity: bySev,
      byStatus: files.reduce((o, f) => (o[f.status] = (o[f.status] || 0) + 1, o), {}) },
    commits, files, findings, checklist, ai: aiInfo, deps, cve: cveInfo, docs: { names: docs.map((d) => d.name), rules: dist.rules.length, note: !!note.trim() },
    impact,
    review: { items: review.items, stats: reviewStats(review.items), resolved: review.resolved, truncated: review.truncated },
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

export function setReviewState(id, keys, state, note) {
  if (!['open', 'aware', 'fix'].includes(state)) throw new Error('stato non valido');
  const r = getReport(id); const store = loadStore(r.repo, r.branch); const set = new Set(keys);
  for (const it of r.review.items) {
    if (!set.has(it.key) || it.state === 'superseded') continue;
    it.state = state; if (note !== undefined) it.note = note;
    if (state === 'open') delete store[it.key];
    else store[it.key] = { state, file: it.file, label: it.tags.map((t) => t.label).slice(0, 2).join(' · '), note: it.note || '', at: new Date().toISOString() };
  }
  saveStore(r.repo, r.branch, store);
  r.review.stats = reviewStats(r.review.items);
  const c = r.checklist.find((x) => x.id === 'c14'); if (c) Object.assign(c, reviewChecklistItem(r.review.stats));
  fs.writeFileSync(rpath(id), JSON.stringify(r));
  return { stats: r.review.stats, checklist: r.checklist };
}

export function toMarkdown(r) {
  const L = [];
  L.push(`# Report analisi: ${r.branch} ← ${r.base}`, '', `- Repo: \`${r.repo}\``, `- Data: ${r.createdAt}`, `- Merge-base: \`${r.mergeBase.slice(0, 10)}\`${r.baseDetected ? ' (base dedotto automaticamente)' : ''}`,
    `- Commit: ${r.summary.commits} · File: ${r.summary.files} · +${r.summary.added}/-${r.summary.deleted}`, `- Segnalazioni: ${r.summary.findings} ${JSON.stringify(r.summary.bySeverity)}`,
    `- AI: ${r.ai.used ? `${r.ai.calls} chiamate (${r.ai.cached} da cache), ${r.ai.spent} token spesi (quota mensile ${r.ai.monthlyUsedBefore + r.ai.spent}/${r.ai.monthlyLimit}), non inviati ${r.ai.skipped}` : r.ai.note}`, '', '## Checklist');
  for (const c of r.checklist) L.push(`- [${c.checked ? 'x' : ' '}] ${{ pass: '✅', warn: '⚠️', fail: '❌', manual: '👁️' }[c.status]} **${c.title}** — ${c.detail}`);
  if (r.impact?.endpoints?.length) {
    L.push('', '## Impatto sugli endpoint', '');
    for (const e of r.impact.endpoints) L.push(`- **${e.risk.toUpperCase()}** ${e.label} (\`${e.file}:${e.line}\`) ← ${e.chains.map((c) => c.join(' → ')).join(' | ')}`);
  }
  if (r.review) {
    const st = r.review.stats;
    L.push('', '## Revisione modifiche', '', `${st.total - st.toDecide}/${st.total} decise · ${st.aware} consapevoli · ${st.fix} da fixare · ${st.blocking} problemi bloccanti · ${st.superseded} riscritte in commit successivi`);
    if (r.review.resolved?.length) L.push('', `Fix verificati: ${r.review.resolved.length}`);
    const todo = r.review.items.filter((i) => i.state === 'fix');
    if (todo.length) { L.push('', '### Da fixare'); for (const i of todo) L.push(`- [ ] \`${i.file}:${i.newStart}\` (${i.commit}) — ${i.tags.map((t) => t.label).join('; ')}${i.note ? ' — ' + i.note : ''}`); }
    for (const c of r.commits) {
      const its = r.review.items.filter((i) => i.commit === c.short && i.state !== 'superseded'); if (!its.length) continue;
      L.push('', `### ${c.short} ${c.subject}`);
      for (const i of its) L.push(`- [${i.state === 'aware' ? 'x' : ' '}] ${i.level === 'problem' ? '❌' : i.level === 'trivial' ? '·' : '👁️'} \`${i.file}:${i.newStart}\` ${i.state === 'fix' ? '**DA FIXARE** ' : ''}${i.tags.filter((t) => t.sev !== 'none').map((t) => t.label).join('; ') || 'modifica banale'}`);
    }
  }
  L.push('', '## Modifiche rispetto a ' + r.base, '', '| Stato | File | + | - |', '|---|---|---|---|');
  for (const f of r.files) L.push(`| ${f.status} | ${f.oldPath ? f.oldPath + ' → ' : ''}${f.path} | ${f.add} | ${f.del} |`);
  if (r.deps?.length) { L.push('', '## Dipendenze modificate', '', '| Pacchetto | Da | A | CVE |', '|---|---|---|---|'); for (const d of r.deps) L.push(`| ${d.ecosystem}:${d.name} | ${d.from || '-'} | ${d.to} | ${d.vulns === null ? 'non verificato' : d.vulns.length ? d.vulns.map((v) => v.cve || v.id).join(', ') : 'nessuna'} |`); }
  L.push('', '## Commit', '');
  for (const c of r.commits) {
    L.push(`- \`${c.short}\` ${c.subject} (${c.author}, ${c.files} file, +${c.add}/-${c.del})${c.analysis ? ` — rischio ${c.analysis.risk}${c.analysis.noTests ? ', senza test' : ''}` : ''}`);
    for (const f of c.analysis?.findings || []) L.push(`  - ${f.severity.toUpperCase()} ${f.file}${f.line ? ':' + f.line : ''} ${f.message}${f.fixedLater ? ' _(corretto in un commit successivo)_' : ''}`);
  }
  L.push('', '## Segnalazioni', '');
  for (const f of r.findings) L.push(`- **${f.severity.toUpperCase()}** [${f.category}] ${f.file}${f.line ? ':' + f.line : ''} — ${f.message}${f.ai ? ` _(AI: ${f.ai}${f.aiNote ? ' – ' + f.aiNote : ''})_` : ''}`);
  return L.join('\n') + '\n';
}
