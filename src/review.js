import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';
import * as R from './rules.js';

/* ====================================================================================
 * Revisione modifiche: ogni hunk di ogni commit diventa una voce di checklist.
 * Classificazione 100% statica (0 token): tag di logica inserita + indizi di regressione.
 * ==================================================================================== */
const norm = (s) => s.replace(/\s+/g, '');
const isComment = (t) => /^\s*(\/\/|#|\*|\/\*|\*\/|<!--|--\s|""")/.test(t) || !t.trim();
const count = (lines, re) => lines.reduce((n, l) => n + (re.test(l) ? 1 : 0), 0);
const OPS = ['===', '!==', '<=', '>=', '==', '!=', '&&', '||', '<', '>'];
const ops = (s) => (s.match(/===|!==|<=|>=|==|!=|&&|\|\||<|>/g) || []).join(' ');
const stripLits = (s) => s.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '""').replace(/\b\d+(\.\d+)?\b/g, '0').replace(/===|!==|<=|>=|==|!=|&&|\|\||<|>/g, '~').replace(/\s+/g, '');

const T = (id, label, sev, hint) => ({ id, label, sev, hint });

// --- tag per logica INSERITA (cosa ho aggiunto?) ---
const ADDED = [
  { re: /\b(if|else if|elif|switch|case|unless)\b|\?[^:]*:|&&|\|\|/, t: T('logic-cond', 'Nuova condizione', 'info', 'Verifica tutti i rami (anche else/default) e i casi limite (null, vuoto, 0).') },
  { re: /\b(for|while|do)\b\s*[\s({]|\.(forEach|map|reduce|filter|flatMap)\(/, t: T('logic-loop', 'Ciclo / iterazione', 'info', 'Controlla condizione di uscita, off-by-one e costo su insiemi grandi.') },
  { re: /\b(await|async|Promise|setTimeout|setInterval|\.then\(|Thread|synchronized|goroutine|go func|Task\.Run)\b/, t: T('logic-async', 'Asincronia / concorrenza', 'low', 'Verifica ordine di esecuzione, race condition, errori non gestiti e timeout.') },
  { re: /\b(try|catch|except|rescue|finally|throw|raise)\b|\.catch\(/, t: T('logic-err', 'Gestione errori', 'info', 'Controlla che l\'errore non venga ingoiato e che il chiamante lo gestisca.') },
  { re: /\b(fetch|axios|XMLHttpRequest|requests\.(get|post)|http\.(get|request)|readFile|writeFile|fs\.|spawn|exec\(|socket|open\()/, t: T('logic-io', 'I/O esterno (rete/file/processi)', 'low', 'Timeout, retry, input non fidato, permessi e cleanup delle risorse.') },
  { re: /\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\b|\.(query|execute|find|findOne|save|update|delete|transaction)\(/i, t: T('logic-db', 'Accesso ai dati', 'low', 'Query parametrizzate, transazioni, indici e impatto su dati esistenti/migrazioni.') },
  { re: /(auth|permission|role|admin|acl|jwt|session|password|crypto|token|csrf|cors)/i, t: T('logic-sec', 'Sicurezza / autorizzazione', 'medium', 'Rivedi con attenzione: controllo accessi, gestione credenziali e superficie d\'attacco.') },
  { re: /(req\.(body|query|params)|request\.(args|form|json|GET|POST)|process\.argv|\binput\()/, t: T('logic-input', 'Input esterno non fidato', 'medium', 'Valida e sanifica prima dell\'uso (tipo, lunghezza, formato).') },
  { re: /\b(timeout|retry|retries|limit|max|min|threshold|ttl|port|interval|size|delay)\w*\s*[:=]\s*[\d"'`]/i, t: T('logic-cfg', 'Soglia / configurazione', 'low', 'Valore cambiato o introdotto: conferma che sia voluto e coerente con gli altri ambienti.') },
  { re: /\bprocess\.env\b|os\.environ|getenv\(/, t: T('logic-env', 'Dipendenza da variabile d\'ambiente', 'low', 'Documenta la variabile e definisci un default sicuro.') },
];

function pushTag(tags, t, detail) { if (!tags.find((x) => x.id === t.id)) tags.push({ ...t, detail: detail || '' }); }

/** Analizza un hunk: tag di logica + indizi di regressione. */
export function classify(file, hunk) {
  const add = hunk.added.map((x) => x.t), rem = hunk.removed.map((x) => x.t);
  const tags = [];
  const addCode = add.filter((l) => !isComment(l)), remCode = rem.filter((l) => !isComment(l));
  const isTest = R.isTestPath(file);

  // 1) solo commenti / spazi / riordino -> banale
  const sameSet = norm(addCode.slice().sort().join('')) === norm(remCode.slice().sort().join(''));
  const trivial = (!addCode.length && !remCode.length) || (addCode.length && sameSet) || (/^\s*(import|from|#include|using|require)\b/.test(addCode[0] || '') && addCode.every((l) => /^\s*(import|from|#include|using|require|export \{)/.test(l)) && remCode.every((l) => /^\s*(import|from|#include|using|require|export \{)/.test(l)));
  if (trivial) return { tags: [T('trivial', addCode.length || remCode.length ? 'Solo formattazione / riordino' : 'Solo commenti / spazi', 'none', '')], trivial: true };

  // 2) logica inserita
  for (const l of addCode) for (const r of ADDED) if (r.re.test(l)) pushTag(tags, r.t);
  const d = add.map((l) => R.defOf(l)).find(Boolean);
  if (d) pushTag(tags, T('logic-fn', 'Nuova funzione / firma', 'info', 'Controlla i chiamanti esistenti e la gestione dei parametri opzionali.'), d.name);

  // 3) possibili regressioni: cosa ho TOLTO senza sostituire?
  const guardRe = /\b(if|assert|require|validate|sanitize|ensure|guard|check|isNaN|typeof)\b|!==?\s*(null|undefined)|===?\s*(null|undefined)|\.length/i;
  const guardRem = count(remCode, guardRe), guardAdd = count(addCode, guardRe);
  if (guardRem > guardAdd) pushTag(tags, T('reg-guard', 'Rimosso controllo / validazione', 'high', 'Un controllo è sparito senza equivalente: verifica che il caso (null, input non valido, limite) non possa più arrivare qui.'), remCode.find((l) => guardRe.test(l))?.trim().slice(0, 100));
  const errRe = /\b(try|catch|except|rescue|finally|throw|raise)\b|\.catch\(/;
  if (count(remCode, errRe) > count(addCode, errRe)) pushTag(tags, T('reg-err', 'Rimossa gestione errori', 'high', 'Un errore prima gestito ora può propagarsi o essere ignorato: controlla i chiamanti.'), remCode.find((l) => errRe.test(l))?.trim().slice(0, 100));
  const secRe = /(auth|permission|role|admin|acl|csrf|authorize|isAllowed|canAccess|verify)/i;
  if (count(remCode, secRe) > count(addCode, secRe)) pushTag(tags, T('reg-auth', 'Rimosso controllo accessi / sicurezza', 'critical', 'Possibile bypass di autorizzazione: ripristina o dimostra che il controllo è spostato altrove.'), remCode.find((l) => secRe.test(l))?.trim().slice(0, 100));
  const resRe = /\b(close|release|dispose|unlock|finally|clearTimeout|clearInterval|removeEventListener|unsubscribe)\b/;
  if (count(remCode, resRe) > count(addCode, resRe)) pushTag(tags, T('reg-res', 'Rimosso rilascio risorse', 'medium', 'Possibile leak (connessioni, timer, listener, lock).'), remCode.find((l) => resRe.test(l))?.trim().slice(0, 100));
  if (count(remCode, /\bawait\b/) > count(addCode, /\bawait\b/) && remCode.length) pushTag(tags, T('reg-await', 'Rimosso await', 'high', 'Il codice non attende più il risultato: race condition o Promise non gestita.'));
  if (isTest && count(remCode, /\b(expect|assert|should|verify)\b/) > count(addCode, /\b(expect|assert|should|verify)\b/)) pushTag(tags, T('reg-test', 'Test indeboliti (meno asserzioni)', 'high', 'Meno verifiche di prima: il test protegge ancora il comportamento?'));
  if (isTest && count(addCode, /\.(skip|only)\(|@Ignore|xit\(|fit\(/) > 0) pushTag(tags, T('reg-skip', 'Test saltato / focalizzato', 'high', 'Rimuovi .skip/.only prima del merge.'));
  if (rem.length >= 10 && add.length === 0) pushTag(tags, T('reg-del', `Blocco eliminato (${rem.length} righe)`, 'medium', 'Verifica che nessun flusso dipenda ancora da questo codice.'));

  // 4) righe sostituite (stessa struttura, letterali/operatori diversi) -> soglia/operatore cambiato
  if (remCode.length <= 30 && addCode.length <= 30) {
    const used = new Set();
    for (const b of addCode) {
      const i = remCode.findIndex((a, k) => !used.has(k) && norm(a) !== norm(b) && stripLits(a) === stripLits(b));
      if (i < 0) continue; used.add(i); const a = remCode[i];
      const na = a.match(/\b\d+(\.\d+)?\b/g)?.join(',') || '', nb = b.match(/\b\d+(\.\d+)?\b/g)?.join(',') || '';
      const chg = `${a.trim().slice(0, 60)}  →  ${b.trim().slice(0, 60)}`;
      if (ops(a) !== ops(b)) pushTag(tags, T('reg-op', 'Operatore di confronto modificato', 'high', 'Cambio di condizione (es. < → <=, && → ||): controlla i casi limite e i test.'), chg);
      else if (na !== nb) pushTag(tags, T('reg-const', 'Valore / soglia modificato', 'medium', 'Costante cambiata: conferma che sia intenzionale e che i test coprano il nuovo valore.'), chg);
      else pushTag(tags, T('reg-lit', 'Stringa / letterale modificato', 'low', 'Controlla che chiavi, messaggi o path non siano usati altrove.'), chg);
    }
    // operatori booleani cambiati su righe non identiche per struttura
    for (const b of addCode) for (const a of remCode) if (norm(a) !== norm(b) && /&&|\|\|/.test(a + b) && ops(a) !== ops(b) && stripLits(a).replace(/[~&|]+/g, '') === stripLits(b).replace(/[~&|]+/g, '')) pushTag(tags, T('reg-op', 'Logica booleana modificata', 'high', 'Combinazione di condizioni cambiata: ricontrolla la tabella di verità.'), `${a.trim().slice(0, 60)} → ${b.trim().slice(0, 60)}`);
  }
  return { tags, trivial: false };
}

const SEVW = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };
const maxSev = (tags) => tags.reduce((m, t) => Math.max(m, SEVW[t.sev] || 0), 0);

export const itemKey = (file, hunk) => crypto.createHash('sha1').update(file + '\n' + hunk.removed.map((x) => norm(x.t)).join('\n') + '\n--\n' + hunk.added.map((x) => norm(x.t)).join('\n')).digest('hex').slice(0, 14);

/* ---- store delle decisioni: sopravvive alle ri-analisi (chiave = contenuto, non commit/riga) ---- */
const storeFile = (repo, branch) => path.join(DATA, 'review', crypto.createHash('sha1').update(repo + '|' + branch).digest('hex').slice(0, 16) + '.json');
export const loadStore = (repo, branch) => { try { return JSON.parse(fs.readFileSync(storeFile(repo, branch), 'utf8')); } catch { return {}; } };
export const saveStore = (repo, branch, s) => { fs.mkdirSync(path.join(DATA, 'review'), { recursive: true }); fs.writeFileSync(storeFile(repo, branch), JSON.stringify(s)); };

const finalRemovedMap = (diff) => { const m = new Map(); for (const [f, d] of diff) m.set(f, new Set(d.hunks.flatMap((h) => h.removed.map((a) => norm(a.t))).filter((x) => x.length > 2))); return m; };
const finalAddedMap = (diff) => { const m = new Map(); for (const [f, d] of diff) m.set(f, new Set(d.hunks.flatMap((h) => h.added.map((a) => norm(a.t))).filter((x) => x.length > 2))); return m; };

/**
 * commits: commit[] cronologici; perCommit: Map hash -> {diff, files, findings}; finalDiff: diff complessivo.
 */
export function buildReview({ commits, perCommit, finalDiff, store, ignored, max = 500 }) {
  const finals = finalAddedMap(finalDiff), finalsRem = finalRemovedMap(finalDiff);
  let n = 0; const items = [];
  const push = (it) => items.push({ id: 'R' + ++n, ...it });
  for (const c of commits) {
    const a = perCommit.get(c.hash); if (!a || c.merge) continue;
    const seen = new Set();
    for (const f of a.files) {
      if (ignored(f.path)) continue;
      const d = a.diff.get(f.path);
      if (!d || !d.hunks.length) { // file eliminato / rinominato / binario: nessun hunk
        const tags = [];
        if (f.status === 'D') tags.push(R.isTestPath(f.path) ? T('reg-testdel', 'Test eliminato', 'high', 'Un test in meno: la funzionalità resta coperta altrove?') : T('reg-filedel', 'File eliminato', R.isSourcePath(f.path) ? 'medium' : 'low', 'Verifica che nessun import o configurazione lo referenzi ancora.'));
        else if (f.status === 'R') tags.push(T('trivial', 'File rinominato/spostato', 'none', ''));
        else if (R.isSensitiveFile(f.path)) tags.push(T('sec-file', 'File sensibile', 'critical', 'Non deve stare nel repository.'));
        else tags.push(T('trivial', 'File binario / senza modifiche di contenuto', 'none', ''));
        const key = crypto.createHash('sha1').update('file:' + f.status + ':' + f.path).digest('hex').slice(0, 14);
        if (seen.has(key)) continue; seen.add(key);
        push({ key, commit: c.short, file: f.path, oldPath: f.oldPath, fileStatus: f.status, newStart: 0, lines: [], extra: 0, tags, trivial: tags[0].id === 'trivial', superseded: false });
        continue;
      }
      for (const h of d.hunks) {
        const key = itemKey(f.path, h); if (seen.has(key)) continue; seen.add(key);
        const cl = classify(f.path, h);
        const lines = [...h.removed.map((x) => ({ k: '-', n: x.n, t: x.t.slice(0, 220) })), ...h.added.map((x) => ({ k: '+', n: x.n, t: x.t.slice(0, 220) }))];
        const sig = h.added.map((x) => norm(x.t)).filter((x) => x.length > 2);
        const set = finals.get(f.path);
        const rsig = h.removed.map((x) => norm(x.t)).filter((x) => x.length > 2), rset = finalsRem.get(f.path);
        // addizioni ancora presenti? se l'hunk e' solo una rimozione: la riga e' ancora rimossa nel diff complessivo?
        const superseded = sig.length > 0 ? !(set && sig.some((s) => set.has(s))) : rsig.length > 0 && !(rset && rsig.some((s) => rset.has(s)));
        // problemi trovati dalle regole statiche su questo hunk
        const rf = a.findings.filter((x) => x.file === f.path && x.line >= h.newStart && x.line < h.newStart + Math.max(1, h.added.length) && x.severity !== 'info');
        const tags = [...rf.map((x) => ({ id: x.rule, label: x.message, sev: x.severity, hint: 'Segnalazione delle regole statiche: correggi nel codice.', detail: x.code || '', rule: true })), ...cl.tags];
        push({ key, commit: c.short, file: f.path, oldPath: f.oldPath, fileStatus: f.status, newStart: h.newStart, oldStart: h.oldStart, lines: lines.slice(0, 60), extra: Math.max(0, lines.length - 60), tags, trivial: cl.trivial && !rf.length, superseded });
      }
    }
  }
  // livello + stato (con decisioni precedenti)
  for (const it of items) {
    const sev = maxSev(it.tags);
    it.level = it.trivial ? 'trivial' : sev >= 4 || it.tags.some((t) => t.rule && sev >= 3) ? 'problem' : 'check';
    const s = store[it.key];
    it.state = it.superseded ? 'superseded' : s && (s.state === 'aware' || s.state === 'fix') ? s.state : 'open';
    if (s?.note) it.note = s.note;
  }
  let list = items;
  let truncated = 0;
  if (items.length > max) { const keep = items.filter((i) => i.level !== 'trivial'); list = [...keep, ...items.filter((i) => i.level === 'trivial')].slice(0, max); truncated = items.length - list.length; list.sort((a, b) => +a.id.slice(1) - +b.id.slice(1)); }
  // fix verificati: voci marcate "da fixare" che non sono piu' attive
  const active = new Set(list.filter((i) => i.state !== 'superseded').map((i) => i.key));
  const resolved = [];
  for (const [k, v] of Object.entries(store)) if (v.state === 'fix' && !active.has(k)) { resolved.push({ key: k, file: v.file, label: v.label }); store[k] = { ...v, state: 'resolved', at: new Date().toISOString() }; }
  return { items: list, resolved, truncated };
}

export function reviewStats(items) {
  const a = items.filter((i) => i.state !== 'superseded');
  const by = (f) => a.filter(f).length;
  const decided = by((i) => i.state === 'aware' || i.state === 'fix');
  return {
    total: a.length, superseded: items.length - a.length, aware: by((i) => i.state === 'aware'), fix: by((i) => i.state === 'fix'), open: by((i) => i.state === 'open'),
    problems: by((i) => i.level === 'problem'), blocking: by((i) => i.level === 'problem' && i.state !== 'aware'), toDecide: a.length - decided, trivial: by((i) => i.level === 'trivial'),
  };
}

export function reviewChecklistItem(st) {
  const status = !st.total ? 'pass' : st.blocking ? 'fail' : st.toDecide ? 'warn' : 'pass';
  const detail = !st.total ? 'nessuna modifica da rivedere' : `${st.total - st.toDecide}/${st.total} decise · ${st.blocking} problemi bloccanti · ${st.fix} da fixare · ${st.superseded} riscritte nei commit successivi`;
  return { id: 'c14', title: 'Revisione di ogni modifica (riga per riga, commit per commit)', status, detail };
}
