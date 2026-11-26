import * as G from './git.js';
import * as R from './rules.js';

/* ====================================================================================
 * ANALISI D'IMPATTO (0 token, statica): per ogni modifica fatta in un PUNTO ESISTENTE risale i
 * chiamanti fino agli endpoint (HTTP, CLI, eventi, job) e valuta il rischio di errori/regressioni.
 * Euristica multi-linguaggio su testo: non risolve dispatch dinamico/DI/riflessione (segnalato).
 * ==================================================================================== */
const KEYWORDS = /^(if|for|while|switch|catch|function|return|else|do|try|with|constructor|super|new|typeof|await|import|export|class)$/;
const GENERIC = new Set(['get', 'set', 'run', 'init', 'main', 'handle', 'handler', 'process', 'update', 'create', 'delete', 'find', 'save', 'load', 'start', 'stop', 'call', 'exec', 'execute', 'test', 'data', 'list', 'add', 'remove', 'open', 'close', 'read', 'write', 'send', 'parse', 'build', 'render', 'then', 'catch', 'push', 'pop', 'map', 'filter', 'reduce', 'toString', 'valueOf']);
const ROUTE_JS = /\b(?:app|router|server|api|fastify|route|routes|r|v\d|\w*[Rr]outer)\s*\.\s*(get|post|put|patch|delete|all|head|options)\s*\(\s*['"`]([^'"`]+)['"`]/;
const ROUTE_GO = /\b\w+\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\s*\(\s*"([^"]+)"/;
const ROUTE_PY = /^\s*@\s*(?:\w+\.)*(route|get|post|put|patch|delete|api_view)\s*\(\s*(?:\[?\s*)?['"]([^'"]*)['"]/i;
const ROUTE_JAVA = /^\s*@\s*(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)")?/;
const ROUTE_NEST = /^\s*@\s*(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/;
const EVENT = /\b(?:\w+)\s*\.\s*(on|once|addListener|subscribe|consume|process)\s*\(\s*['"`]([^'"`]+)['"`]/;
const JOB = /\b(?:cron\.schedule|schedule\.\w+|@Scheduled|@Cron|setInterval|agenda\.define|queue\.process)\b/;
const isCommentLine = (t) => /^\s*(\/\/|#|\*|\/\*|--|""")/.test(t);
const isTest = R.isTestPath;

export function endpointInLine(text) {
  let m;
  if ((m = text.match(ROUTE_JS)) || (m = text.match(ROUTE_GO))) return { kind: 'http', label: `${m[1].toUpperCase().replace('HANDLEFUNC', 'ANY').replace('HANDLE', 'ANY')} ${m[2]}` };
  if ((m = text.match(ROUTE_PY))) return { kind: 'http', label: `${/route|api_view/i.test(m[1]) ? 'ANY' : m[1].toUpperCase()} ${m[2] || '/'}` };
  if ((m = text.match(ROUTE_JAVA))) return { kind: 'http', label: `${m[1] === 'Request' ? 'ANY' : m[1].toUpperCase()} ${m[2] || '/'}` };
  if ((m = text.match(ROUTE_NEST))) return { kind: 'http', label: `${m[1].toUpperCase()} /${m[2] || ''}` };
  if ((m = text.match(EVENT)) && !/^(error|close|end|data|finish|open|connect|exit|drain|message|ready|listening|SIGINT|SIGTERM|uncaughtException|unhandledRejection)$/.test(m[2])) return { kind: 'event', label: `evento «${m[2]}»` };
  if (JOB.test(text)) return { kind: 'job', label: 'job pianificato' };
  return null;
}
const fileRoute = (file, name) => {
  let m = file.match(/(?:^|\/)pages\/api\/(.+?)\.(?:js|ts|jsx|tsx)$/); if (m) return { kind: 'http', label: `ANY /api/${m[1].replace(/\/index$/, '')}` };
  m = file.match(/(?:^|\/)app\/(.*?)\/?route\.(?:js|ts)$/); if (m && /^(GET|POST|PUT|PATCH|DELETE)$/.test(name || '')) return { kind: 'http', label: `${name} /${m[1]}` };
  return null;
};

// funzione che contiene una riga: risale fino a una definizione con indentazione minore
const METHOD = /^(\s+)(?:public\s+|private\s+|protected\s+|static\s+|async\s+|get\s+|set\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|, ]+)?\s*\{\s*$/;
function defAt(line) {
  const d = R.defOf(line); if (d) return { name: d.name, params: d.params };
  const m = line.match(METHOD); if (m && !KEYWORDS.test(m[2]) && m[2].length >= 2) return { name: m[2], params: '' };
  return null;
}
const indent = (l) => (l.match(/^\s*/)[0].replace(/\t/g, '    ')).length;

/** Risale dalla riga `idx` (0-based) al contenitore: endpoint inline, funzione nominata, o modulo. */
export function enclosing(lines, idx, file) {
  const startIndent = indent(lines[idx] || '');
  const ep0 = endpointInLine(lines[idx] || ''); if (ep0) return { type: 'endpoint', ...ep0, line: idx + 1 };
  let minInd = startIndent;
  for (let i = idx; i >= 0 && idx - i < 400; i--) {
    const l = lines[i]; if (!l.trim() || isCommentLine(l)) continue;
    const ind = indent(l);
    if (ind > minInd && i !== idx) continue; // dentro un blocco piu' annidato: sale
    const ep = endpointInLine(l); if (ep && i !== idx && ind < startIndent + 1) return { type: 'endpoint', ...ep, line: i + 1 };
    const d = defAt(l);
    if (d && (ind < startIndent || i === idx)) {
      // decoratori / annotazioni subito sopra la definizione
      for (let k = i - 1; k >= 0 && i - k <= 4; k--) { const e2 = endpointInLine(lines[k]); if (e2) return { type: 'endpoint', ...e2, line: k + 1, handler: d.name }; if (!/^\s*[@\[]/.test(lines[k]) && lines[k].trim()) break; }
      const fr = fileRoute(file, d.name); if (fr) return { type: 'endpoint', ...fr, line: i + 1, handler: d.name };
      return { type: 'fn', name: d.name, params: d.params, line: i + 1 };
    }
    if (ind < minInd) minInd = ind;
  }
  return { type: 'module' };
}

/** Corpo di una funzione: dalla riga di definizione fino al primo rientro <= indentazione (max n righe). */
export function bodyRange(lines, defIdx, max = 40) {
  const base = indent(lines[defIdx] || ''); const out = [lines[defIdx]];
  for (let i = defIdx + 1; i < lines.length && out.length < max; i++) {
    const l = lines[i]; out.push(l);
    if (l.trim() && indent(l) <= base) break; // chiusura (}) o prossima definizione
  }
  return out.map((l) => l.replace(/\s+$/, '').slice(0, 140));
}
const CALL_RE = /\b([A-Za-z_$][\w$]*)\s*\(/g;

export async function computeImpact({ repo, ref, items, hashOf, changedFiles, cfg, buildPacks = false }) {
  const o = cfg.analysis.impact; const out = { endpoints: new Map(), analyzed: 0, skipped: 0, notes: [] }; const packs = new Map();
  const cache = new Map();
  const read = async (r, f) => { const k = r + '|' + f; if (!cache.has(k)) cache.set(k, (await G.readFileAt(repo, r, f)).split('\n')); return cache.get(k); };
  const fnCache = new Map();

  // callers di un simbolo nello stato finale
  async function callers(name, defFile) {
    const hits = await G.grepLines(repo, ref, name, 300);
    const res = [], tests = new Set();
    for (const h of hits) {
      if (/node_modules|(^|\/)(dist|build|vendor)\/|\.min\./.test(h.file)) continue;
      if (isCommentLine(h.text)) continue;
      if (R.isTestPath(h.file)) { tests.add(h.file); continue; }
      const d = defAt(h.text); if (d && d.name === name) continue; // la definizione stessa
      if (/^\s*(import|from|export\s*\{|#include|using|require)\b/.test(h.text) && !/\(/.test(h.text.replace(/^\s*import[^(]*/, ''))) continue; // solo import
      const lines = await read(ref, h.file);
      const enc = enclosing(lines, h.line - 1, h.file);
      res.push({ file: h.file, line: h.line, enc, text: h.text });
      if (res.length >= 25) break;
    }
    return { res, tests };
  }

  async function trace(start) {
    const key = start.file + '|' + start.name;
    if (fnCache.has(key)) return fnCache.get(key);
    const result = { direct: [], endpoints: [], callers: 0, untouched: new Set(), tests: new Set(), generic: false, depthHit: false, nodes: 0, modules: 0 };
    fnCache.set(key, result);
    const seen = new Set([key]);
    let frontier = [{ name: start.name, file: start.file, chain: [start.name] }];
    for (let depth = 0; depth < o.maxDepth && frontier.length; depth++) {
      const next = [];
      for (const node of frontier) {
        if (result.nodes++ > o.maxNodes) { result.depthHit = true; break; }
        if (node.name.length < 3 || (GENERIC.has(node.name) && depth > 0)) { result.generic = true; continue; }
        const { res, tests } = await callers(node.name, node.file);
        tests.forEach((t) => result.tests.add(t));
        for (const c of res) {
          result.callers++;
          if (depth === 0 && result.direct.length < 4) result.direct.push({ name: c.enc.type === 'fn' ? c.enc.name : c.enc.type === 'endpoint' ? c.enc.label : '(modulo)', file: c.file, line: c.line, defLine: c.enc.type === 'fn' ? c.enc.line : 0, text: (c.text || '').trim().slice(0, 140) });
          if (!changedFiles.has(c.file)) result.untouched.add(`${c.file}:${c.line}`);
          if (c.enc.type === 'endpoint') { result.endpoints.push({ kind: c.enc.kind, label: c.enc.label, file: c.file, line: c.enc.line, chain: [...node.chain, ...(c.enc.handler && c.enc.handler !== node.name ? [c.enc.handler] : [])] }); continue; }
          if (c.enc.type === 'module') { result.modules++; continue; }
          const k = c.file + '|' + c.enc.name; if (seen.has(k)) continue; seen.add(k);
          next.push({ name: c.enc.name, file: c.file, chain: [...node.chain, c.enc.name] });
        }
      }
      frontier = next;
      if (depth === o.maxDepth - 1 && frontier.length) result.depthHit = true;
    }
    return result;
  }

  const cand = items.filter((i) => i.state !== 'superseded' && i.level !== 'trivial' && i.fileStatus !== 'D' && i.lines.length && R.langOf(i.file) !== 'other' && !R.isTestPath(i.file))
    .sort((a, b) => (b.level === 'problem') - (a.level === 'problem')).slice(0, o.maxItems);
  out.skipped = items.length - cand.length;
  for (const it of cand) {
    const hash = hashOf(it.commit); if (!hash) continue;
    const at = hash === G.WT ? G.WT : hash;
    const lines = await read(at, it.file); if (lines.length <= 1) continue;
    const hasRemoved = it.lines.some((l) => l.k === '-');
    const addedDefs = new Set(it.lines.filter((l) => l.k === '+').map((l) => defAt(l.t)?.name).filter(Boolean));
    const firstAdd = it.lines.find((l) => l.k === '+');
    const idx = Math.max(0, (firstAdd ? firstAdd.n : it.newStart) - 1);
    let enc = enclosing(lines, Math.min(idx, lines.length - 1), it.file);
    // una riga di route modificata E' un endpoint modificato
    const route = it.lines.map((l) => endpointInLine(l.t)).find(Boolean);
    if (route) { enc = { type: 'endpoint', ...route, line: idx + 1 }; }
    if (enc.type === 'fn' && !hasRemoved && addedDefs.has(enc.name)) { it.impact = { fn: enc.name, isNew: true, note: 'Funzione nuova: nessun chiamante esistente da impattare.' }; continue; }
    if (enc.type === 'module') { it.impact = { fn: null, note: 'Codice a livello di modulo: eseguito all\'import/avvio, impatta chiunque importi il file.' }; continue; }
    out.analyzed++;
    let tr;
    if (enc.type === 'endpoint') tr = { endpoints: [{ kind: enc.kind, label: enc.label, file: it.file, line: enc.line, chain: [enc.handler || '(handler)'] }], callers: 0, untouched: new Set(), tests: new Set(), generic: false, depthHit: false };
    else tr = await trace({ name: enc.name, file: it.file });
    const eps = []; const sk = new Set();
    for (const e of tr.endpoints) { const k = e.label + '|' + e.file + ':' + e.line; if (!sk.has(k)) { sk.add(k); eps.push(e); } }
    // test: nel percorso, oppure test che nominano la funzione
    const tests = [...tr.tests].slice(0, 8);
    // rischio
    const tagSev = Math.max(0, ...it.tags.map((t) => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 }[t.sev] || 0)));
    const reasons = [];
    if (eps.length) reasons.push(`raggiunge ${eps.length} endpoint (${eps.slice(0, 3).map((e) => e.label).join(', ')}${eps.length > 3 ? '…' : ''})`);
    if (tr.untouched.size) reasons.push(`${tr.untouched.size} punti di chiamata NON toccati da questo branch dipendono dal nuovo comportamento`);
    if (!tests.length) reasons.push('nessun test referenzia la funzione o i suoi chiamanti');
    if (tr.generic) reasons.push('nome generico: risalita parziale (possibili falsi positivi/negativi)');
    if (tr.depthHit) reasons.push('catena troncata al limite di profondità');
    let risk = 'low';
    if (eps.length && tagSev >= 4) risk = it.tags.some((t) => t.id === 'reg-auth') || eps.length >= 3 ? 'critical' : 'high';
    else if (eps.length && tagSev >= 3) risk = 'medium';
    else if (eps.length && !tests.length) risk = 'medium';
    else if (!eps.length && tagSev >= 4 && tr.callers) risk = 'medium';
    if (risk === 'high' && tests.length >= 2 && tagSev < 5 && tr.untouched.size === 0) risk = 'medium';
    it.impact = { fn: enc.type === 'fn' ? enc.name : enc.handler || null, risk, reasons, endpoints: eps.slice(0, 8), callers: tr.callers, untouched: [...tr.untouched].slice(0, 8), tests, unresolvedModules: tr.modules || 0, truncated: !!tr.depthHit };
    if (buildPacks && (enc.type === 'fn' || enc.type === 'endpoint')) {
      const key = it.file + '|' + (it.impact.fn || enc.label || '');
      let pk = packs.get(key);
      if (!pk) {
        const defIdx = enc.type === 'fn' ? enc.line - 1 : -1;
        const body = defIdx >= 0 ? bodyRange(lines, defIdx, 40) : [];
        const self = enc.type === 'fn' ? enc.name : '';
        const names = []; for (const m of body.slice(1).join('\n').matchAll(CALL_RE)) { const n = m[1]; if (n !== self && n.length >= 3 && !KEYWORDS.test(n) && !GENERIC.has(n) && !names.includes(n)) names.push(n); if (names.length >= 8) break; }
        const callees = [];
        for (const n of names) {
          if (callees.length >= 4) break;
          const hit = (await G.grepLines(repo, ref, n, 60)).find((h) => !isTest(h.file) && defAt(h.text)?.name === n);
          if (hit) callees.push({ name: n, sig: hit.text.trim().slice(0, 120), file: hit.file, line: hit.line });
        }
        const callersP = tr.direct.map((d) => ({ name: d.name, callText: d.text, file: d.file, line: d.defLine }));
        const allow = new Set([...callees.map((c) => c.name), ...callersP.filter((c) => c.line).map((c) => c.name)]);
        pk = { key, itemIds: [], file: it.file, fn: it.impact.fn || enc.label, sig: defIdx >= 0 ? lines[defIdx].trim().slice(0, 140) : '', body, diff: [], tags: [], callees, callers: callersP.map((c) => ({ name: c.name, callText: c.callText })), endpoints: eps.slice(0, 3), tests: tests.length, untouched: tr.untouched.size, risk, allow,
          bodyOf: async (name) => { const t = callees.find((c) => c.name === name) || callersP.find((c) => c.name === name && c.line); if (!t) return []; const ls = await read(ref, t.file); const di = t.line - 1; return di >= 0 && di < ls.length ? bodyRange(ls, di, 25) : []; } };
        packs.set(key, pk);
      }
      pk.itemIds.push(it.id);
      for (const l of it.lines) if (pk.diff.length < 14) pk.diff.push(`${l.k}${l.t.trim().slice(0, 130)}`);
      for (const t of it.tags) if (t.sev !== 'none' && !pk.tags.includes(t.label)) pk.tags.push(t.label);
    }
    for (const e of eps) {
      const k = e.label + '|' + e.file;
      const cur = out.endpoints.get(k) || { label: e.label, kind: e.kind, file: e.file, line: e.line, items: [], chains: [], risk: 'low' };
      const W = { low: 1, medium: 2, high: 3, critical: 4 };
      if (W[risk] > W[cur.risk]) cur.risk = risk;
      if (!cur.items.includes(it.id)) cur.items.push(it.id);
      if (cur.chains.length < 4 && !cur.chains.some((c) => c.join('>') === e.chain.join('>'))) cur.chains.push(e.chain);
      out.endpoints.set(k, cur);
    }
  }
  return { packs: [...packs.values()], endpoints: [...out.endpoints.values()].sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b.risk] - { critical: 4, high: 3, medium: 2, low: 1 }[a.risk])), analyzed: out.analyzed, skipped: out.skipped };
}
