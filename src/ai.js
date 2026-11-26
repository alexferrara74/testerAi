import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';
import { estimate, fit } from './tokens.js';
import { remaining, record, readUsage } from './usage.js';
import os from 'node:os';
import { guardedFetch, redact } from './privacy.js';
import { loadConfig } from './config.js';

/* ---------------- GitHub Copilot: scambio token ---------------- */
// Il token GitHub (OAuth del tuo login Copilot) si scambia con un token Copilot di breve durata.
// NB: l'endpoint di scambio e' quello usato dai plugin ufficiali ma non e' documentato come API pubblica.
export function readLocalCopilotToken() {
  const dirs = [path.join(os.homedir(), '.config', 'github-copilot'), process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'github-copilot')].filter(Boolean);
  for (const d of dirs) for (const f of ['apps.json', 'hosts.json']) {
    try { const j = JSON.parse(fs.readFileSync(path.join(d, f), 'utf8')); for (const v of Object.values(j)) if (v?.oauth_token) return v.oauth_token; } catch { /* prossimo */ }
  }
  return '';
}
const ctok = new Map();
async function copilotToken(ai) {
  const oauth = ai.apiKey || (ai.copilotAutoToken ? readLocalCopilotToken() : '');
  if (!oauth) throw new Error('Copilot: manca il token GitHub (incollalo nel campo API key oppure abilita la lettura del login Copilot locale)');
  const hit = ctok.get(oauth); if (hit && hit.exp - 60e3 > Date.now()) return hit.token;
  const res = await guardedFetch(ai.copilotTokenUrl, { method: 'GET', headers: { authorization: `token ${oauth}`, accept: 'application/json', 'user-agent': 'GitHubCopilotChat/0.22.0', 'editor-version': 'vscode/1.95.0' }, signal: AbortSignal.timeout(ai.timeoutMs || 60000) }, 'ai-token');
  const raw = await res.text();
  if (!res.ok) throw new Error(`Copilot token ${res.status}: verifica che l'account abbia una licenza Copilot attiva (${raw.slice(0, 120)})`);
  const j = JSON.parse(raw); if (!j.token) throw new Error('Copilot: risposta senza token');
  ctok.set(oauth, { token: j.token, exp: (j.expires_at || 0) * 1000 || Date.now() + 20 * 60e3 });
  return j.token;
}

/* ---------------- Provider layer ---------------- */
export async function callModel(ai, system, user, maxOut) {
  const headers = { 'content-type': 'application/json', ...(ai.extraHeaders || {}) };
  let url, body;
  const base = ai.baseUrl.replace(/\/+$/, '');
  if (ai.provider === 'anthropic') {
    url = `${base}/v1/messages`;
    headers['anthropic-version'] = '2023-06-01';
    if (ai.apiKey) headers['x-api-key'] = ai.apiKey;
    body = { model: ai.model, max_tokens: maxOut, temperature: ai.temperature, system, messages: [{ role: 'user', content: user }] };
  } else if (ai.provider === 'ollama') {
    url = `${base}/api/chat`;
    body = { model: ai.model, stream: false, options: { temperature: ai.temperature, num_predict: maxOut }, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };
  } else if (ai.provider === 'copilot') {
    url = `${base}/chat/completions`;
    Object.assign(headers, { authorization: `Bearer ${await copilotToken(ai)}`, 'editor-version': 'vscode/1.95.0', 'editor-plugin-version': 'copilot-chat/0.22.0', 'copilot-integration-id': 'vscode-chat', 'user-agent': 'GitHubCopilotChat/0.22.0' });
    body = { model: ai.model, max_tokens: maxOut, temperature: ai.temperature, stream: false, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };
  } else {
    url = `${base}/chat/completions${ai.apiVersion ? `?api-version=${encodeURIComponent(ai.apiVersion)}` : ''}`;
    if (ai.apiKey) headers[ai.authHeader || 'Authorization'] = ai.authScheme ? `${ai.authScheme} ${ai.apiKey}` : ai.apiKey;
    body = { model: ai.model, max_tokens: maxOut, temperature: ai.temperature, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };
  }
  const res = await guardedFetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(ai.timeoutMs || 60000) }, 'ai');
  const raw = await res.text();
  if (!res.ok) throw new Error(`AI ${res.status}: ${raw.slice(0, 200)}`);
  const j = JSON.parse(raw);
  if (ai.provider === 'anthropic') return { text: (j.content || []).map((c) => c.text || '').join(''), tin: j.usage?.input_tokens, tout: j.usage?.output_tokens };
  if (ai.provider === 'ollama') return { text: j.message?.content || '', tin: j.prompt_eval_count, tout: j.eval_count };
  return { text: j.choices?.[0]?.message?.content || '', tin: j.usage?.prompt_tokens, tout: j.usage?.completion_tokens };
}

/* ---------------- Cache (zero token sui ri-run) ---------------- */
const CACHE = path.join(DATA, 'cache', 'ai.json');
let cache = null;
const loadCache = () => { if (!cache) { try { cache = JSON.parse(fs.readFileSync(CACHE, 'utf8')); } catch { cache = {}; } } return cache; };
const saveCache = () => { try { fs.mkdirSync(path.dirname(CACHE), { recursive: true }); fs.writeFileSync(CACHE, JSON.stringify(cache)); } catch { /* best effort */ } };

/* ---------------- Triage con budget rigido ---------------- */
const SYSTEM = 'Review items id|loc|code. JSON only: {"b":[ids with real bug/vuln],"f":[ids harmless],"a":[[file,from,to]] only if context is essential}';

function parseReply(text) {
  const m = text.match(/\{[\s\S]*\}/);
  const e = { bug: [], fp: [], ask: [] };
  if (!m) return e;
  try {
    const j = JSON.parse(m[0]);
    const arr = (x) => (Array.isArray(x) ? x : []);
    return { bug: arr(j.b ?? j.bug), fp: arr(j.f ?? j.fp), ask: arr(j.a ?? j.ask) };
  } catch { return e; }
}

/* ---------- budget condiviso tra triage e revisione d'impatto ---------- */
export const newUsage = (cfg) => ({ calls: 0, cached: 0, estIn: 0, estOut: 0, in: 0, out: 0, spent: 0, monthlyLimit: cfg.budget.monthlyTokens, monthlyUsedBefore: readUsage().used });
export const leftTokens = (cfg, u) => Math.min(cfg.budget.perAnalysisTokens - u.spent, remaining(cfg.budget.monthlyTokens));

/** Crea la funzione di chiamata: redazione segreti, cache, tetti per analisi/mese, contabilita' reale. */
function makeAsk(cfg, usage, system, parse) {
  const { ai, budget } = cfg; const sysTokens = estimate(system);
  return async (user, note) => {
    if (cfg.privacy.redactSecrets) user = redact(user); // ultima barriera: nulla di sensibile esce
    const key = crypto.createHash('sha1').update(`${ai.provider}|${ai.model}|${system}|${user}`).digest('hex');
    const c = loadCache();
    if (budget.cache && c[key]) { usage.cached++; return c[key]; }
    if (usage.calls >= budget.maxCalls) return null;
    if (sysTokens + estimate(user) + budget.maxOutputTokens > leftTokens(cfg, usage)) return null; // mai superare la quota
    usage.calls++; usage.estIn += sysTokens + estimate(user);
    const r = await callModel(ai, system, user, budget.maxOutputTokens);
    const real = (r.tin || 0) + (r.tout || 0);
    const spent = real || (sysTokens + estimate(user) + estimate(r.text));
    usage.spent += spent; usage.estOut += estimate(r.text); usage.in += r.tin || 0; usage.out += r.tout || 0;
    record(spent, note);
    const parsed = parse(r.text);
    if (budget.cache) { c[key] = parsed; saveCache(); }
    return parsed;
  };
}

/**
 * Il vero limite e' MENSILE (budget.monthlyTokens, contatore persistente in usage.json) e per singola
 * analisi (perAnalysisTokens). Ogni chiamata viene dimensionata sul residuo; se non c'e' spazio non parte.
 * Le risposte in cache non consumano nulla.
 */
export async function triage(cfg, items, docsText, ctx, usage = newUsage(cfg)) {
  const { budget } = cfg;
  const res = { bug: new Map(), fp: new Set(), usage, skipped: items.length, errors: [] };
  const sysTokens = estimate(SYSTEM);
  const docs = docsText ? fit(`DOCS:\n${docsText}\n`, budget.docTokens) : '';
  const room = () => Math.min(budget.maxContextTokens, leftTokens(cfg, usage)) - budget.maxOutputTokens - sysTokens - estimate(docs) - 8;
  if (room() < 40) { res.errors.push(`Quota token esaurita o troppo bassa (residuo mese: ${remaining(budget.monthlyTokens)}, analisi: ${budget.perAnalysisTokens - usage.spent})`); return res; }
  const ask = makeAsk(cfg, usage, SYSTEM, parseReply);

  const queue = [...items].sort((a, b) => b.priority - a.priority);
  const sent = new Set();
  const apply = (p) => { for (const b of p.bug) res.bug.set(String(Array.isArray(b) ? b[0] : b), ''); for (const f of p.fp) res.fp.add(String(f)); };

  while (queue.length && usage.calls < budget.maxCalls && room() >= 40) {
    const r = room(); const batch = []; let used = 0;
    while (queue.length) {
      const it = queue[0]; const c = estimate(it.text) + 2;
      if (used + c > r) { if (!batch.length) { it.text = fit(it.text, r - 2); continue; } break; }
      batch.push(queue.shift()); used += c;
    }
    try {
      const p = await ask(docs + batch.map((i) => i.text).join('\n'), 'triage');
      if (!p) { queue.unshift(...batch); break; }
      apply(p); batch.forEach((i) => sent.add(i.id));
      let asks = p.ask;
      for (let round = 0; round < budget.maxRounds && asks.length && usage.calls < budget.maxCalls && room() >= 60; round++) {
        const [file, from, to] = asks[0];
        const f = Number(from) || 1, t = Math.min(Number(to) || f + 12, f + 20);
        const lines = cfg.privacy.sendCode ? await ctx.snippet(String(file), f, t) : [];
        if (!lines.length) break;
        const ctxTxt = fit(`CTX ${file}\n${lines.join('\n')}`, Math.floor(room() * 0.6));
        const pending = batch.filter((i) => !res.bug.has(i.id) && !res.fp.has(i.id)).map((i) => i.text).join('\n');
        const p2 = await ask(ctxTxt + '\n' + fit(pending, room() - estimate(ctxTxt) - 4), 'ask');
        if (!p2) break;
        apply(p2); asks = p2.ask;
      }
    } catch (e) { res.errors.push(e.message); break; }
  }
  res.skipped = items.length - sent.size;
  return res;
}

/* ============================================================================
 * REVISIONE D'IMPATTO con CONTESTO CHIUSO.
 * L'AI non ha strumenti e non vede il repository: riceve SOLO un "pacchetto" costruito da noi con
 * la funzione modificata (diff), i metodi che chiama, i chiamanti diretti e la catena fino all'endpoint.
 * Puo' chiedere (ask) solo simboli contenuti nel pacchetto; qualsiasi altra richiesta viene ignorata.
 * ============================================================================ */
const SYSTEM_I = 'Impact review. Judge ONLY with the given context (changed fn, callees, callers, path to endpoint). JSON only: {"v":"ok|risk|unsure","why":"max 20 words IT","ask":["one symbol from context if essential"]}';
function parseImpact(text) {
  const m = text.match(/\{[\s\S]*\}/); const e = { v: 'unsure', why: '', ask: [] };
  if (!m) return e;
  try { const j = JSON.parse(m[0]); return { v: ['ok', 'risk', 'unsure'].includes(j.v) ? j.v : 'unsure', why: String(j.why || '').slice(0, 200), ask: Array.isArray(j.ask) ? j.ask.map(String).slice(0, 2) : [] }; } catch { return e; }
}

/** Compone il pacchetto a sezioni in ordine di priorita' finche' c'e' budget. metaOnly = nessuna riga di codice. */
export function renderPack(pack, tokens, metaOnly) {
  const sec = [];
  sec.push(`FN ${pack.sig || pack.fn} @${pack.file.split('/').pop()}`);
  sec.push(`TAGS ${pack.tags.join(', ')}`);
  if (pack.endpoints.length) sec.push('PATH ' + pack.endpoints.slice(0, 3).map((e) => `${e.chain.join('>')} => ${e.label}`).join(' | '));
  if (!metaOnly && pack.diff.length) sec.push('CHG\n' + pack.diff.join('\n'));
  if (pack.callers.length) sec.push('CALLERS\n' + pack.callers.map((c) => metaOnly ? c.name : `${c.name}: ${c.callText}`).join('\n'));
  if (pack.callees.length) sec.push('CALLEES\n' + pack.callees.map((c) => metaOnly ? c.name : c.sig).join('\n'));
  sec.push(`TESTS ${pack.tests} | UNTOUCHED-CALLERS ${pack.untouched}`);
  if (!metaOnly && pack.body.length) sec.push('BODY\n' + pack.body.join('\n'));
  let out = '', used = 0;
  for (const part of sec) { const c = estimate(part) + 1; if (used + c > tokens) { if (!out) out = fit(part, tokens); break; } out += (out ? '\n' : '') + part; used += c; }
  return out;
}

export async function impactReview(cfg, packs, usage = newUsage(cfg)) {
  const { budget } = cfg; const out = new Map(); const errors = []; let skipped = 0;
  const sysTokens = estimate(SYSTEM_I); const metaOnly = !cfg.privacy.sendCode;
  const room = () => Math.min(budget.maxContextTokens, leftTokens(cfg, usage)) - budget.maxOutputTokens - sysTokens - 8;
  const ask = makeAsk(cfg, usage, SYSTEM_I, parseImpact);
  for (const pack of packs) {
    if (usage.calls >= budget.maxCalls || room() < 80) { skipped++; continue; }
    try {
      let p = await ask(renderPack(pack, room(), metaOnly), 'impact');
      if (!p) { skipped++; continue; }
      for (let round = 0; round < budget.maxRounds && p.ask.length && !metaOnly && usage.calls < budget.maxCalls && room() >= 80; round++) {
        const sym = p.ask[0];
        if (!pack.allow.has(sym)) break;                       // fuori dal perimetro: ignorata
        const body = await pack.bodyOf(sym); if (!body.length) break;
        const extra = fit(`CTX ${sym}\n${body.join('\n')}`, Math.floor(room() * 0.65));
        const head = renderPack({ ...pack, callers: [], callees: [], body: [], diff: pack.diff.slice(0, 6) }, Math.max(40, room() - estimate(extra) - 4), false);
        const p2 = await ask(extra + '\n' + head, 'impact-ask'); if (!p2) break; p = p2;
      }
      out.set(pack.key, p);
    } catch (e) { errors.push(e.message); break; }
  }
  return { verdicts: out, errors, skipped, usage };
}
