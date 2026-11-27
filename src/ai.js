import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';
import { estimate, fit } from './tokens.js';
import { remaining, record, readUsage } from './usage.js';
import { guardedFetch, redact } from './privacy.js';
import { loadConfig } from './config.js';
import { pickRules, briefText } from './docs.js';
import { copilotChat, copilotModels, sdkStatus, checkToken } from './copilot.js';

/* ---------------- Provider layer ---------------- */
export async function callModel(ai, system, user, maxOut) {
  if (ai.provider === 'copilot') return copilotChat(loadConfig(), system, user); // SDK ufficiale: contesto chiuso, nessuno strumento
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

/** Diagnostica passo-passo del collegamento AI (cosi' si vede DOVE si rompe: token, rete, proxy, certificato, licenza). */
export async function diagnose(cfg) {
  const ai = cfg.ai, steps = [];
  const host = (u) => { try { return new URL(u).host; } catch { return u; } };
  const step = async (name, fn) => { try { steps.push({ name, ok: true, detail: (await fn()) || '' }); return true; } catch (e) { steps.push({ name, ok: false, detail: e.message, hint: e.hint || '' }); return false; } };
  if (ai.provider === 'copilot') {
    if (!(await step('SDK Copilot installato', async () => { const st = await sdkStatus(); if (!st.installed) throw Object.assign(new Error('non installato: npm install @microsoft/copilot-sdk'), { hint: 'Poi riavvia il servizio. Serve Node ≥ 20.19 / 22.12.' }); return `@microsoft/copilot-sdk ${st.version}`; }))) return steps;
    if (!(await step('Token GitHub', async () => { checkToken(ai.apiKey); return `${ai.apiKey.slice(0, 4)}… inserito dal FE (nessun login locale usato)`; }))) return steps;
    if (!(await step('Autenticazione e modelli (account con licenza Copilot)', async () => { const m = await copilotModels(loadConfig()); return `${m.length} modelli disponibili`; }))) return steps;
  }
  await step(`Chiamata al modello (${host(ai.baseUrl)})`, async () => { const r = await callModel(ai, 'Reply {}', 'x', 5); record((r.tin || 0) + (r.tout || 0) || 15, 'test'); return `risposta ricevuta (${(r.tin || 0) + (r.tout || 0) || '~15'} token)`; });
  return steps;
}

/** Elenco dei modelli disponibili per il provider configurato (0 token: e' una GET sull'host gia' consentito). */
export async function listModels(ai) {
  if (ai.provider === 'copilot') return copilotModels(loadConfig());
  const base = ai.baseUrl.replace(/\/+$/, ''); const u = new URL(base);
  const headers = { accept: 'application/json', ...(ai.extraHeaders || {}) };
  let url, parse;
  const arr = (j) => (Array.isArray(j) ? j : j.data || j.models || []);
  if (ai.provider === 'anthropic') {
    url = `${base}/v1/models?limit=100`; headers['anthropic-version'] = '2023-06-01'; if (ai.apiKey) headers['x-api-key'] = ai.apiKey;
    parse = (j) => arr(j).map((m) => ({ id: m.id, name: m.display_name || m.id }));
  } else if (ai.provider === 'ollama') {
    url = `${base}/api/tags`; parse = (j) => arr(j).map((m) => ({ id: m.name, name: m.name }));
  } else {
    if (ai.apiKey) headers[ai.authHeader || 'Authorization'] = ai.authScheme ? `${ai.authScheme} ${ai.apiKey}` : ai.apiKey;
    if (u.hostname === 'models.github.ai') { url = `${u.origin}/catalog/models`; parse = (j) => arr(j).map((m) => ({ id: m.id, name: m.name || m.id })); }
    else if (/openai\.azure\.com$/.test(u.hostname)) { url = `${u.origin}/openai/deployments?api-version=${encodeURIComponent(ai.apiVersion || '2023-03-15-preview')}`; parse = (j) => arr(j).map((d) => ({ id: d.id, name: d.model ? `${d.id} (${d.model})` : d.id })); }
    else { url = `${base}/models${ai.apiVersion ? `?api-version=${encodeURIComponent(ai.apiVersion)}` : ''}`; parse = (j) => arr(j).filter((m) => !/embed|whisper|tts|dall-e|moderation|davinci-002|babbage|realtime|audio|image/i.test(m.id || '')).map((m) => ({ id: m.id, name: m.name || m.id })); }
  }
  const res = await guardedFetch(url, { method: 'GET', headers, signal: AbortSignal.timeout(ai.timeoutMs || 60000) }, 'ai');
  const raw = await res.text();
  if (!res.ok) { const e = new Error(`Elenco modelli ${res.status}: ${raw.slice(0, 160)}`); e.hint = res.status === 401 || res.status === 403 ? 'Credenziali non valide o senza permesso di elencare i modelli.' : 'Questo provider potrebbe non esporre l\'elenco: indica il modello a mano.'; throw e; }
  let list; try { list = parse(JSON.parse(raw)); } catch { throw Object.assign(new Error('Risposta non riconosciuta dall\'endpoint dei modelli'), { hint: 'Indica il modello a mano.' }); }
  const seen = new Set();
  return list.filter((m) => m.id && !seen.has(m.id) && seen.add(m.id)).sort((a, b) => a.id.localeCompare(b.id));
}

/* ============================================================================
 * REVISIONE GUIDATA DAL DOCUMENTO: UNA chiamata compatta (poche centinaia di token).
 * BRIEF (testo del box) + RULES (solo le regole del documento pertinenti) + CHANGES (una riga per modifica rischiosa,
 * con percorso fino all'endpoint). L'AI elenca solo cio' che NON e' ok. Un solo follow-up opzionale su UNA modifica
 * gia' inviata (contesto chiuso: pacchetto della funzione). Nulla fuori da questo perimetro.
 * ============================================================================ */
const SYSTEM_G = 'Review code CHANGES against BRIEF and RULES (ids Rn). JSON only, list ONLY non-ok changes: {"r":[[id,"risk|viol|unsure","max 12 words IT, cite Rn"]],"ask":[one id whose code you need]}. Unlisted = ok.';
function parseGuided(text) {
  const m = text.match(/\{[\s\S]*\}/); const e = { r: [], ask: [] }; if (!m) return e;
  try {
    const j = JSON.parse(m[0]); const arr = (x) => (Array.isArray(x) ? x : []);
    return { r: arr(j.r ?? j.results).map((x) => (Array.isArray(x) ? { id: String(x[0]), v: String(x[1] || 'unsure'), why: String(x[2] || '').slice(0, 200) } : { id: String(x.id), v: String(x.v || 'unsure'), why: String(x.why || '').slice(0, 200) })).filter((x) => ['risk', 'viol', 'unsure'].includes(x.v)), ask: arr(j.ask ?? j.a).map(String).slice(0, 1) };
  } catch { return e; }
}
export const changeLine = (c, withRules = true) => `${c.id}|${c.where}|${c.tags.join(',')}|${c.route || '-'}${withRules && c.rules?.length ? '|' + c.rules.join(',') : ''}`;

/** rules: tutte le regole del documento; brief: testo del box; changes ordinate per priorita'. */
export async function guidedReview(cfg, { rules, brief }, changes, usage, ctx) {
  const { budget } = cfg; const res = { results: new Map(), sent: new Set(), skipped: changes.length, rulesUsed: [], errors: [], rounds: 0 };
  const sysTokens = estimate(SYSTEM_G); const metaOnly = !cfg.privacy.sendCode; const docsOk = cfg.privacy.sendDocs !== false;
  const room = () => Math.min(budget.maxContextTokens, leftTokens(cfg, usage)) - budget.maxOutputTokens - sysTokens - 8;
  if (room() < 90) { res.errors.push(`Quota token troppo bassa per l'analisi guidata (residuo mese: ${remaining(budget.monthlyTokens)}, analisi: ${budget.perAnalysisTokens - usage.spent})`); return res; }
  const ask = makeAsk(cfg, usage, SYSTEM_G, parseGuided);
  const r0 = room();
  const brf = docsOk ? briefText(brief, Math.min(budget.docTokens, Math.floor(r0 * 0.25))) : '';
  const picked = docsOk ? pickRules(rules, changes, Math.min(budget.docTokens, Math.floor(r0 * 0.4))) : (changes.forEach((c) => { c.rules = []; }), []);
  const head = (brf ? `BRIEF ${brf}\n` : '') + (picked.length ? 'RULES\n' + picked.map((r) => `${r.id} ${r.text}`).join('\n') + '\n' : '');
  const lines = []; let used = estimate(head) + 3;
  for (const c of changes) { const l = changeLine(c); const t = estimate(l) + 1; if (used + t > r0) continue; lines.push(l); res.sent.add(c.id); used += t; }
  res.skipped = changes.length - res.sent.size; res.rulesUsed = picked.filter((r) => changes.some((c) => res.sent.has(c.id) && c.rules.includes(r.id)));
  if (!lines.length) { res.errors.push('Nessuna modifica entra nel budget'); return res; }
  try {
    let p = await ask(head + 'CHANGES\n' + lines.join('\n'), 'guided');
    if (!p) { res.errors.push('Quota o limite chiamate raggiunto prima della chiamata'); res.sent.clear(); res.skipped = changes.length; return res; }
    for (const x of p.r) if (res.sent.has(x.id)) res.results.set(x.id, x);
    for (let round = 0; round < budget.maxRounds && p.ask.length && !metaOnly && usage.calls < budget.maxCalls; round++) {
      const id = p.ask[0]; const c = changes.find((x) => x.id === id); if (!c || !res.sent.has(id) || !c.pack || room() < 120) break; // fuori perimetro: ignorata
      const rl = picked.filter((r) => c.rules.includes(r.id)).map((r) => `${r.id} ${r.text}`).join('\n');
      const text = (rl ? 'RULES\n' + rl + '\n' : '') + 'CTX\n' + (await ctx.render(c.pack, Math.max(60, room() - estimate(rl) - estimate(changeLine(c)) - 12))) + '\nCHANGES\n' + changeLine(c);
      const p2 = await ask(text, 'guided-ask'); res.rounds++; if (!p2) break;
      res.results.delete(id); const x = p2.r.find((y) => y.id === id); if (x) res.results.set(id, x); else res.results.set(id, { id, v: 'ok', why: '' }); p = p2;
    }
  } catch (e) { res.errors.push(e.message); }
  return res;
}
