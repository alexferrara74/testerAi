import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';
import { estimate, fit } from './tokens.js';

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
  } else {
    url = `${base}/chat/completions${ai.apiVersion ? `?api-version=${encodeURIComponent(ai.apiVersion)}` : ''}`;
    if (ai.apiKey) headers[ai.authHeader || 'Authorization'] = ai.authScheme ? `${ai.authScheme} ${ai.apiKey}` : ai.apiKey;
    body = { model: ai.model, max_tokens: maxOut, temperature: ai.temperature, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };
  }
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(ai.timeoutMs || 60000) });
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
const SYSTEM = 'Code reviewer. Items: id|file:line|code. Find real bugs/vulns/regressions. Reply ONLY JSON: {"bug":[[id,"motivo max 12 parole IT"]],"fp":[ids that are harmless],"ask":[["file",fromLine,toLine]]}. Use ask only if context is essential. No prose.';

function parseReply(text) {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return { bug: [], fp: [], ask: [] };
  try {
    const j = JSON.parse(m[0]);
    return { bug: Array.isArray(j.bug) ? j.bug : [], fp: Array.isArray(j.fp) ? j.fp : [], ask: Array.isArray(j.ask) ? j.ask : [] };
  } catch { return { bug: [], fp: [], ask: [] }; }
}

/** Impacchetta gli item (gia' ordinati per priorita') in prompt che stanno dentro il budget di input. */
export function pack(items, inputBudget) {
  const batches = []; let cur = []; let used = 0;
  for (const it of items) {
    const c = estimate(it.text) + 2;
    if (c > inputBudget) { it.text = fit(it.text, inputBudget - 2); }
    if (used + c > inputBudget && cur.length) { batches.push(cur); cur = []; used = 0; }
    cur.push(it); used += Math.min(c, inputBudget);
  }
  if (cur.length) batches.push(cur);
  return batches;
}

/**
 * items: [{id, text, priority}]; ctx.snippet(file,from,to) -> Promise<string[]>
 * Ritorna {bug:Map(id->motivo), fp:Set(id), usage, skipped, errors}
 */
export async function triage(cfg, items, docsText, ctx) {
  const { ai, budget } = cfg;
  const usage = { calls: 0, cached: 0, estIn: 0, estOut: 0, in: 0, out: 0 };
  const res = { bug: new Map(), fp: new Set(), usage, skipped: 0, errors: [] };
  const sysTokens = estimate(SYSTEM);
  const docs = docsText ? fit(`DOCS:\n${docsText}\n`, budget.docTokens) : '';
  const inputBudget = budget.maxContextTokens - budget.maxOutputTokens - sysTokens - estimate(docs) - 20; // margine
  if (inputBudget < 100) { res.errors.push('Budget troppo piccolo: aumenta maxContextTokens o riduci docTokens/maxOutputTokens'); res.skipped = items.length; return res; }

  const sorted = [...items].sort((a, b) => b.priority - a.priority);
  const batches = pack(sorted, inputBudget);

  const ask = async (user) => {
    const key = crypto.createHash('sha1').update(`${ai.provider}|${ai.model}|${user}`).digest('hex');
    const c = loadCache();
    if (budget.cache && c[key]) { usage.cached++; return c[key]; }
    if (usage.calls >= budget.maxCalls) return null;
    // Guardia finale: mai oltre il limite aziendale
    if (sysTokens + estimate(user) + budget.maxOutputTokens > budget.maxContextTokens) { user = fit(user, budget.maxContextTokens - budget.maxOutputTokens - sysTokens - 5); }
    usage.calls++; usage.estIn += sysTokens + estimate(user);
    const r = await callModel(ai, SYSTEM, user, budget.maxOutputTokens);
    usage.estOut += estimate(r.text); usage.in += r.tin || 0; usage.out += r.tout || 0;
    const parsed = parseReply(r.text);
    if (budget.cache) { c[key] = parsed; saveCache(); }
    return parsed;
  };

  const apply = (p) => {
    for (const b of p.bug) { if (Array.isArray(b)) res.bug.set(String(b[0]), String(b[1] || '')); else res.bug.set(String(b), ''); }
    for (const f of p.fp) res.fp.add(String(f));
  };

  let done = 0;
  for (const batch of batches) {
    if (usage.calls >= budget.maxCalls) break;
    try {
      const user = docs + batch.map((i) => i.text).join('\n');
      const p = await ask(user);
      if (!p) break;
      apply(p);
      done += batch.length;
      // Il modello chiede contesto: lo forniamo ritagliato, senza reinviare tutto il batch.
      let asks = p.ask;
      for (let round = 0; round < budget.maxRounds && asks.length && usage.calls < budget.maxCalls; round++) {
        const room = Math.floor((inputBudget - 40) / Math.min(asks.length, 2));
        const parts = [];
        for (const a of asks.slice(0, 2)) {
          const [file, from, to] = a; const f = Number(from) || 1, t = Math.min(Number(to) || f + 20, f + 40);
          const lines = await ctx.snippet(String(file), f, t);
          if (lines.length) parts.push(fit(`CTX ${file}\n${lines.join('\n')}`, room));
        }
        if (!parts.length) break;
        const ids = batch.filter((i) => !res.bug.has(i.id) && !res.fp.has(i.id)).map((i) => i.text);
        const follow = parts.join('\n') + '\nRe-evaluate:\n' + fit(ids.join('\n'), Math.max(40, inputBudget - estimate(parts.join('\n')) - 10));
        const p2 = await ask(follow);
        if (!p2) break;
        apply(p2); asks = p2.ask;
      }
    } catch (e) { res.errors.push(e.message); break; }
  }
  res.skipped = items.length - done;
  return res;
}
