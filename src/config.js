import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA = process.env.TESTERAI_DATA || path.join(ROOT, 'data');
const FILE = path.join(DATA, 'config.json');

export const DEFAULTS = {
  ai: {
    enabled: false,
    provider: 'openai',          // openai (compatibile: Copilot/Azure/gateway aziendale) | anthropic | ollama
    baseUrl: 'https://api.openai.com/v1',
    apiKey: '',
    model: '',
    authHeader: 'Authorization', // es. "api-key" per Azure
    authScheme: 'Bearer',        // vuoto = solo chiave
    extraHeaders: {},
    apiVersion: '',              // Azure: ?api-version=
    temperature: 0,
    timeoutMs: 60000,
  },
  budget: {
    maxContextTokens: 2000,      // limite aziendale per singola chiamata (input + output)
    maxOutputTokens: 300,
    maxCalls: 8,                 // chiamate AI max per analisi
    maxRounds: 1,                // domande di approfondimento del modello per batch
    docTokens: 250,              // quota di contesto riservata ai documenti in input
    cache: true,
  },
  analysis: {
    maxFilesDetail: 300,
    maxHunkLinesPerFile: 150,
    ignorePaths: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'dist/', 'build/', 'node_modules/', '.min.'],
  },
};

const merge = (a, b) => {
  const o = { ...a };
  for (const k of Object.keys(b || {})) o[k] = b[k] && typeof b[k] === 'object' && !Array.isArray(b[k]) && a[k] && typeof a[k] === 'object' ? merge(a[k], b[k]) : b[k];
  return o;
};

export function loadConfig() {
  let c = DEFAULTS;
  try { c = merge(DEFAULTS, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch { /* default */ }
  if (process.env.TESTERAI_API_KEY) c = merge(c, { ai: { apiKey: process.env.TESTERAI_API_KEY } });
  return c;
}

const num = (v, lo, hi, d) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d; };

export function saveConfig(patch) {
  const cur = loadConfig();
  if (patch.ai && patch.ai.apiKey === '********') delete patch.ai.apiKey; // il FE non ritrasmette il segreto
  const next = merge(cur, patch);
  next.ai.provider = ['openai', 'anthropic', 'ollama'].includes(next.ai.provider) ? next.ai.provider : 'openai';
  if (typeof next.ai.extraHeaders === 'string') { try { next.ai.extraHeaders = JSON.parse(next.ai.extraHeaders || '{}'); } catch { throw new Error('extraHeaders non e\' JSON valido'); } }
  next.budget.maxContextTokens = num(next.budget.maxContextTokens, 500, 200000, 2000);
  next.budget.maxOutputTokens = num(next.budget.maxOutputTokens, 50, next.budget.maxContextTokens / 2, 300);
  next.budget.maxCalls = num(next.budget.maxCalls, 1, 100, 8);
  next.budget.maxRounds = num(next.budget.maxRounds, 0, 3, 1);
  next.budget.docTokens = num(next.budget.docTokens, 0, next.budget.maxContextTokens / 2, 250);
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return next;
}

export function publicConfig(c = loadConfig()) {
  return { ...c, ai: { ...c.ai, apiKey: c.ai.apiKey ? '********' : '' } };
}
