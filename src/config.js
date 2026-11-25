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
    monthlyTokens: 2000,         // TETTO MENSILE aziendale totale (input+output, tutte le analisi)
    perAnalysisTokens: 400,      // quota massima spendibile da una singola analisi
    maxContextTokens: 600,       // dimensione massima di una singola chiamata
    maxOutputTokens: 40,         // risposta minima: solo id
    maxCalls: 3,                 // chiamate AI max per analisi
    maxRounds: 1,                // domande di approfondimento del modello per batch
    docTokens: 60,               // quota di contesto riservata ai documenti in input
    cache: true,
  },
  analysis: {
    maxFilesDetail: 300,
    maxCommits: 100,
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
  next.analysis.maxCommits = num(next.analysis.maxCommits, 1, 1000, 100);
  const b = next.budget;
  b.monthlyTokens = num(b.monthlyTokens, 100, 1e9, 2000);
  b.perAnalysisTokens = num(b.perAnalysisTokens, 50, b.monthlyTokens, 400);
  b.maxContextTokens = num(b.maxContextTokens, 150, b.perAnalysisTokens, 600);
  b.maxOutputTokens = num(b.maxOutputTokens, 10, Math.floor(b.maxContextTokens / 2), 40);
  b.maxCalls = num(b.maxCalls, 1, 50, 3);
  b.maxRounds = num(b.maxRounds, 0, 3, 1);
  b.docTokens = num(b.docTokens, 0, Math.floor(b.maxContextTokens / 3), 60);
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return next;
}

export function publicConfig(c = loadConfig()) {
  return { ...c, ai: { ...c.ai, apiKey: c.ai.apiKey ? '********' : '' } };
}
