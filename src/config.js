import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Dati (report, cache, chiavi) FUORI dal repository del progetto: non possono finire in un commit.
export const DATA = process.env.TESTERAI_DATA || path.join(os.homedir(), '.testerai');
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
    copilotTokenUrl: 'https://api.github.com/copilot_internal/v2/token', // solo provider copilot (GHE: tuo host)
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
  privacy: {
    offline: false,             // blocca QUALSIASI connessione in uscita (analisi solo statica)
    sendCode: true,             // false = all'AI vanno solo metadati, mai righe di codice
    redactSecrets: true,        // oscura chiavi/token/password/email/IP prima di ogni invio
    proxyUrl: '',               // proxy aziendale (es. http://utente:pwd@proxy:8080); vuoto = usa HTTPS_PROXY/HTTP_PROXY dell'ambiente
    caFile: '',                 // certificato CA aziendale (PEM) se la rete ispeziona TLS; la verifica NON viene mai disattivata
    allowHttp: false,           // consente http non cifrato verso host non locali
  },
  analysis: {
    maxFilesDetail: 300,
    includeWorktree: true,       // analizza anche le modifiche locali non committate (solo sul branch attivo)
    impact: { enabled: true, maxDepth: 6, maxNodes: 150, maxItems: 80 }, // risalita chiamanti -> endpoint (0 token)
    maxCommits: 100,
    maxReviewItems: 500,
    cve: { enabled: false, osvUrl: 'https://api.osv.dev', cacheHours: 24, timeoutMs: 10000 },
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
  next.ai.provider = ['openai', 'anthropic', 'ollama', 'copilot'].includes(next.ai.provider) ? next.ai.provider : 'openai';
  if (typeof next.ai.extraHeaders === 'string') { try { next.ai.extraHeaders = JSON.parse(next.ai.extraHeaders || '{}'); } catch { throw new Error('extraHeaders non e\' JSON valido'); } }
  next.privacy.proxyUrl = String(next.privacy.proxyUrl || '').trim(); next.privacy.caFile = String(next.privacy.caFile || '').trim();
  delete next.ai.copilotAutoToken; // rimosso: il token si inserisce solo a mano
  for (const k of ['offline', 'sendCode', 'redactSecrets', 'allowHttp']) next.privacy[k] = !!next.privacy[k];
  next.analysis.cve.cacheHours = num(next.analysis.cve.cacheHours, 0, 720, 24);
  next.analysis.cve.timeoutMs = num(next.analysis.cve.timeoutMs, 1000, 60000, 10000);
  next.analysis.includeWorktree = !!next.analysis.includeWorktree; next.analysis.impact.enabled = !!next.analysis.impact.enabled;
  next.analysis.impact.maxDepth = num(next.analysis.impact.maxDepth, 1, 12, 6); next.analysis.impact.maxNodes = num(next.analysis.impact.maxNodes, 10, 1000, 150); next.analysis.impact.maxItems = num(next.analysis.impact.maxItems, 5, 500, 80);
  next.analysis.maxReviewItems = num(next.analysis.maxReviewItems, 20, 5000, 500);
  next.analysis.maxCommits = num(next.analysis.maxCommits, 1, 1000, 100);
  const b = next.budget;
  b.monthlyTokens = num(b.monthlyTokens, 100, 1e9, 2000);
  b.perAnalysisTokens = num(b.perAnalysisTokens, 50, b.monthlyTokens, 400);
  b.maxContextTokens = num(b.maxContextTokens, 150, b.perAnalysisTokens, 600);
  b.maxOutputTokens = num(b.maxOutputTokens, 10, Math.floor(b.maxContextTokens / 2), 40);
  b.maxCalls = num(b.maxCalls, 1, 50, 3);
  b.maxRounds = num(b.maxRounds, 0, 3, 1);
  b.docTokens = num(b.docTokens, 0, Math.floor(b.maxContextTokens / 3), 60);
  fs.mkdirSync(DATA, { recursive: true, mode: 0o700 });
  fs.writeFileSync(FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return next;
}

export function publicConfig(c = loadConfig()) {
  return { ...c, ai: { ...c.ai, apiKey: c.ai.apiKey ? '********' : '' } };
}
