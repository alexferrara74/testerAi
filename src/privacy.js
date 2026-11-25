import fs from 'node:fs';
import path from 'node:path';
import { loadConfig, DATA } from './config.js';

/* ====================================================================================
 * PRIVACY: il codice non deve uscire dal PC.
 * Unico punto di uscita di rete dell'intera applicazione = guardedFetch().
 *  - 'ai'  -> SOLO l'host del provider AI configurato da te
 *  - 'cve' -> SOLO l'host OSV configurato, e solo se abiliti la verifica CVE (invia nomi+versioni, mai codice)
 *  - modalita' offline: blocca tutto
 *  - ogni richiesta e' registrata in egress.log (host, scopo, byte: MAI il contenuto)
 * ==================================================================================== */
const LOG = () => path.join(DATA, 'egress.log');
const isLocalHost = (h) => /^(localhost|127\.|::1$|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h.endsWith('.local');

export function allowedDestinations(cfg = loadConfig()) {
  const out = [];
  const host = (u) => { try { return new URL(u).hostname; } catch { return null; } };
  if (cfg.privacy.offline) return { offline: true, destinations: [] };
  if (cfg.ai.enabled && cfg.ai.provider === 'copilot') out.push({ purpose: 'ai-token', host: host(cfg.ai.copilotTokenUrl), sends: 'solo il tuo token GitHub, per ottenere il token Copilot (nessun codice)' });
  if (cfg.ai.enabled && cfg.ai.baseUrl) out.push({ purpose: 'ai', host: host(cfg.ai.baseUrl), sends: cfg.privacy.sendCode ? 'frammenti di codice minimi (segreti oscurati) + documenti scelti da te' : 'solo metadati (nome file, tipo di segnalazione): nessun codice' });
  if (cfg.analysis.cve.enabled) out.push({ purpose: 'cve', host: host(cfg.analysis.cve.osvUrl), sends: 'solo nome pacchetto + versione delle dipendenze modificate: nessun codice' });
  return { offline: false, destinations: out.filter((d) => d.host) };
}

function logEgress(e) {
  try { fs.mkdirSync(DATA, { recursive: true, mode: 0o700 }); fs.appendFileSync(LOG(), JSON.stringify({ t: new Date().toISOString(), ...e }) + '\n', { mode: 0o600 }); } catch { /* best effort */ }
}
export function readEgressLog(n = 100) {
  try { return fs.readFileSync(LOG(), 'utf8').trim().split('\n').slice(-n).map((l) => JSON.parse(l)).reverse(); } catch { return []; }
}

export async function guardedFetch(url, opts, purpose) {
  const cfg = loadConfig(); const u = new URL(url);
  const deny = (why) => { logEgress({ purpose, host: u.hostname, blocked: why }); throw new Error(`Uscita di rete bloccata (${why}): ${u.hostname}`); };
  if (cfg.privacy.offline) deny('modalita offline attiva');
  const expected = purpose === 'ai-token' && cfg.ai.provider === 'copilot' ? cfg.ai.copilotTokenUrl : purpose === 'ai' ? cfg.ai.baseUrl : purpose === 'cve' && cfg.analysis.cve.enabled ? cfg.analysis.cve.osvUrl : null;
  if (!expected) deny('scopo non autorizzato');
  if (new URL(expected).host !== u.host) deny('host diverso da quello configurato');
  if (u.protocol !== 'https:' && !isLocalHost(u.hostname) && !cfg.privacy.allowHttp) deny('connessione non cifrata (http) verso host non locale');
  const bytes = opts?.body ? Buffer.byteLength(opts.body) : 0;
  let status = 0;
  try { const res = await fetch(url, { ...opts, redirect: 'error' }); status = res.status; return res; } // niente redirect verso altri host
  finally { logEgress({ purpose, host: u.hostname, path: u.pathname, bytes, status }); }
}

/* ---- oscuramento segreti prima di QUALSIASI invio ad AI ---- */
const REDACTIONS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[REDACTED:KEY]'],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '[REDACTED:AWS]'],
  [/\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b/g, '[REDACTED:TOKEN]'],
  [/(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{12,}/gi, '$1[REDACTED]'],
  [/((?:password|passwd|pwd|secret|api[_-]?key|token|auth)\w*["']?\s*[:=]\s*["'])[^"'\s]{4,}(["'])/gi, '$1[REDACTED]$2'],
  [/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[REDACTED:BLOB]'],
  [/\b[0-9a-f]{32,}\b/gi, '[REDACTED:HEX]'],
  [/[\w.+-]+@[\w-]+\.[\w.-]+/g, '[EMAIL]'],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]'],
];
export function redact(text) { let t = text; for (const [re, rep] of REDACTIONS) t = t.replace(re, rep); return t; }
