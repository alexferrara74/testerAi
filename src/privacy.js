import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
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
  if (cfg.ai.enabled && cfg.ai.provider === 'copilot') out.push({ purpose: 'ai', host: 'api.githubcopilot.com / api.github.com (tramite Copilot SDK)', sends: (cfg.privacy.sendCode ? 'frammenti di codice minimi (segreti oscurati) + regole del documento' : 'solo metadati') + '. SDK senza strumenti: non legge file né esegue comandi. Le richieste del livello-modello sono filtrate e registrate; autenticazione e telemetria interna dell\'SDK non sono intercettabili dal tool' });
  else if (cfg.ai.enabled && cfg.ai.baseUrl) out.push({ purpose: 'ai', host: host(cfg.ai.baseUrl), sends: cfg.privacy.sendCode ? 'frammenti di codice minimi (segreti oscurati) + documenti scelti da te' : 'solo metadati (nome file, tipo di segnalazione): nessun codice' });
  if (cfg.analysis.cve.enabled) out.push({ purpose: 'cve', host: host(cfg.analysis.cve.osvUrl), sends: 'solo nome pacchetto + versione delle dipendenze modificate: nessun codice' });
  return { offline: false, destinations: out.filter((d) => d.host) };
}

export function logEgress(e) {
  try { fs.mkdirSync(DATA, { recursive: true, mode: 0o700 }); fs.appendFileSync(LOG(), JSON.stringify({ t: new Date().toISOString(), ...e }) + '\n', { mode: 0o600 }); } catch { /* best effort */ }
}
export function readEgressLog(n = 100) {
  try { return fs.readFileSync(LOG(), 'utf8').trim().split('\n').slice(-n).map((l) => JSON.parse(l)).reverse(); } catch { return []; }
}

export async function guardedFetch(url, opts, purpose) {
  const cfg = loadConfig(); const u = new URL(url);
  const deny = (why) => { logEgress({ purpose, host: u.hostname, blocked: why }); throw new Error(`Uscita di rete bloccata (${why}): ${u.hostname}`); };
  if (cfg.privacy.offline) deny('modalita offline attiva');
  const expected = purpose === 'ai' ? cfg.ai.baseUrl : purpose === 'cve' && cfg.analysis.cve.enabled ? cfg.analysis.cve.osvUrl : null;
  if (!expected) deny('scopo non autorizzato');
  if (new URL(expected).host !== u.host) deny('host diverso da quello configurato');
  if (u.protocol !== 'https:' && !isLocalHost(u.hostname) && !cfg.privacy.allowHttp) deny('connessione non cifrata (http) verso host non locale');
  const bytes = opts?.body ? Buffer.byteLength(opts.body) : 0;
  let status = 0;
  try { const res = await netRequest(u, opts || {}, cfg); status = res.status; return res; } // nessun redirect seguito: restiamo sull'host consentito
  catch (e) { logEgress({ purpose, host: u.hostname, path: u.pathname, bytes, status: 0, error: e.message }); throw e; }
  finally { if (status) logEgress({ purpose, host: u.hostname, path: u.pathname, bytes, status }); }
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

/* ====================================================================================
 * Trasporto di rete (senza dipendenze): supporta PROXY aziendale (CONNECT) e CA personalizzata.
 * fetch() di Node ignora HTTP(S)_PROXY e nasconde la causa ("fetch failed"): qui no.
 * ==================================================================================== */
export function proxyFor(u, cfg = loadConfig()) {
  if (/^(localhost|127\.|\[?::1\]?$)/.test(u.hostname)) return null; // solo loopback: mai via proxy
  const e = process.env;
  const raw = cfg.privacy.proxyUrl || (u.protocol === 'https:' ? e.HTTPS_PROXY || e.https_proxy : e.HTTP_PROXY || e.http_proxy) || e.ALL_PROXY || e.all_proxy;
  if (!raw) return null;
  const no = (e.NO_PROXY || e.no_proxy || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  if (no.some((n) => n === '*' || u.hostname.toLowerCase() === n.replace(/^\./, '') || u.hostname.toLowerCase().endsWith('.' + n.replace(/^\./, '')))) return null;
  try { return new URL(/^\w+:\/\//.test(raw) ? raw : 'http://' + raw); } catch { return null; }
}
export function describeNetError(e, host) {
  const c = e.cause || e; const code = c.code || e.code || '';
  const hints = {
    ENOTFOUND: 'DNS non risolve il nome: rete aziendale senza accesso diretto a internet? Imposta il proxy.',
    ECONNREFUSED: 'Connessione rifiutata: se la rete richiede un proxy, impostalo.',
    ETIMEDOUT: 'Timeout: firewall/proxy che blocca l\'uscita. Imposta il proxy aziendale o chiedi di abilitare l\'host.',
    ECONNRESET: 'Connessione chiusa dal peer: spesso un proxy/firewall che ispeziona il traffico.',
    EHOSTUNREACH: 'Host non raggiungibile: serve un proxy o una VPN.',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'Certificato non verificabile: la rete aziendale ispeziona TLS. Indica il certificato CA aziendale (campo «File CA» o NODE_EXTRA_CA_CERTS). Non disattivare la verifica.',
    SELF_SIGNED_CERT_IN_CHAIN: 'Certificato CA aziendale non fidato: indica il file CA aziendale (campo «File CA» o NODE_EXTRA_CA_CERTS).',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'Certificato autofirmato: indica il file CA aziendale.',
    CERT_HAS_EXPIRED: 'Certificato scaduto: controlla data/ora del PC.',
    ERR_TLS_CERT_ALTNAME_INVALID: 'Il certificato non corrisponde all\'host: controlla l\'URL.',
  };
  return { code, detail: c.message || String(e), hint: hints[code] || '' };
}
const netErr = (e, u) => { const d = describeNetError(e, u.hostname); const err = new Error(`Connessione a ${u.hostname} non riuscita: ${d.code || d.detail}${d.hint ? ' — ' + d.hint : ''}`); err.code = d.code; err.hint = d.hint; return err; };

function caFor(cfg) { if (!cfg.privacy.caFile) return undefined; try { return [...tls.rootCertificates, fs.readFileSync(cfg.privacy.caFile, 'utf8')]; } catch (e) { throw new Error(`File CA non leggibile (${cfg.privacy.caFile}): ${e.message}`); } }

function netRequest(u, opts, cfg) {
  return new Promise((resolve, reject) => {
    const px = proxyFor(u, cfg); const method = opts.method || 'GET'; const headers = { ...(opts.headers || {}) };
    if (opts.body) headers['content-length'] = Buffer.byteLength(opts.body);
    const isHttps = u.protocol === 'https:', ca = caFor(cfg);
    const abort = (req) => { if (opts.signal) { const on = () => { const er = new Error('Timeout o richiesta annullata'); er.code = 'ETIMEDOUT'; req.destroy(er); }; opts.signal.aborted ? on() : opts.signal.addEventListener('abort', on, { once: true }); } };
    const done = (req) => { abort(req); req.on('response', (res) => { const chunks = []; res.on('data', (c) => chunks.push(c)); res.on('end', () => { const h = new Headers(); for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) h.set(k, Array.isArray(v) ? v.join(', ') : v); const st = res.statusCode; resolve(new Response([204, 205, 304].includes(st) ? null : Buffer.concat(chunks), { status: st, headers: h })); }); res.on('error', (e) => reject(netErr(e, u))); }); req.on('error', (e) => reject(netErr(e, u))); if (opts.body) req.write(opts.body); req.end(); };
    const auth = px && px.username ? 'Basic ' + Buffer.from(`${decodeURIComponent(px.username)}:${decodeURIComponent(px.password)}`).toString('base64') : null;
    const path = u.pathname + u.search;
    if (!px) { const m = isHttps ? https : http; return done(m.request({ protocol: u.protocol, hostname: u.hostname, port: u.port || (isHttps ? 443 : 80), path, method, headers, ca })); }
    if (!isHttps) { // http via proxy: richiesta con URL assoluto
      if (auth) headers['proxy-authorization'] = auth; headers.host = u.host;
      return done(http.request({ hostname: px.hostname, port: px.port || 80, path: u.href, method, headers }));
    }
    // https via proxy: tunnel CONNECT, poi TLS verso l'host reale (la verifica certificati resta attiva)
    const c = http.request({ hostname: px.hostname, port: px.port || 80, method: 'CONNECT', path: `${u.hostname}:${u.port || 443}`, headers: { host: `${u.hostname}:${u.port || 443}`, ...(auth ? { 'proxy-authorization': auth } : {}) } });
    c.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); const er = new Error(`Il proxy ha rifiutato il tunnel verso ${u.hostname} (HTTP ${res.statusCode})${res.statusCode === 407 ? ': credenziali proxy mancanti (usa http://utente:password@proxy:porta)' : ''}`); return reject(er); }
      const t = tls.connect({ socket, servername: u.hostname, ca });
      done(https.request({ hostname: u.hostname, path, method, headers, createConnection: () => t, agent: false }));
    });
    c.on('error', (e) => reject(Object.assign(new Error(`Proxy ${px.host} non raggiungibile: ${e.code || e.message}`), { code: e.code })));
    abort(c); c.end();
  });
}
