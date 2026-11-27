import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';
import { proxyFor, logEgress } from './privacy.js';

/* ====================================================================================
 * GitHub Copilot tramite l'SDK ufficiale (@microsoft/copilot-sdk). Copilot non ha API key:
 * si usa un TOKEN GITHUB (gho_/ghu_/github_pat_) inserito dal FE. Nessun login/variabile d'ambiente locale
 * viene letto: github.useLoggedInUser=false.
 *
 * CONTESTO CHIUSO: mode "empty" + tools.availableTools=[] + permessi sempre negati + system message sostituito.
 * L'agente NON ha strumenti: non puo' leggere file, eseguire comandi o vagare nel codice; vede solo il prompt.
 * ==================================================================================== */
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { ROOT } from './config.js';

// Come viene cercato l'SDK (in ordine): 1) import ESM standard dal progetto; 2) lettura diretta di
// <cartella>/node_modules/@microsoft/copilot-sdk/package.json risalendo dal progetto e dalla cartella corrente,
// e nelle installazioni globali di npm; l'entry si legge da package.json (exports.import) e si importa come file://.
// Ogni tentativo e' registrato e mostrato nel FE.
const PKG = '@microsoft/copilot-sdk';
function candidateDirs() {
  const dirs = []; const add = (d) => { if (d && !dirs.includes(d)) dirs.push(d); };
  for (const start of [ROOT, process.cwd()]) { let d = path.resolve(start); for (let i = 0; i < 8; i++) { add(path.join(d, 'node_modules')); const up = path.dirname(d); if (up === d) break; d = up; } }
  for (const g of [process.env.NODE_PATH, path.join(path.dirname(process.execPath), 'node_modules'), path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules'), process.env.APPDATA && path.join(process.env.APPDATA, 'npm', 'node_modules'), path.join(os.homedir(), '.npm-global', 'lib', 'node_modules')].filter(Boolean).flatMap((x) => String(x).split(path.delimiter))) add(g);
  return dirs;
}
export function entryOf(pkgDir) {
  const pj = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  const dot = pj.exports && (pj.exports['.'] ?? pj.exports);
  const pick = (x) => (typeof x === 'string' ? x : x?.default || x?.import?.default || (typeof x?.import === 'string' ? x.import : '') || '');
  const rel = pick(dot?.import) || pick(dot) || pj.module || pj.main || 'index.js';
  return { entry: path.resolve(pkgDir, rel), version: pj.version, name: pj.name };
}
export async function loadFromDirs(dirs, attempts = []) {
  for (const nm of dirs) {
    const pkgDir = path.join(nm, '@microsoft', 'copilot-sdk');
    if (!fs.existsSync(path.join(pkgDir, 'package.json'))) { attempts.push({ where: pkgDir, found: false }); continue; }
    let e; try { e = entryOf(pkgDir); } catch (er) { attempts.push({ where: pkgDir, found: true, error: `package.json non leggibile: ${er.message}` }); throw Object.assign(new Error(`package.json non leggibile in ${pkgDir}: ${er.message}`), { code: 'SDK_LOAD_FAILED' }); }
    attempts.push({ where: pkgDir, found: true, version: e.version, entry: e.entry });
    try { return await import(pathToFileURL(e.entry).href); } catch (er) { throw Object.assign(new Error(String(er?.message || er)), { code: 'SDK_LOAD_FAILED', cause: er, attempts }); }
  }
  return null;
}
let lastAttempts = [];
async function defaultLoader() {
  const attempts = []; lastAttempts = attempts;
  try { const m = await import(PKG); attempts.push({ where: 'import ESM standard dal progetto', found: true }); return m; } // 1) risoluzione standard di Node (condizione "import")
  catch (e) {
    const missing = e?.code === 'ERR_MODULE_NOT_FOUND' && new RegExp(`Cannot find package '${PKG.replace('/', '\\/')}'`).test(String(e.message));
    attempts.push({ where: 'import ESM standard dal progetto', found: false, error: String(e?.message || e).slice(0, 200) });
    if (!missing) throw Object.assign(new Error(String(e?.message || e)), { code: 'SDK_LOAD_FAILED', cause: e, attempts });
  }
  const m = await loadFromDirs(candidateDirs(), attempts); // 2) ricerca diretta
  if (m) return m;
  throw Object.assign(new Error('SDK non trovato'), { code: 'SDK_NOT_FOUND', attempts });
}
let loader = defaultLoader;
let sdkMod = null;
export const setSdkLoader = (fn) => { loader = fn || defaultLoader; sdkMod = null; client = null; clientKey = ''; }; // solo per test
const platformPkgs = () => { try { return fs.readdirSync(path.join(ROOT, 'node_modules', '@microsoft')).filter((n) => n.startsWith('copilot-sdk-')); } catch { return []; } };
async function sdk() {
  if (sdkMod) return sdkMod;
  try { sdkMod = await loader(); return sdkMod; } catch (e) {
    if (e.code === 'SDK_NOT_FOUND') {
      const err = new Error(`SDK Copilot non trovato. Esegui nella cartella del progetto (${ROOT}): npm install @microsoft/copilot-sdk — poi riavvia.`);
      err.hint = 'Il servizio lo cerca in node_modules del progetto (e delle cartelle superiori), della cartella da cui lo avvii e nelle installazioni globali di npm. Vedi i tentativi qui sotto.'; err.code = e.code; err.attempts = e.attempts || lastAttempts; throw err;
    }
    const nodeOk = (() => { const [M, m] = process.versions.node.split('.').map(Number); return (M === 20 && m >= 19) || (M === 22 && m >= 12) || M > 22; })();
    const err = new Error(`SDK Copilot installato ma non si carica: ${String(e.message).slice(0, 300)}`);
    err.hint = [!nodeOk ? `Node ${process.versions.node} non è supportato: serve ≥ 20.19 o ≥ 22.12.` : '', `Pacchetto nativo per ${process.platform}-${process.arch}: ${platformPkgs().length ? platformPkgs().join(', ') : 'NESSUNO installato (npm ha saltato le dipendenze opzionali: reinstalla senza --omit=optional / --no-optional)'}.`, 'Un antivirus può bloccare il runtime nativo.'].filter(Boolean).join(' ');
    err.code = e.code || 'SDK_LOAD_FAILED'; err.cause = e; err.attempts = e.attempts || lastAttempts; throw err;
  }
}
export async function sdkStatus() {
  const base = { node: process.versions.node, root: ROOT };
  try { await sdk(); const hit = lastAttempts.find((a) => a.version); let version = hit?.version || ''; if (!version) for (const nm of candidateDirs()) { try { const e = entryOf(path.join(nm, '@microsoft', 'copilot-sdk')); version = e.version; break; } catch { /* prossima */ } } return { ...base, installed: true, version }; }
  catch (e) { return { ...base, installed: false, version: '', code: e.code || '', error: e.message, hint: e.hint || '', attempts: (e.attempts || lastAttempts).slice(0, 14) }; }
}

const ALLOWED = /(^|\.)(githubcopilot\.com|github\.com|githubusercontent\.com)$/i;
export function checkToken(t) {
  if (!t) { const e = new Error('Manca il token GitHub: inseriscilo nel campo «Token GitHub» della Configurazione.'); e.hint = 'Copilot non usa API key: serve un token OAuth (gho_/ghu_) o un PAT fine-grained (github_pat_) di un account con licenza Copilot.'; throw e; }
  if (/^ghp_/.test(t)) { const e = new Error('I token classici (ghp_) non sono supportati dall\'SDK Copilot.'); e.hint = 'Usa un PAT fine-grained (github_pat_) o un token OAuth (gho_/ghu_).'; throw e; }
}

let client = null, clientKey = '';
async function getClient(cfg) {
  const ai = cfg.ai; checkToken(ai.apiKey);
  if (cfg.privacy.offline) throw new Error('Modalità offline attiva: Copilot non può essere contattato.');
  const key = `${ai.apiKey}|${cfg.privacy.proxyUrl}`;
  if (client && clientKey === key) return client;
  await stopCopilot();
  const m = await sdk(); const base = path.join(DATA, 'copilot'); fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  // Ogni richiesta del livello-modello passa da qui: host consentiti + registro (stesso criterio del guard di rete)
  const Handler = class extends m.CopilotRequestHandler {
    async sendRequest(request, ctx) {
      let host = ''; try { host = new URL(ctx.url).hostname; } catch { /* url non valido */ }
      if (!ALLOWED.test(host)) { logEgress({ purpose: 'ai', host, blocked: 'host non consentito (Copilot SDK)' }); throw new Error(`Uscita di rete bloccata (host non consentito): ${host}`); }
      let bytes = 0; try { bytes = Number(request.headers.get('content-length')) || 0; } catch { /* ignora */ }
      const res = await super.sendRequest(request, ctx); logEgress({ purpose: 'ai', host, path: new URL(ctx.url).pathname, bytes, status: res.status, via: 'copilot-sdk' }); return res;
    }
  };
  client = new m.CopilotClient({
    mode: 'empty',                                           // nessuna funzione ambientale (CLI, plugin, estensioni, memoria...)
    runtime: m.RuntimeConnection.forInProcess({ baseDirectory: base }), // stato dell'SDK in ~/.testerai/copilot, non nel progetto
    github: { token: ai.apiKey, useLoggedInUser: false },    // SOLO il token inserito dal FE; ignora login locale e variabili d'ambiente
    network: { resolveProxy: async (req) => { try { const p = proxyFor(new URL(req.url || req.href || `https://${req.host || 'api.githubcopilot.com'}`), cfg); return p ? p.href : undefined; } catch { return undefined; } } },
    models: { requestHandler: new Handler() },
  });
  clientKey = key;
  try { await client.start(); } catch (e) { client = null; clientKey = ''; throw e; }
  return client;
}
export async function stopCopilot() { const c = client; client = null; clientKey = ''; if (c) { try { await c.stop(); } catch { /* ignora */ } } }
process.once('exit', () => { client?.forceStop?.().catch?.(() => {}); });

const explain = (e) => {
  const msg = String(e?.message || e);
  if (/not authenticated|authenticate/i.test(msg)) { const x = new Error('Token GitHub non accettato da Copilot (non autenticato).'); x.hint = 'Controlla che il token sia valido, non scaduto e di un account con licenza Copilot attiva. I token ghp_ non sono supportati.'; return x; }
  return e;
};

/** Elenco modelli dell'account (0 token). */
export async function copilotModels(cfg) {
  const c = await getClient(cfg);
  try { const list = await c.listModels(); return list.map((m) => ({ id: m.id, name: m.name || m.id })).sort((a, b) => a.id.localeCompare(b.id)); } catch (e) { throw explain(e); }
}

/** Una chiamata a contesto chiuso: nessuno strumento, permessi negati, system message sostituito. */
export async function copilotChat(cfg, system, user) {
  const c = await getClient(cfg); const ai = cfg.ai;
  if (!ai.model) throw new Error('Scegli un modello (pulsante «Carica modelli»).');
  let session; const usage = { in: 0, out: 0 };
  try {
    session = await c.createSession({
      model: ai.model,
      systemMessage: { mode: 'replace', content: system },          // sostituisce TUTTO il prompt dell'agente (meno token, nessuna istruzione da agente)
      tools: { availableTools: [] },                                  // nessuno strumento: niente file, shell, rete, ricerca
      permissions: { onRequest: () => ({ kind: 'reject', feedback: 'Strumenti disabilitati: rispondi solo con il testo fornito.' }) },
      enableConfigDiscovery: false,
      instructions: { skipCustomInstructions: true },
      skills: { enabled: false },
      extensions: { enabled: false },
      git: { enableHostGitOperations: false },
      workingDirectory: path.join(DATA, 'copilot'),                   // cartella vuota e privata, mai il repository
    });
    session.on((ev) => { if (ev?.type === 'assistant.usage') { usage.in += ev.data?.inputTokens || 0; usage.out += ev.data?.outputTokens || 0; } });
    const r = await session.sendAndWait({ prompt: user }, ai.timeoutMs || 60000);
    return { text: r?.data?.content || '', tin: usage.in || undefined, tout: usage.out || undefined };
  } catch (e) { throw explain(e); }
  finally { try { await session?.disconnect(); } catch { /* ignora */ } }
}
