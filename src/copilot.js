import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
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
let loader = async () => { const req = createRequire(import.meta.url); return import(req.resolve('@microsoft/copilot-sdk')); };
let sdkMod = null;
export const setSdkLoader = (fn) => { loader = fn; sdkMod = null; client = null; clientKey = ''; }; // solo per test
async function sdk() {
  if (sdkMod) return sdkMod;
  try { sdkMod = await loader(); return sdkMod; } catch (e) {
    const err = new Error('SDK Copilot non installato. Esegui nella cartella del progetto: npm install @microsoft/copilot-sdk (poi riavvia).');
    err.hint = 'Serve Node ≥ 20.19 o ≥ 22.12. L\'SDK è ufficiale Microsoft/GitHub e viene installato solo se lo richiedi.'; err.cause = e; throw err;
  }
}
export async function sdkStatus() {
  try { await sdk(); let version = ''; try { let d = path.dirname(createRequire(import.meta.url).resolve('@microsoft/copilot-sdk')); for (let i = 0; i < 6 && !version; i++, d = path.dirname(d)) { const f = path.join(d, 'package.json'); if (fs.existsSync(f)) { const j = JSON.parse(fs.readFileSync(f, 'utf8')); if (j.name === '@microsoft/copilot-sdk') version = j.version; } } } catch { /* sconosciuta */ } return { installed: true, version }; }
  catch { return { installed: false, version: '' }; }
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
