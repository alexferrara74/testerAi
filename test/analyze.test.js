import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { execFileSync } from 'node:child_process';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tai-'));
process.env.TESTERAI_DATA = path.join(tmp, 'data');
const { analyze, toMarkdown, setReviewState, getReport } = await import('../src/analyzer.js');
const { saveConfig } = await import('../src/config.js');
const { estimate } = await import('../src/tokens.js');

const repo = path.join(tmp, 'repo');
const g = (...a) => execFileSync('git', a, { cwd: repo, stdio: 'pipe' }).toString();
fs.mkdirSync(repo);
g('init', '-q', '-b', 'main'); g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
fs.writeFileSync(path.join(repo, 'util.js'), 'export function computeTotal(a, b) { return a + b; }\n');
fs.writeFileSync(path.join(repo, 'app.js'), 'import { computeTotal } from "./util.js";\nconsole.log(computeTotal(1,2));\n');
g('add', '.'); g('commit', '-qm', 'initial commit');
g('checkout', '-qb', 'feature/x');
fs.writeFileSync(path.join(repo, 'util.js'), 'export function computeTotal(a, b, c) { return a + b + c; }\nconst password = "SuperSecret123";\nconst r = eval(input);\n');
fs.writeFileSync(path.join(repo, 'db.js'), 'const q = "SELECT * FROM users WHERE id=" + id;\n');
g('add', '.'); g('commit', '-qm', 'wip');

test('analisi statica: modifiche, segreti, regressioni, checklist', async () => {
  const r = await analyze({ repo, branch: 'feature/x', useAI: false });
  assert.equal(r.base, 'main'); assert.ok(r.baseDetected);
  assert.deepEqual(r.files.map((f) => f.path).sort(), ['db.js', 'util.js']);
  const rules = r.findings.map((f) => f.rule);
  for (const x of ['SEC-SECRET-ASSIGN', 'SEC-EVAL', 'SEC-SQL-CONCAT', 'REG-SIGNATURE', 'REG-NO-TESTS', 'GIT-MSG']) assert.ok(rules.includes(x), x);
  assert.equal(r.checklist.find((c) => c.id === 'c2').status, 'fail');
  assert.match(toMarkdown(r), /Checklist/);
});

test('analisi per commit: attribuzione, segreto poi rimosso resta in cronologia', async () => {
  g('checkout', '-q', 'feature/x');
  fs.writeFileSync(path.join(repo, 'cfg.js'), 'const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";\n');
  g('add', '.'); g('commit', '-qm', 'add config with token');
  fs.writeFileSync(path.join(repo, 'cfg.js'), 'const token = process.env.TOKEN;\n');
  g('add', '.'); g('commit', '-qm', 'use env for token');
  const r = await analyze({ repo, branch: 'feature/x', useAI: false });
  const leak = r.commits.find((c) => c.subject === 'add config with token');
  assert.ok(leak.analysis.findings.some((f) => f.rule === 'SEC-SECRET-TOKEN' && f.fixedLater));
  assert.ok(r.findings.some((f) => f.rule === 'SEC-SECRET-HISTORY' && f.commit === leak.short));
  const sql = r.findings.find((f) => f.rule === 'SEC-SQL-CONCAT');
  assert.ok(sql.commit, 'problema attribuito al commit');
  assert.equal(r.checklist.find((c) => c.id === 'c12').status, 'fail');
  assert.equal(r.summary.commitsAnalyzed, r.summary.commits);
});

test('CVE: dipendenze cambiate verificate su OSV (mock), cache, errore di rete gestito', async () => {
  let hits = 0;
  const osv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => b += c); req.on('end', () => {
      hits++; res.setHeader('content-type', 'application/json');
      if (req.url === '/v1/querybatch') return res.end(JSON.stringify({ results: JSON.parse(b).queries.map((q) => (q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-xxxx' }] } : {})) }));
      res.end(JSON.stringify({ id: 'GHSA-xxxx', aliases: ['CVE-2021-23337'], summary: 'Command injection', database_specific: { severity: 'HIGH' }, affected: [{ package: { name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }));
    });
  }).listen(0);
  const url = `http://127.0.0.1:${osv.address().port}`;
  g('checkout', '-q', 'main'); g('checkout', '-qb', 'feature/deps');
  fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ dependencies: { lodash: '4.17.15', express: '^4.19.0' } }));
  g('add', '.'); g('commit', '-qm', 'add deps');
  saveConfig({ analysis: { cve: { enabled: true, osvUrl: url, cacheHours: 24 } } });
  const r = await analyze({ repo, branch: 'feature/deps', base: 'main', useAI: false });
  const cve = r.findings.find((f) => f.rule === 'DEP-CVE');
  assert.ok(cve && cve.severity === 'high' && /CVE-2021-23337/.test(cve.message) && /4\.17\.21/.test(cve.message));
  assert.equal(r.checklist.find((c) => c.id === 'c13').status, 'fail');
  const h = hits;
  await analyze({ repo, branch: 'feature/deps', base: 'main', useAI: false });
  assert.equal(hits, h, 'cache: nessuna nuova richiesta di rete');
  osv.close();
  saveConfig({ analysis: { cve: { osvUrl: 'http://127.0.0.1:1', cacheHours: 0 } } });
  const r2 = await analyze({ repo, branch: 'feature/deps', base: 'main', useAI: false });
  assert.equal(r2.checklist.find((c) => c.id === 'c13').status, 'warn');
  g('checkout', '-q', 'feature/x');
});

test('AI: quota mensile 2000 mai superata, cache e stop a quota esaurita', async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => b += c); req.on('end', () => {
      seen.push(JSON.parse(b)); res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ choices: [{ message: { content: '{"b":["F1"],"f":[],"a":[]}' } }], usage: { prompt_tokens: 150, completion_tokens: 10 } }));
    });
  }).listen(0);
  saveConfig({ ai: { enabled: true, baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, model: 'm', apiKey: 'k' }, budget: { strategy: 'detailed', perAnalysisTokens: 400, maxContextTokens: 600, maxOutputTokens: 40, maxCalls: 3, docTokens: 60 } });
  const { readUsage } = await import('../src/usage.js');
  const docs = [{ name: 'rules', text: 'Vietato usare eval in util.\n\nAltro testo irrilevante qui.' }];
  const r = await analyze({ repo, branch: 'feature/x', useAI: true, docs });
  assert.ok(r.ai.used && r.ai.calls >= 1, JSON.stringify(r.ai));
  assert.ok(r.ai.spent <= 400, 'tetto per analisi');
  assert.ok(readUsage().used <= 2000);
  for (const j of seen) assert.ok(j.max_tokens <= 40 && estimate(j.messages.map((m) => m.content).join('')) <= 600);
  const n = seen.length, used = readUsage().used;
  await analyze({ repo, branch: 'feature/x', useAI: true, docs });
  assert.equal(seen.length, n, 'cache: nessuna nuova chiamata'); assert.equal(readUsage().used, used);
  // quota mensile quasi esaurita -> nessuna chiamata
  fs.writeFileSync(path.join(process.env.TESTERAI_DATA, 'usage.json'), JSON.stringify({ month: new Date().toISOString().slice(0, 7), used: 1990, calls: 9, log: [] }));
  saveConfig({ budget: { cache: false } });
  const r3 = await analyze({ repo, branch: 'feature/x', useAI: true });
  assert.equal(seen.length, n); assert.ok(r3.ai.errors.length, 'segnala quota esaurita');
  srv.close();
});

test('revisione riga per riga: tag logica/regressione, decisioni persistenti, fix verificato', async () => {
  const r2 = path.join(tmp, 'repo2'); fs.mkdirSync(r2);
  const h = (...a) => execFileSync('git', a, { cwd: r2, stdio: 'pipe' }).toString();
  const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(r2, f)), { recursive: true }); fs.writeFileSync(path.join(r2, f), t); };
  h('init', '-q', '-b', 'main'); h('config', 'user.email', 't@t'); h('config', 'user.name', 't');
  w('src/pay.js', 'export function pay(user, amount) {\n  if (!user) throw new Error("no user");\n  if (amount < 100) return refund(amount);\n  return charge(amount);\n}\n');
  w('tests/pay.test.js', 'expect(pay(u, 5)).toBe(1);\nexpect(pay(u, 500)).toBe(2);\n');
  h('add', '.'); h('commit', '-qm', 'base'); h('checkout', '-qb', 'feat');
  w('src/pay.js', 'export function pay(user, amount) {\n  if (amount <= 100) return refund(amount);\n  return charge(amount);\n}\n');
  w('tests/pay.test.js', 'expect(pay(u, 5)).toBe(1);\n');
  h('add', '.'); h('commit', '-qm', 'simplify pay');
  fs.appendFileSync(path.join(r2, 'src/pay.js'), '// nota\n'); h('add', '.'); h('commit', '-qm', 'comment only');
  const rep = await analyze({ repo: r2, branch: 'feat', base: 'main', useAI: false });
  const tags = rep.review.items.flatMap((i) => i.tags.map((t) => t.id));
  for (const t of ['reg-guard', 'reg-op', 'reg-test']) assert.ok(tags.includes(t), 'manca ' + t + ' in ' + tags);
  assert.ok(rep.review.items.some((i) => i.level === 'trivial'), 'commit con solo commento = banale');
  assert.ok(rep.findings.some((f) => f.rule === 'REV-REG-GUARD' && f.commit), 'regressione tra le segnalazioni');
  assert.equal(rep.checklist.find((c) => c.id === 'c14').status, 'fail');
  const prob = rep.review.items.filter((i) => i.level === 'problem');
  assert.ok(prob.length >= 2);
  // decisioni: uno consapevole, uno da fixare
  setReviewState(rep.id, [prob[0].key], 'aware'); const after = setReviewState(rep.id, [prob[1].key], 'fix');
  assert.equal(after.stats.aware, 1); assert.equal(after.stats.fix, 1);
  assert.equal(getReport(rep.id).review.items.find((i) => i.key === prob[0].key).state, 'aware');
  // re-analisi: le decisioni persistono
  const rep2 = await analyze({ repo: r2, branch: 'feat', base: 'main', useAI: false });
  assert.equal(rep2.review.items.find((i) => i.key === prob[0].key).state, 'aware');
  assert.equal(rep2.review.items.find((i) => i.key === prob[1].key).state, 'fix');
  // fix nel codice: ripristino test e guard -> il problema "da fixare" risulta risolto
  w('src/pay.js', 'export function pay(user, amount) {\n  if (!user) throw new Error("no user");\n  if (amount < 100) return refund(amount);\n  return charge(amount);\n}\n');
  w('tests/pay.test.js', 'expect(pay(u, 5)).toBe(1);\nexpect(pay(u, 500)).toBe(2);\n');
  h('add', '.'); h('commit', '-qm', 'fix: restore guard and test');
  const rep3 = await analyze({ repo: r2, branch: 'feat', base: 'main', useAI: false });
  assert.ok(rep3.review.resolved.length >= 1, 'fix verificato');
  assert.equal(rep3.review.stats.fix, 0);
  assert.match(toMarkdown(rep3), /Revisione modifiche/);
});

test('privacy: uscite solo verso AI configurata, segreti oscurati, offline e sendCode=false', async () => {
  const { guardedFetch, redact, readEgressLog } = await import('../src/privacy.js');
  const bodies = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => b += c); req.on('end', () => { bodies.push(b); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ choices: [{ message: { content: '{"b":[],"f":[],"a":[]}' } }], usage: { prompt_tokens: 50, completion_tokens: 5 } })); }); }).listen(0);
  const base = `http://127.0.0.1:${srv.address().port}/v1`;
  fs.writeFileSync(path.join(process.env.TESTERAI_DATA, 'usage.json'), '{}');
  saveConfig({ ai: { enabled: true, baseUrl: base, model: 'm', apiKey: 'k' }, budget: { cache: false }, privacy: { offline: false, sendCode: true, redactSecrets: true } });
  // host non configurato -> bloccato (e registrato)
  await assert.rejects(guardedFetch('https://example.com/x', { method: 'GET' }, 'ai'), /bloccata/);
  await assert.rejects(guardedFetch('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{}' }, 'cve'), /bloccata/); // cve disabilitato
  assert.ok(readEgressLog().some((e) => e.host === 'example.com' && e.blocked));
  // i segreti non arrivano all'AI
  g('checkout', '-q', 'feature/x');
  await analyze({ repo, branch: 'feature/x', useAI: true });
  assert.ok(bodies.length >= 1);
  for (const b of bodies) { assert.ok(!b.includes('SuperSecret123'), 'segreto inviato!'); }
  assert.equal(redact('const t = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"; a@b.com 10.1.2.3'), 'const t = "[REDACTED:TOKEN]"; [EMAIL] [IP]');
  // sendCode=false -> nessuna riga di codice
  bodies.length = 0; fs.writeFileSync(path.join(process.env.TESTERAI_DATA, 'usage.json'), '{}');
  saveConfig({ privacy: { sendCode: false } });
  await analyze({ repo, branch: 'feature/x', useAI: true });
  for (const b of bodies) assert.ok(!/eval\(|SELECT \*|password/i.test(JSON.parse(b).messages[1].content.replace(/SEC-[A-Z-]+/g, '')), 'codice inviato con sendCode=false');
  // offline -> nessuna richiesta
  bodies.length = 0; saveConfig({ privacy: { offline: true } });
  const off = await analyze({ repo, branch: 'feature/x', useAI: true });
  assert.equal(bodies.length, 0); assert.match(off.ai.note, /offline/i);
  await assert.rejects(guardedFetch(base + '/chat/completions', { method: 'POST', body: '{}' }, 'ai'), /offline/);
  saveConfig({ privacy: { offline: false, sendCode: true } });
  srv.close();
});

test('provider GitHub Copilot via SDK ufficiale: token dal FE, contesto chiuso senza strumenti, modelli, guard', async () => {
  const { setSdkLoader, stopCopilot } = await import('../src/copilot.js'); const { callModel, listModels } = await import('../src/ai.js'); const { loadConfig, DATA } = await import('../src/config.js'); const { readEgressLog } = await import('../src/privacy.js');
  const seen = { clientOpts: null, sessionOpts: null, prompt: '', started: 0, disconnected: 0 };
  class FakeHandler { async sendRequest() { return new Response('{}', { status: 200 }); } }
  class FakeClient {
    constructor(o) { seen.clientOpts = o; } async start() { seen.started++; } async stop() {} async forceStop() {}
    async listModels() { return [{ id: 'gpt-4o', name: 'GPT-4o' }, { id: 'claude-sonnet-4', name: 'Claude Sonnet 4' }]; }
    async createSession(o) { seen.sessionOpts = o; const hs = []; return { on: (h) => hs.push(h), sendAndWait: async (m) => { seen.prompt = m.prompt; hs.forEach((h) => h({ type: 'assistant.usage', data: { inputTokens: 120, outputTokens: 12 } })); return { data: { content: '{"b":[],"f":[],"a":[]}' } }; }, disconnect: async () => { seen.disconnected++; } }; }
  }
  const fake = { CopilotClient: FakeClient, CopilotRequestHandler: FakeHandler, RuntimeConnection: { forInProcess: (o) => ({ kind: 'in-process', ...o }) } };
  setSdkLoader(async () => fake);
  const set = (ai) => { saveConfig({ ai: { enabled: true, provider: 'copilot', model: 'gpt-4o', apiKey: 'github_pat_abc123', ...ai }, privacy: { offline: false, proxyUrl: '' } }); return loadConfig().ai; };
  const ai = set({});
  const r = await callModel(ai, 'SYS PROMPT', 'USER PROMPT', 20);
  assert.equal(r.text, '{"b":[],"f":[],"a":[]}'); assert.equal(r.tin, 120); assert.equal(r.tout, 12);
  // accesso: SOLO il token del FE, nessun login/ambiente locale; nessuna funzione ambientale
  assert.equal(seen.clientOpts.mode, 'empty'); assert.deepEqual(seen.clientOpts.github, { token: 'github_pat_abc123', useLoggedInUser: false });
  assert.ok(seen.clientOpts.runtime.baseDirectory.startsWith(DATA), 'stato SDK fuori dal progetto');
  // contesto chiuso: nessuno strumento, permessi negati, system message sostituito, cartella vuota privata
  assert.deepEqual(seen.sessionOpts.tools.availableTools, []);
  assert.equal(seen.sessionOpts.permissions.onRequest({}).kind, 'reject');
  assert.deepEqual(seen.sessionOpts.systemMessage, { mode: 'replace', content: 'SYS PROMPT' });
  assert.equal(seen.sessionOpts.model, 'gpt-4o'); assert.ok(seen.sessionOpts.workingDirectory.startsWith(DATA));
  assert.equal(seen.prompt, 'USER PROMPT'); assert.equal(seen.disconnected, 1);
  // elenco modelli
  assert.deepEqual((await listModels(ai)).map((m) => m.id), ['claude-sonnet-4', 'gpt-4o']);
  assert.equal(seen.started, 1, 'client riusato');
  // guard sul livello-modello: host Copilot ok, altri bloccati e registrati
  const h = seen.clientOpts.models.requestHandler;
  const ok = await h.sendRequest(new Request('https://api.githubcopilot.com/chat/completions', { method: 'POST', body: '{}' }), { url: 'https://api.githubcopilot.com/chat/completions' });
  assert.equal(ok.status, 200);
  await assert.rejects(h.sendRequest(new Request('https://evil.example.com/x'), { url: 'https://evil.example.com/x' }), /bloccata/);
  assert.ok(readEgressLog().some((e) => e.host === 'evil.example.com' && e.blocked) && readEgressLog().some((e) => e.via === 'copilot-sdk'));
  // token: obbligatorio, ghp_ classico rifiutato
  await assert.rejects(callModel(set({ apiKey: '' }), 's', 'u', 5), /Manca il token GitHub/);
  await assert.rejects(callModel(set({ apiKey: 'ghp_classic' }), 's', 'u', 5), /ghp_/);
  // offline: nessuna connessione
  await stopCopilot(); const aiOff = set({}); saveConfig({ privacy: { offline: true } });
  await assert.rejects(callModel(aiOff, 's', 'u', 5), /offline/i); saveConfig({ privacy: { offline: false } });
  // SDK non installato: messaggio con il comando
  setSdkLoader(async () => { throw Object.assign(new Error('x'), { code: 'SDK_NOT_FOUND' }); });
  await assert.rejects(callModel(set({}), 's', 'u', 5), /npm install @microsoft\/copilot-sdk/);
  // installato ma non si carica: l'errore VERO viene mostrato, non "non installato"
  setSdkLoader(async () => { throw new Error('ERR_DLOPEN_FAILED: koffi.node non valido'); });
  await assert.rejects(callModel(set({}), 's', 'u', 5), (e) => /installato ma non si carica/.test(e.message) && /koffi/.test(e.message) && /Pacchetto nativo/.test(e.hint));
  const { sdkStatus } = await import('../src/copilot.js'); const st = await sdkStatus(); assert.ok(!st.installed && /koffi/.test(st.error) && st.node);
  setSdkLoader(async () => { throw new Error('x'); }); await stopCopilot();
});

test('impatto: dalla modifica in un punto esistente risale fino all\'endpoint; modifiche locali incluse', async () => {
  const r3 = path.join(tmp, 'repo3'); fs.mkdirSync(r3);
  const h = (...a) => execFileSync('git', a, { cwd: r3, stdio: 'pipe' }).toString();
  const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(r3, f)), { recursive: true }); fs.writeFileSync(path.join(r3, f), t); };
  h('init', '-q', '-b', 'main'); h('config', 'user.email', 't@t'); h('config', 'user.name', 't');
  w('src/validate.js', 'export function checkUser(u) {\n  if (!u || !u.id) throw new Error("bad user");\n  return true;\n}\n');
  w('src/service.js', 'import { checkUser } from "./validate.js";\nexport function login(u) {\n  checkUser(u);\n  return "token";\n}\n');
  w('src/routes.js', 'import { login } from "./service.js";\nrouter.post("/login", (req, res) => {\n  res.json(login(req.body));\n});\n');
  w('api/views.py', 'from helper import compute\n\n@app.route("/report", methods=["GET"])\ndef report():\n    return compute(1)\n');
  w('api/helper.py', 'def compute(x):\n    if x < 10:\n        return x\n    return 10\n');
  h('add', '.'); h('commit', '-qm', 'base'); h('checkout', '-qb', 'feat');
  w('src/validate.js', 'export function checkUser(u) {\n  return true;\n}\n');
  h('add', '.'); h('commit', '-qm', 'drop validation');
  // modifica locale NON committata + file nuovo non tracciato
  w('api/helper.py', 'def compute(x):\n    if x <= 10:\n        return x\n    return 10\n');
  w('src/new.js', 'export const a = 1;\n');
  const rep = await analyze({ repo: r3, branch: 'feat', base: 'main', useAI: false });
  // 1) modifiche locali viste come pseudo-commit
  assert.ok(rep.commits.some((c) => c.short === 'locale'), 'commit locale');
  assert.ok(rep.files.some((f) => f.path === 'src/new.js' && f.status === 'A'), 'file non tracciato incluso');
  // 2) catena fino all'endpoint HTTP (JS)
  const ep = rep.impact.endpoints.find((e) => e.label === 'POST /login');
  assert.ok(ep, JSON.stringify(rep.impact.endpoints.map((e) => e.label)));
  assert.deepEqual(ep.chains[0].slice(0, 2), ['checkUser', 'login']);
  const f = rep.findings.find((x) => x.rule === 'REG-IMPACT' && x.file === 'src/validate.js');
  assert.ok(f && /POST \/login/.test(f.message), 'finding di impatto');
  // 3) decoratore Python + modifica locale
  assert.ok(rep.impact.endpoints.some((e) => /\/report/.test(e.label)), 'endpoint Python da modifica locale');
  assert.ok(rep.review.items.some((i) => i.commit === 'locale' && i.impact?.endpoints?.length), 'voce locale con impatto');
  assert.equal(rep.checklist.find((c) => c.id === 'c15').status, 'fail');
  // 4) funzione nuova: nessun impatto da cercare
  assert.match(toMarkdown(rep), /Impatto sugli endpoint/);
  // senza modifiche locali il commit 'locale' sparisce
  h('checkout', '--', 'api/helper.py'); fs.unlinkSync(path.join(r3, 'src/new.js'));
  const rep2 = await analyze({ repo: r3, branch: 'feat', base: 'main', useAI: false });
  assert.ok(!rep2.commits.some((c) => c.short === 'locale'));
});

test('AI sull\'impatto: contesto chiuso (solo funzione, callee, chiamanti, percorso); ask fuori perimetro ignorata', async () => {
  const r4 = path.join(tmp, 'repo4'); fs.mkdirSync(r4);
  const h = (...a) => execFileSync('git', a, { cwd: r4, stdio: 'pipe' }).toString();
  const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(r4, f)), { recursive: true }); fs.writeFileSync(path.join(r4, f), t); };
  h('init', '-q', '-b', 'main'); h('config', 'user.email', 't@t'); h('config', 'user.name', 't');
  w('src/util.js', 'export function normalizeInput(u) {\n  const CALLEE_BODY_MARKER = 1;\n  return u;\n}\n');
  w('src/validate.js', 'import { normalizeInput } from "./util.js";\nexport function checkUser(u) {\n  normalizeInput(u);\n  if (!u || !u.id) throw new Error("bad user");\n  return true;\n}\n');
  w('src/service.js', 'import { checkUser } from "./validate.js";\nexport function login(u) {\n  checkUser(u);\n  return "token";\n}\n');
  w('src/routes.js', 'import { login } from "./service.js";\nrouter.post("/login", (req, res) => {\n  res.json(login(req.body));\n});\n');
  w('src/unrelated.js', 'export function otherThing() {\n  const UNRELATED_MARKER = 42;\n  return UNRELATED_MARKER;\n}\n');
  h('add', '.'); h('commit', '-qm', 'base'); h('checkout', '-qb', 'feat');
  w('src/validate.js', 'import { normalizeInput } from "./util.js";\nexport function checkUser(u) {\n  normalizeInput(u);\n  return true;\n}\n');
  h('add', '.'); h('commit', '-qm', 'drop validation');
  const seen = []; let script = ['normalizeInput', null];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => b += c); req.on('end', () => {
    const j = JSON.parse(b); const sys = j.messages[0].content, usr = j.messages[1].content; seen.push({ sys, usr });
    let content = '{"b":[],"f":[],"a":[]}';
    if (/Impact review/.test(sys)) { const ask = script.shift(); content = ask ? `{"v":"unsure","why":"serve il callee","ask":["${ask}"]}` : '{"v":"risk","why":"guardia rimossa: raggiungibile da POST /login","ask":[]}'; }
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ choices: [{ message: { content } }], usage: { prompt_tokens: 90, completion_tokens: 10 } })); }); }).listen(0);
  const reset = () => fs.writeFileSync(path.join(process.env.TESTERAI_DATA, 'usage.json'), '{}');
  saveConfig({ ai: { enabled: true, provider: 'openai', baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, model: 'm', apiKey: 'k' }, budget: { strategy: 'detailed', monthlyTokens: 5000, perAnalysisTokens: 1500, maxContextTokens: 900, maxOutputTokens: 40, maxCalls: 6, maxRounds: 1, cache: false }, privacy: { offline: false, sendCode: true, redactSecrets: true } });
  reset();
  const rep = await analyze({ repo: r4, branch: 'feat', base: 'main', useAI: true });
  const imp = seen.filter((x) => /Impact review/.test(x.sys));
  assert.equal(imp.length, 2, 'prima chiamata + follow-up su simbolo del perimetro');
  assert.match(imp[0].usr, /FN .*checkUser/); assert.match(imp[0].usr, /login/); assert.match(imp[0].usr, /=> POST \/login/); assert.match(imp[0].usr, /normalizeInput/);
  assert.match(imp[1].usr, /CALLEE_BODY_MARKER/, 'follow-up col corpo del callee richiesto');
  for (const x of seen) assert.ok(!/UNRELATED_MARKER|otherThing/.test(x.usr), 'codice fuori perimetro inviato!');
  const f = rep.findings.find((x) => x.rule === 'REG-IMPACT');
  assert.equal(f.ai, 'confermato'); assert.match(f.aiNote, /POST \/login/);
  assert.ok(rep.review.items.some((i) => i.impact?.ai?.v === 'risk'));
  // ask fuori perimetro: ignorata, nessun follow-up
  seen.length = 0; script = ['otherThing', null]; reset();
  await analyze({ repo: r4, branch: 'feat', base: 'main', useAI: true });
  assert.equal(seen.filter((x) => /Impact review/.test(x.sys)).length, 1, 'ask non whitelisted -> nessuna seconda chiamata');
  for (const x of seen) assert.ok(!/UNRELATED_MARKER/.test(x.usr));
  // sendCode=false: solo nomi/percorso, nessuna riga di codice
  seen.length = 0; script = [null]; reset(); saveConfig({ privacy: { sendCode: false } });
  await analyze({ repo: r4, branch: 'feat', base: 'main', useAI: true });
  const m = seen.find((x) => /Impact review/.test(x.sys));
  assert.ok(m && /=> POST \/login/.test(m.usr) && !/CHG|BODY|return true|normalizeInput\(u\)/.test(m.usr), 'metadati senza codice');
  saveConfig({ privacy: { sendCode: true } });
  srv.close();
});

test('rete: causa reale invece di "fetch failed", proxy aziendale, diagnostica', async () => {
  const { guardedFetch } = await import('../src/privacy.js'); const { diagnose } = await import('../src/ai.js'); const { loadConfig } = await import('../src/config.js');
  // 1) host irraggiungibile -> codice di errore leggibile, non "fetch failed"
  saveConfig({ privacy: { offline: false, proxyUrl: '' }, ai: { enabled: true, provider: 'openai', baseUrl: 'http://127.0.0.1:1/v1', model: 'm', apiKey: 'k' } });
  await assert.rejects(guardedFetch('http://127.0.0.1:1/v1/chat/completions', { method: 'POST', body: '{}' }, 'ai'), (e) => /ECONNREFUSED/.test(e.message) && !/^fetch failed$/.test(e.message));
  // 2) http via proxy: la richiesta passa dal proxy con URL assoluto
  let seenUrl = '', seenAuth = '';
  const proxy = http.createServer((req, res) => { seenUrl = req.url; seenAuth = req.headers['proxy-authorization'] || ''; res.setHeader('content-type', 'application/json'); res.end('{"via":"proxy"}'); }).listen(0);
  saveConfig({ ai: { enabled: true, provider: 'openai', baseUrl: 'http://gw.local:8081/v1', model: 'm', apiKey: 'k' }, privacy: { proxyUrl: `http://user:pw@127.0.0.1:${proxy.address().port}` } });
  const r = await guardedFetch('http://gw.local:8081/v1/chat/completions', { method: 'POST', body: '{}' }, 'ai');
  assert.equal((await r.json()).via, 'proxy'); assert.equal(seenUrl, 'http://gw.local:8081/v1/chat/completions'); assert.match(seenAuth, /^Basic /);
  // 3) https via proxy: il tunnel CONNECT viene richiesto; rifiuto del proxy spiegato
  let connectTo = '';
  const proxy2 = http.createServer(() => {}); proxy2.on('connect', (req, sock) => { connectTo = req.url; sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); }); proxy2.listen(0);
  saveConfig({ ai: { baseUrl: 'https://llm.example.com/v1', provider: 'openai', apiKey: 'k', enabled: true }, privacy: { proxyUrl: `http://127.0.0.1:${proxy2.address().port}` } });
  const steps = await diagnose(loadConfig());
  assert.equal(connectTo, 'llm.example.com:443');
  assert.ok(steps.length === 1 && !steps[0].ok && /proxy/i.test(steps[0].detail), JSON.stringify(steps));
  saveConfig({ privacy: { proxyUrl: '' } }); proxy.close(); proxy2.close();
});

test('elenco modelli per provider (si sceglie, non si digita) e nessun auto-token', async () => {
  const { listModels } = await import('../src/ai.js'); const { loadConfig } = await import('../src/config.js');
  const reqs = [];
  const srv = http.createServer((req, res) => { reqs.push({ url: req.url, auth: req.headers.authorization, key: req.headers['x-api-key'] }); res.setHeader('content-type', 'application/json');
    if (req.url === '/copilot_internal/v2/token') return res.end(JSON.stringify({ token: 'cop-tok', expires_at: Math.floor(Date.now() / 1000) + 1500 }));
    if (req.url === '/models' && /cop-tok/.test(req.headers.authorization || '')) return res.end(JSON.stringify({ data: [{ id: 'gpt-4o', name: 'GPT-4o', capabilities: { type: 'chat' } }, { id: 'text-embedding-3', capabilities: { type: 'embeddings' } }, { id: 'claude-sonnet', name: 'Claude Sonnet', capabilities: { type: 'chat' }, model_picker_enabled: true }, { id: 'gpt-4o', capabilities: { type: 'chat' } }] }));
    if (req.url === '/v1/models?limit=100') return res.end(JSON.stringify({ data: [{ id: 'claude-x', display_name: 'Claude X' }] }));
    if (req.url === '/api/tags') return res.end(JSON.stringify({ models: [{ name: 'qwen2.5-coder' }, { name: 'llama3' }] }));
    if (req.url === '/v1/models') return res.end(JSON.stringify({ data: [{ id: 'gpt-4.1' }, { id: 'text-embedding-3-small' }, { id: 'whisper-1' }, { id: 'gpt-4o-mini' }] }));
    res.statusCode = 404; res.end('{}'); }).listen(0);
  const root = `http://127.0.0.1:${srv.address().port}`;
  const set = (ai) => { saveConfig({ ai: { enabled: true, apiKey: 'k', ...ai } }); return loadConfig().ai; };
  let m;
  m = await listModels(set({ provider: 'anthropic', baseUrl: root })); assert.deepEqual(m, [{ id: 'claude-x', name: 'Claude X' }]); assert.equal(reqs.at(-1).key, 'k');
  m = await listModels(set({ provider: 'ollama', baseUrl: root })); assert.deepEqual(m.map((x) => x.id), ['llama3', 'qwen2.5-coder']);
  m = await listModels(set({ provider: 'openai', baseUrl: root + '/v1' })); assert.deepEqual(m.map((x) => x.id), ['gpt-4.1', 'gpt-4o-mini'], 'esclusi embedding/whisper');
  await assert.rejects(listModels(set({ provider: 'openai', baseUrl: root + '/nope' })), (e) => /404/.test(e.message) && !!e.hint);
  srv.close();
});

test('analisi guidata dal documento: UNA chiamata compatta, solo regole pertinenti, PDF locale', async () => {
  const { distill, pdfToText } = await import('../src/docs.js'); const zlib = await import('node:zlib');
  // PDF minimo (stream compresso) con due requisiti
  const content = 'BT /F1 12 Tf (Requisiti) Tj ET BT (Il login deve validare sempre lo user prima di emettere il token.) Tj ET BT [(Vietato rimuovere i controlli di accesso dagli endpoint.)] TJ ET';
  const comp = zlib.deflateSync(Buffer.from(content));
  const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n'), comp, Buffer.from('\nendstream\nendobj\n%%EOF')]);
  const pt = pdfToText(pdf); assert.match(pt.text, /login deve validare/); assert.equal(pt.warning, '');
  assert.match(pdfToText(Buffer.from('%PDF-1.4 niente testo')).warning, /non leggibile/);
  // distillazione: bullet/normative -> regole numerate; irrilevante scartato
  const md = '# Requisiti login\n- Il login deve validare sempre lo user prima di emettere il token\n- Vietato rimuovere i controlli di accesso dagli endpoint\n\nParagrafo descrittivo senza regole che parla del colore del logo aziendale e basta.\n\n## Report\n- I report devono essere esportati in CSV';
  const d = distill([{ name: 'req.md', text: md }]); assert.ok(d.rules.length >= 3 && d.rules[0].id === 'R1');
  // repo + analisi guidata
  const r5 = path.join(tmp, 'repo5'); fs.mkdirSync(r5);
  const h = (...a) => execFileSync('git', a, { cwd: r5, stdio: 'pipe' }).toString();
  const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(r5, f)), { recursive: true }); fs.writeFileSync(path.join(r5, f), t); };
  h('init', '-q', '-b', 'main'); h('config', 'user.email', 't@t'); h('config', 'user.name', 't');
  w('src/validate.js', 'export function checkUser(u) {\n  if (!u || !u.id) throw new Error("bad user");\n  return true;\n}\n');
  w('src/service.js', 'import { checkUser } from "./validate.js";\nexport function login(u) {\n  checkUser(u);\n  return "token";\n}\n');
  w('src/routes.js', 'import { login } from "./service.js";\nrouter.post("/login", (req, res) => {\n  res.json(login(req.body));\n});\n');
  w('src/csv.js', 'export function exportCsv(rows) {\n  return rows.join(",");\n}\n');
  h('add', '.'); h('commit', '-qm', 'base'); h('checkout', '-qb', 'feat');
  w('src/validate.js', 'export function checkUser(u) {\n  return true;\n}\n'); h('add', '.'); h('commit', '-qm', 'simplify');
  const seen = [];
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => b += c); req.on('end', () => { const j = JSON.parse(b); seen.push({ sys: j.messages[0].content, usr: j.messages[1].content, max: j.max_tokens });
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ choices: [{ message: { content: '{"r":[["C1","viol","R1 validazione rimossa dal login"]],"ask":[]}' } }], usage: { prompt_tokens: 260, completion_tokens: 30 } })); }); }).listen(0);
  const reset = () => fs.writeFileSync(path.join(process.env.TESTERAI_DATA, 'usage.json'), '{}');
  saveConfig({ ai: { enabled: true, provider: 'openai', baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, model: 'm', apiKey: 'k' }, budget: { strategy: 'guided', monthlyTokens: 2000, perAnalysisTokens: 500, maxContextTokens: 600, maxOutputTokens: 80, maxCalls: 2, maxRounds: 1, docTokens: 200, cache: false }, privacy: { offline: false, sendCode: true, sendDocs: true, redactSecrets: true } });
  reset();
  const rep = await analyze({ repo: r5, branch: 'feat', base: 'main', useAI: true, docs: [{ name: 'req.md', text: md }], note: 'Focus su sicurezza del login, ignora la formattazione.' });
  assert.equal(seen.length, 1, 'UNA sola chiamata');
  const u = seen[0].usr;
  assert.match(u, /BRIEF Focus su sicurezza/); assert.match(u, /R1 .*login/i); assert.match(u, /C1\|validate\.js:checkUser\|.*\|checkUser>login=>POST \/login\|R/);
  assert.ok(!/colore del logo|CSV|exportCsv/.test(u), 'regole/codice irrilevanti non inviati');
  assert.ok(estimate(seen[0].sys + u) + seen[0].max <= 600, 'dentro il contesto');
  assert.ok(rep.ai.spent <= 500 && rep.ai.calls === 1, JSON.stringify(rep.ai));
  assert.ok(rep.findings.some((f) => f.rule === 'DOC-RULE' && /R1/.test(f.message)), 'violazione del documento');
  assert.ok(rep.review.items.some((i) => i.ai?.v === 'viol'));
  assert.ok(rep.ai.guided.rulesUsed.length >= 1 && rep.ai.guided.sent >= 1);
  // follow-up: ask di un id non inviato -> ignorata; sendCode=false -> nessun codice
  seen.length = 0; reset(); saveConfig({ privacy: { sendCode: false } });
  await analyze({ repo: r5, branch: 'feat', base: 'main', useAI: true, docs: [{ name: 'req.md', text: md }], note: 'x' });
  assert.ok(seen.length === 1 && !/return true|CHG|BODY/.test(seen[0].usr));
  saveConfig({ privacy: { sendCode: true } }); srv.close();
});
