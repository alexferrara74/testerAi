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
  saveConfig({ analysis: { cve: { osvUrl: url, cacheHours: 24 } } });
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
  saveConfig({ ai: { enabled: true, baseUrl: `http://127.0.0.1:${srv.address().port}/v1`, model: 'm', apiKey: 'k' } });
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
