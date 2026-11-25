import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { execFileSync } from 'node:child_process';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tai-'));
process.env.TESTERAI_DATA = path.join(tmp, 'data');
const { analyze, toMarkdown } = await import('../src/analyzer.js');
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
