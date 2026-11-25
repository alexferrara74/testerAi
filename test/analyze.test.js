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

test('AI: rispetta il budget di 2000 token e usa la cache', async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => b += c); req.on('end', () => {
      const j = JSON.parse(b); seen.push(j);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ choices: [{ message: { content: '{"bug":[["F1","segreto reale"]],"fp":[],"ask":[]}' } }], usage: { prompt_tokens: 100, completion_tokens: 10 } }));
    });
  }).listen(0);
  const port = srv.address().port;
  saveConfig({ ai: { enabled: true, baseUrl: `http://127.0.0.1:${port}/v1`, model: 'm', apiKey: 'k' }, budget: { maxContextTokens: 2000 } });
  const r = await analyze({ repo, branch: 'feature/x', useAI: true, docs: [{ name: 'rules', text: 'Vietato usare eval in util.\n\nAltro testo irrilevante qui.' }] });
  assert.ok(r.ai.used && r.ai.calls >= 1, JSON.stringify(r.ai));
  for (const j of seen) assert.ok(estimate(j.messages.map((m) => m.content).join('')) + j.max_tokens <= 2000);
  const n = seen.length;
  await analyze({ repo, branch: 'feature/x', useAI: true, docs: [{ name: 'rules', text: 'Vietato usare eval in util.\n\nAltro testo irrilevante qui.' }] });
  assert.equal(seen.length, n, 'seconda esecuzione servita dalla cache');
  srv.close();
});
