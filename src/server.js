import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, saveConfig, publicConfig, ROOT } from './config.js';
import * as G from './git.js';
import { analyze, listReports, getReport, setChecked, toMarkdown } from './analyzer.js';
import { callModel } from './ai.js';
import { readUsage } from './usage.js';

const PUB = path.join(ROOT, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
const jobs = new Map();

const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const readBody = (req) => new Promise((ok, ko) => {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > 8e6) { ko(new Error('payload troppo grande')); req.destroy(); } });
  req.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch { ko(new Error('JSON non valido')); } });
});
const repoOf = (p) => {
  const r = path.resolve(String(p || ''));
  if (!fs.existsSync(r) || !G.isGitRepo(r)) throw new Error('Non e\' un repository git: ' + r);
  return r;
};

export function createServer() {
  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    try {
      // Difesa CSRF/DNS-rebinding: l'API accede al filesystem locale.
      const origin = req.headers.origin;
      if (u.pathname.startsWith('/api/') && origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: 'origin non consentito' });

      if (req.method === 'GET' && u.pathname === '/api/fs') {
        const p = path.resolve(u.searchParams.get('path') || os.homedir());
        const dirs = fs.readdirSync(p, { withFileTypes: true }).filter((d) => d.isDirectory() && !d.name.startsWith('.')).map((d) => d.name).sort();
        return send(res, 200, { path: p, parent: path.dirname(p) === p ? null : path.dirname(p), dirs, isGit: G.isGitRepo(p) });
      }
      if (req.method === 'GET' && u.pathname === '/api/branches') {
        const repo = repoOf(u.searchParams.get('path'));
        const b = await G.listBranches(repo);
        const target = u.searchParams.get('branch') || b.current;
        const d = target ? await G.detectBase(repo, target) : null;
        return send(res, 200, { ...b, suggestedBase: d?.base || null });
      }
      if (req.method === 'GET' && u.pathname === '/api/usage') { const u2 = readUsage(), lim = loadConfig().budget.monthlyTokens; return send(res, 200, { month: u2.month, used: u2.used, limit: lim, remaining: Math.max(0, lim - u2.used), calls: u2.calls }); }
      if (u.pathname === '/api/config') {
        if (req.method === 'GET') return send(res, 200, publicConfig());
        if (req.method === 'PUT') return send(res, 200, publicConfig(saveConfig(await readBody(req))));
      }
      if (req.method === 'POST' && u.pathname === '/api/config/test') {
        const { ai } = loadConfig();
        const r = await callModel(ai, 'Reply {}', 'x', 5); // ~15 token; viene contabilizzato
        const { record } = await import('./usage.js'); record((r.tin || 0) + (r.tout || 0) || 15, 'test');
        return send(res, 200, { ok: true, reply: r.text.slice(0, 100), tokens: { in: r.tin, out: r.tout } });
      }
      if (req.method === 'POST' && u.pathname === '/api/analyze') {
        const b = await readBody(req);
        const repo = repoOf(b.path);
        const id = Math.random().toString(36).slice(2);
        const job = { status: 'running', progress: 'avvio', reportId: null, error: null };
        jobs.set(id, job);
        const docs = (Array.isArray(b.docs) ? b.docs : []).slice(0, 20).map((d) => ({ name: String(d.name || 'doc').slice(0, 80), text: String(d.text || '').slice(0, 300000) }));
        analyze({ repo, branch: b.branch, base: b.base, docs, useAI: b.useAI !== false, onProgress: (m) => { job.progress = m; } })
          .then((r) => { job.status = 'done'; job.reportId = r.id; }).catch((e) => { job.status = 'error'; job.error = e.message; });
        return send(res, 202, { job: id });
      }
      if (req.method === 'GET' && u.pathname.startsWith('/api/jobs/')) {
        const j = jobs.get(u.pathname.split('/').pop());
        return j ? send(res, 200, j) : send(res, 404, { error: 'job inesistente' });
      }
      if (req.method === 'GET' && u.pathname === '/api/reports') return send(res, 200, listReports());
      let m;
      if ((m = u.pathname.match(/^\/api\/reports\/([\w-]+)(\.md)?$/)) && req.method === 'GET') {
        const r = getReport(m[1]);
        return m[2] ? send(res, 200, toMarkdown(r), 'text/markdown; charset=utf-8') : send(res, 200, r);
      }
      if ((m = u.pathname.match(/^\/api\/reports\/([\w-]+)\/check$/)) && req.method === 'POST') {
        const b = await readBody(req);
        return send(res, 200, setChecked(m[1], b.item, b.checked));
      }
      if (u.pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });

      const f = path.join(PUB, u.pathname === '/' ? 'index.html' : path.normalize(u.pathname).replace(/^(\.\.[/\\])+/, ''));
      if (!f.startsWith(PUB) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) return send(res, 404, 'not found', 'text/plain');
      return send(res, 200, fs.readFileSync(f), MIME[path.extname(f)] || 'application/octet-stream');
    } catch (e) { send(res, 400, { error: e.message }); }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = +process.env.PORT || 4377, host = process.env.HOST || '127.0.0.1';
  createServer().listen(port, host, () => console.log(`testerAi su http://${host}:${port}`));
}
