import fs from 'node:fs';
import path from 'node:path';
import { git, safeRef } from './git.js';
import { DATA } from './config.js';
import { guardedFetch } from './privacy.js';

// Verifica CVE delle SOLE dipendenze aggiunte/cambiate nel branch (non l'intero albero) tramite OSV.dev.
// Costo AI: 0 token. Risultati in cache su disco per ridurre le chiamate di rete.

const show = (repo, ref, file) => git(repo, ['show', `${ref}:${file}`], { allowFail: true });
const dirOf = (f) => (f.includes('/') ? f.slice(0, f.lastIndexOf('/') + 1) : '');
const cleanVer = (v) => (String(v).match(/\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?/) || [''])[0];

/* ---- parser dei manifest -> Map(name -> {version, exact}) ---- */
function parsePackageJson(txt, lockTxt) {
  const m = new Map(); let j, lock;
  try { j = JSON.parse(txt); } catch { return m; }
  try { lock = lockTxt ? JSON.parse(lockTxt) : null; } catch { lock = null; }
  const resolved = (n) => lock?.packages?.[`node_modules/${n}`]?.version || lock?.dependencies?.[n]?.version;
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [n, range] of Object.entries(j[k] || {})) {
      const r = resolved(n);
      if (r) m.set(n, { version: r, exact: true, range });
      else if (/^[\d]/.test(range) || /^[\^~]/.test(range)) m.set(n, { version: cleanVer(range), exact: /^\d/.test(range), range });
    }
  }
  return m;
}
function parseRequirements(txt) {
  const m = new Map();
  for (const l of txt.split('\n')) {
    const x = l.trim().match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.\-+]+)/);
    if (x) m.set(x[1].toLowerCase(), { version: x[2], exact: true });
  }
  return m;
}
function parseGoMod(txt) {
  const m = new Map();
  for (const l of txt.split('\n')) {
    const x = l.trim().replace(/^require\s+/, '').match(/^([\w.\-/~]+\.[\w.\-/]+)\s+v([\w.\-+]+)/);
    if (x) m.set(x[1], { version: x[2], exact: true });
  }
  return m;
}
const KINDS = [
  { re: /(^|\/)package\.json$/, eco: 'npm', parse: async (repo, ref, f) => parsePackageJson(await show(repo, ref, f), await show(repo, ref, dirOf(f) + 'package-lock.json')) },
  { re: /(^|\/)requirements[\w.\-]*\.txt$/, eco: 'PyPI', parse: async (repo, ref, f) => parseRequirements(await show(repo, ref, f)) },
  { re: /(^|\/)go\.mod$/, eco: 'Go', parse: async (repo, ref, f) => parseGoMod(await show(repo, ref, f)) },
];

/** Dipendenze nuove o con versione cambiata tra base e branch. */
export async function changedDeps(repo, mb, branch, changedFiles) {
  const out = [];
  const lockChanged = (f) => changedFiles.some((c) => /(package-lock\.json)$/.test(c) && dirOf(c) === dirOf(f));
  const targets = new Set(changedFiles.filter((f) => KINDS.some((k) => k.re.test(f))));
  for (const f of changedFiles) if (/package-lock\.json$/.test(f)) targets.add(dirOf(f) + 'package.json');
  for (const f of targets) {
    const k = KINDS.find((x) => x.re.test(f)); if (!k) continue;
    const [before, after] = await Promise.all([k.parse(repo, mb, f), k.parse(repo, branch, f)]);
    for (const [name, d] of after) {
      const b = before.get(name);
      if (!b || b.version !== d.version) out.push({ ecosystem: k.eco, name, from: b?.version || null, to: d.version, exact: d.exact, file: f, lock: lockChanged(f) });
    }
  }
  return out;
}

/* ---- OSV ---- */
const CACHE = () => path.join(DATA, 'cache', 'osv.json');
let mem = null;
const loadC = () => { if (!mem) { try { mem = JSON.parse(fs.readFileSync(CACHE(), 'utf8')); } catch { mem = {}; } } return mem; };
const saveC = () => { try { fs.mkdirSync(path.dirname(CACHE()), { recursive: true }); fs.writeFileSync(CACHE(), JSON.stringify(mem)); } catch { /* best effort */ } };

const sevFrom = (v) => {
  const s = String(v.database_specific?.severity || '').toLowerCase();
  if (s === 'critical') return 'critical'; if (s === 'high') return 'high'; if (s === 'moderate' || s === 'medium') return 'medium'; if (s === 'low') return 'low';
  return 'medium'; // sconosciuta: prudente ma non allarmista
};
const fixedIn = (v, name) => {
  for (const a of v.affected || []) if (!a.package || a.package.name === name) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) return e.fixed;
  return null;
};
async function osv(base, pathname, body, timeoutMs) {
  const res = await guardedFetch(base.replace(/\/+$/, '') + pathname, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(timeoutMs) }, 'cve');
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  return res.json();
}

export async function checkCves(deps, cfg) {
  const info = { checked: deps.length, error: null, source: cfg.osvUrl };
  const c = loadC(); const ttl = cfg.cacheHours * 3600e3, now = Date.now();
  const key = (d) => `${d.ecosystem}|${d.name}|${d.to}`;
  const todo = deps.filter((d) => d.to && !(c[key(d)] && now - c[key(d)].t < ttl));
  try {
    for (let i = 0; i < todo.length; i += 100) {
      const chunk = todo.slice(i, i + 100);
      const r = await osv(cfg.osvUrl, '/v1/querybatch', { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.to })) }, cfg.timeoutMs);
      const ids = [...new Set(r.results.flatMap((x) => (x.vulns || []).map((v) => v.id)))].slice(0, 60);
      const detail = {};
      await Promise.all(ids.map(async (id) => { try { detail[id] = await osv(cfg.osvUrl, '/v1/vulns/' + encodeURIComponent(id), null, cfg.timeoutMs); } catch { detail[id] = { id }; } }));
      chunk.forEach((d, n) => {
        c[key(d)] = { t: now, vulns: (r.results[n]?.vulns || []).map((v) => { const x = detail[v.id] || { id: v.id }; return { id: v.id, cve: (x.aliases || []).find((a) => a.startsWith('CVE-')) || null, severity: sevFrom(x), summary: (x.summary || '').slice(0, 140), fixed: fixedIn(x, d.name) }; }) };
      });
      saveC();
    }
  } catch (e) { info.error = `Verifica CVE non riuscita (${e.message}). Risultati parziali.`; }
  for (const d of deps) d.vulns = c[key(d)]?.vulns ?? null; // null = non verificata
  return info;
}
