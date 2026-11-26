import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';

const pexec = promisify(execFile);

// 'to' speciale: working tree (modifiche locali non committate, staged+unstaged+file nuovi)
export const WT = 'WORKTREE';
const range = (from, to) => (to === WT ? [from] : [from, to]);
const MAX_UNTRACKED = 1024 * 1024;

export async function git(cwd, args, { allowFail = false } = {}) {
  try {
    const { stdout } = await pexec('git', ['-c', 'core.quotepath=off', ...args], {
      cwd, maxBuffer: 128 * 1024 * 1024,
      // Nessuna operazione di rete per git: protocolli remoti disabilitati, niente prompt/credential helper.
      env: { ...process.env, GIT_ALLOW_PROTOCOL: 'file', GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'true', GIT_OPTIONAL_LOCKS: '0' },
    });
    return stdout;
  } catch (e) {
    if (allowFail) return '';
    throw new Error(`git ${args.join(' ')}: ${(e.stderr || e.message).toString().trim()}`);
  }
}

export function isGitRepo(dir) {
  try { return fs.existsSync(path.join(dir, '.git')); } catch { return false; }
}

// Un ref e' accettato solo se non inizia con '-' e non contiene caratteri di controllo.
export function safeRef(ref) {
  if (typeof ref !== 'string' || !ref || ref.startsWith('-') || /[\s\x00-\x1f~^:?*\[\\]/.test(ref)) {
    throw new Error(`Ref non valido: ${ref}`);
  }
  return ref;
}

export async function listBranches(repo) {
  const out = await git(repo, ['for-each-ref', '--format=%(refname:short)|%(refname)', 'refs/heads', 'refs/remotes']);
  const names = out.split('\n').filter(Boolean).map((l) => l.split('|')).filter(([n]) => !n.endsWith('/HEAD'));
  const current = (await git(repo, ['rev-parse', '--abbrev-ref', 'HEAD'], { allowFail: true })).trim();
  return { current, branches: names.map(([n, full]) => ({ name: n, remote: full.startsWith('refs/remotes') })) };
}

const PREFERRED = ['main', 'master', 'develop', 'development', 'dev', 'trunk'];

/**
 * Deduce il branch "padre": tra i candidati sceglie quello con meno commit tra merge-base e branch
 * (= il piu' vicino al punto di stacco). A parita' preferisce main/master/develop.
 */
export async function detectBase(repo, branch) {
  const { branches } = await listBranches(repo);
  const cands = branches.map((b) => b.name).filter((n) => n !== branch && n !== `origin/${branch}` && n !== branch.replace(/^origin\//, ''));
  let best = null;
  for (const c of cands) {
    const mb = (await git(repo, ['merge-base', c, branch], { allowFail: true })).trim();
    if (!mb) continue;
    const ahead = parseInt((await git(repo, ['rev-list', '--count', `${mb}..${branch}`], { allowFail: true })).trim() || '0', 10);
    const pref = PREFERRED.indexOf(c.replace(/^origin\//, ''));
    const score = ahead * 10 + (pref >= 0 ? pref : 9) + (c.startsWith('origin/') ? 0.5 : 0);
    if (ahead === 0 && (await git(repo, ['rev-parse', c])).trim() === (await git(repo, ['rev-parse', branch])).trim()) continue;
    if (!best || score < best.score) best = { name: c, score, mb, ahead };
  }
  return best ? { base: best.name, mergeBase: best.mb } : null;
}

export async function mergeBase(repo, base, branch) {
  return (await git(repo, ['merge-base', safeRef(base), safeRef(branch)])).trim();
}

export async function commitsBetween(repo, mb, branch) {
  const SEP = '\x1f', REC = '\x1e';
  const out = await git(repo, ['log', '--reverse', `--format=${REC}%H${SEP}%an${SEP}%aI${SEP}%P${SEP}%s`, '--numstat', `${mb}..${branch}`]);
  const commits = [];
  for (const rec of out.split(REC)) {
    const t = rec.replace(/^\n+/, '');
    if (!t.trim()) continue;
    const [head, ...rest] = t.split('\n');
    const [hash, author, date, parents, subject] = head.split(SEP);
    let add = 0, del = 0, files = 0;
    for (const l of rest) {
      const m = l.match(/^(\d+|-)\t(\d+|-)\t/);
      if (m) { files++; add += m[1] === '-' ? 0 : +m[1]; del += m[2] === '-' ? 0 : +m[2]; }
    }
    commits.push({ hash, short: hash.slice(0, 8), author, date, merge: parents.trim().split(' ').length > 1, subject, files, add, del });
  }
  return commits;
}

export async function untracked(repo) {
  const out = await git(repo, ['ls-files', '--others', '--exclude-standard', '-z'], { allowFail: true });
  const files = [];
  for (const p of out.split('\0').filter(Boolean)) {
    try {
      const abs = path.join(repo, p); const st = fs.statSync(abs);
      if (!st.isFile() || st.size > MAX_UNTRACKED) continue;
      const buf = fs.readFileSync(abs); if (buf.includes(0)) continue; // binario
      files.push({ path: p, lines: buf.toString('utf8').split('\n').filter((l, i, a) => !(i === a.length - 1 && l === '')) });
    } catch { /* ignora */ }
  }
  return files;
}

export async function nameStatus(repo, mb, branch) {
  const out = await git(repo, ['diff', '--name-status', '-M', '-z', ...range(mb, branch)]);
  const parts = out.split('\0').filter((x) => x !== '');
  const files = [];
  for (let i = 0; i < parts.length;) {
    const st = parts[i++];
    if (st[0] === 'R' || st[0] === 'C') files.push({ status: st[0], oldPath: parts[i++], path: parts[i++] });
    else files.push({ status: st[0], path: parts[i++] });
  }
  if (branch === WT) for (const u of await untracked(repo)) files.push({ status: 'A', path: u.path });
  return files;
}

export async function numstat(repo, mb, branch) {
  const out = await git(repo, ['diff', '--numstat', '-M', '-z', ...range(mb, branch)]);
  const map = new Map();
  if (branch === WT) for (const u of await untracked(repo)) map.set(u.path, { add: u.lines.length, del: 0, binary: false });
  const parts = out.split('\0');
  for (let i = 0; i < parts.length; i++) {
    const m = parts[i].match(/^(\d+|-)\t(\d+|-)\t(.*)$/);
    if (!m) continue;
    let p = m[3];
    if (p === '') { i += 2; p = parts[i]; } // rename: old\0new
    map.set(p, { add: m[1] === '-' ? 0 : +m[1], del: m[2] === '-' ? 0 : +m[2], binary: m[1] === '-' });
  }
  return map;
}

/** Diff unificato a 0 righe di contesto, parsato in hunk con numeri di riga. */
export async function parseDiff(repo, mb, branch) {
  const out = await git(repo, ['diff', '-U0', '--no-color', '-M', ...range(mb, branch)]);
  const files = new Map();
  if (branch === WT) for (const u of await untracked(repo)) files.set(u.path, { path: u.path, hunks: [{ newStart: 1, oldStart: 0, added: u.lines.map((t, i) => ({ n: i + 1, t })), removed: [] }] });
  let cur = null, hunk = null, oldNo = 0, newNo = 0;
  for (const line of out.split('\n')) {
    if (line.startsWith('diff --git ')) { cur = null; hunk = null; continue; }
    if (line.startsWith('+++ ')) {
      const p = line.slice(4);
      if (p === '/dev/null') continue;
      cur = { path: p.replace(/^b\//, ''), hunks: [] };
      files.set(cur.path, cur);
      continue;
    }
    if (line.startsWith('--- ')) continue;
    if (!cur) continue;
    const h = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (h) { oldNo = +h[1]; newNo = +h[3]; hunk = { newStart: newNo, oldStart: oldNo, added: [], removed: [] }; cur.hunks.push(hunk); continue; }
    if (!hunk) continue;
    if (line.startsWith('+')) hunk.added.push({ n: newNo++, t: line.slice(1) });
    else if (line.startsWith('-')) hunk.removed.push({ n: oldNo++, t: line.slice(1) });
  }
  return files;
}

/** Contenuto di un file a un ref (o nel working tree). */
export async function readFileAt(repo, ref, file) {
  if (ref === WT) { try { const abs = path.resolve(repo, file); if (!abs.startsWith(path.resolve(repo) + path.sep)) return ''; return fs.readFileSync(abs, 'utf8'); } catch { return ''; } }
  return git(repo, ['show', `${safeRef(ref)}:${file}`], { allowFail: true });
}

export async function showLines(repo, ref, file, from, to) {
  const out = await readFileAt(repo, ref, file);
  return out.split('\n').slice(Math.max(0, from - 1), to).map((t, i) => `${from + i}:${t}`);
}

export async function grepSymbol(repo, ref, symbol) {
  const out = ref === WT ? await git(repo, ['grep', '-lwI', '--untracked', '-e', symbol, '--'], { allowFail: true }) : await git(repo, ['grep', '-lwI', '-e', symbol, safeRef(ref), '--'], { allowFail: true });
  return out.split('\n').filter(Boolean).map((l) => (ref === WT ? l : l.slice(l.indexOf(':') + 1)));
}

/** Occorrenze (file, riga, testo) di un simbolo come parola intera. */
export async function grepLines(repo, ref, symbol, cap = 400) {
  const out = ref === WT ? await git(repo, ['grep', '-nwI', '--untracked', '-e', symbol, '--'], { allowFail: true }) : await git(repo, ['grep', '-nwI', '-e', symbol, safeRef(ref), '--'], { allowFail: true });
  const hits = [];
  for (const l of out.split('\n')) {
    if (!l) continue;
    const m = (ref === WT ? l : l.slice(ref.length + 1)).match(/^(.*?):(\d+):(.*)$/); if (!m) continue;
    hits.push({ file: m[1], line: +m[2], text: m[3] }); if (hits.length >= cap) break;
  }
  return hits;
}

export async function currentBranch(repo) { return (await git(repo, ['rev-parse', '--abbrev-ref', 'HEAD'], { allowFail: true })).trim(); }

export async function behindCount(repo, base, branch) {
  return parseInt((await git(repo, ['rev-list', '--count', `${safeRef(branch)}..${safeRef(base)}`], { allowFail: true })).trim() || '0', 10);
}

export async function dirtyFiles(repo) {
  return (await git(repo, ['status', '--porcelain'], { allowFail: true })).split('\n').filter(Boolean);
}
