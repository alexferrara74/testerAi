import * as G from './git.js';
import * as R from './rules.js';

// Analisi per singolo commit: SOLO regole statiche (0 token). Serve a dire "quale commit ha introdotto cosa",
// quali problemi sono stati poi corretti (ma restano nella cronologia) e dove sta il rischio.
const W = { critical: 8, high: 4, medium: 2, low: 1, info: 0 };
export const findingKey = (f) => `${f.rule}|${f.file}|${f.code}`;

export async function analyzeCommits(repo, commits, { ignored, max = 100 }) {
  const out = new Map();
  const list = commits.slice(-max); // i piu' recenti
  for (let i = 0; i < list.length; i += 6) {
    await Promise.all(list.slice(i, i + 6).map(async (c) => {
      const [st, diff] = await Promise.all([G.nameStatus(repo, `${c.hash}^`, c.hash), G.parseDiff(repo, `${c.hash}^`, c.hash)]);
      const findings = [];
      if (!c.merge) for (const [file, d] of diff) if (!ignored(file)) findings.push(...R.scanHunks(file, d.hunks));
      for (const s of st) {
        if (s.status !== 'D' && R.isSensitiveFile(s.path)) findings.push({ rule: 'SEC-SENSITIVE-FILE', severity: 'critical', file: s.path, message: 'File sensibile aggiunto', code: '' });
        if (s.status === 'D' && R.isTestPath(s.path)) findings.push({ rule: 'REG-TEST-DELETED', severity: 'high', file: s.path, message: 'Test eliminato', code: '' });
      }
      const touchesSrc = st.some((s) => s.status !== 'D' && R.isSourcePath(s.path) && !ignored(s.path));
      const touchesTests = st.some((s) => R.isTestPath(s.path));
      out.set(c.hash, {
        files: st.map((s) => ({ status: s.status, path: s.path, oldPath: s.oldPath })),
        findings, touchesSrc, touchesTests, diff,
        risk: findings.reduce((n, f) => n + (W[f.severity] || 0), 0) + (touchesSrc && !touchesTests ? 1 : 0),
      });
    }));
  }
  return { byHash: out, analyzed: list.length, total: commits.length };
}
