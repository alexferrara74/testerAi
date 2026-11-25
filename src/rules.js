// Regole deterministiche: costo AI = 0 token. Applicate solo alle righe AGGIUNTE.

export const LINE_RULES = [
  { id: 'SEC-SECRET-PRIVKEY', cat: 'security', sev: 'critical', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, msg: 'Chiave privata nel codice' },
  { id: 'SEC-SECRET-AWS', cat: 'security', sev: 'critical', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, msg: 'Possibile AWS access key' },
  { id: 'SEC-SECRET-TOKEN', cat: 'security', sev: 'critical', re: /\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35})\b/, msg: 'Token/API key hardcoded' },
  { id: 'SEC-SECRET-ASSIGN', cat: 'security', sev: 'high', re: /(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s${}]{6,}["']/i, msg: 'Credenziale hardcoded', skipPath: /(test|spec|mock|fixture|example|sample)/i },
  { id: 'SEC-EVAL', cat: 'security', sev: 'high', re: /\beval\s*\(|new Function\s*\(/, msg: 'eval/new Function: code injection', langs: ['js', 'py', 'php'] },
  { id: 'SEC-EXEC', cat: 'security', sev: 'high', re: /\b(?:child_process|os\.system|subprocess\.(?:call|run|Popen)|Runtime\.getRuntime\(\)\.exec|shell_exec|passthru)\b.*(?:\+|\$\{|%s|f["'])/, msg: 'Esecuzione comando con input concatenato' },
  { id: 'SEC-SQL-CONCAT', cat: 'security', sev: 'high', re: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\b(?:FROM|INTO|SET|WHERE)\b[^;\n]*(?:["']\s*\+|\+\s*["']|\$\{|%s|f["'])/i, msg: 'Possibile SQL injection (query concatenata)' },
  { id: 'SEC-XSS', cat: 'security', sev: 'medium', re: /\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(|v-html/, msg: 'Possibile XSS (HTML non sanitizzato)' },
  { id: 'SEC-TLS-OFF', cat: 'security', sev: 'high', re: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|InsecureSkipVerify\s*:\s*true|-k\b.*https/, msg: 'Verifica TLS disabilitata' },
  { id: 'SEC-WEAK-HASH', cat: 'security', sev: 'medium', re: /\b(?:md5|sha1)\b\s*[(\[]|createHash\(["'](?:md5|sha1)["']\)|hashlib\.(?:md5|sha1)/i, msg: 'Hash debole (md5/sha1)' },
  { id: 'SEC-HTTP', cat: 'security', sev: 'low', re: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org)[\w.-]+/, msg: 'URL http non cifrato' },
  { id: 'SEC-CHMOD', cat: 'security', sev: 'medium', re: /chmod\s+(?:-R\s+)?777|0o?777\b/, msg: 'Permessi 777' },
  { id: 'SEC-CORS-ANY', cat: 'security', sev: 'medium', re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*["']\*["']/i, msg: 'CORS aperto a *' },
  { id: 'ERR-CONFLICT', cat: 'error', sev: 'critical', re: /^(?:<{7}|>{7})(?: |$)|^={7}$/, msg: 'Marcatore di merge conflict' },
  { id: 'ERR-EMPTY-CATCH', cat: 'error', sev: 'medium', re: /catch\s*(?:\([^)]*\))?\s*\{\s*\}|except\s*(?:\w+\s*)?:\s*pass\b/, msg: 'Eccezione ingoiata (catch vuoto)' },
  { id: 'ERR-DEBUGGER', cat: 'error', sev: 'medium', re: /^\s*debugger\s*;?\s*$|\bbreakpoint\(\)|import pdb|pdb\.set_trace/, msg: 'Istruzione di debug' },
  { id: 'ERR-TEST-ONLY', cat: 'regression', sev: 'high', re: /\b(?:describe|it|test)\.only\s*\(|\bfdescribe\(|\bfit\(|@Ignore\b|\bt\.Skip\(|\.skip\s*\(|@pytest\.mark\.skip|\bxit\(/, msg: 'Test focalizzato o saltato' },
  { id: 'ERR-CONSOLE', cat: 'quality', sev: 'low', re: /\bconsole\.(?:log|debug)\s*\(|\bprint\(\s*["']DEBUG|System\.out\.println/, msg: 'Log di debug residuo', skipPath: /(test|spec|cli|bin|scripts?)\b/i },
  { id: 'QLT-TODO', cat: 'quality', sev: 'info', re: /\b(?:TODO|FIXME|HACK|XXX)\b/, msg: 'TODO/FIXME aggiunto' },
  { id: 'ERR-EQ-LOOSE', cat: 'error', sev: 'low', re: /[^=!<>]==[^=]|!=[^=]/, msg: 'Confronto loose (==)', langs: ['js'], skipComment: true },
];

const EXT_LANG = { js: 'js', jsx: 'js', ts: 'js', tsx: 'js', mjs: 'js', cjs: 'js', vue: 'js', py: 'py', php: 'php', java: 'java', go: 'go', cs: 'cs', rb: 'rb', sh: 'sh' };
export const langOf = (p) => EXT_LANG[(p.split('.').pop() || '').toLowerCase()] || 'other';
export const isTestPath = (p) => /(^|\/)(tests?|__tests__|spec|e2e)\/|\.(test|spec)\.|_test\.|Test\.java$/i.test(p);
export const isDocPath = (p) => /\.(md|txt|rst|adoc)$/i.test(p) || /(^|\/)docs?\//i.test(p);
export const isSourcePath = (p) => langOf(p) !== 'other' && !isTestPath(p);
export const isManifest = (p) => /(^|\/)(package\.json|requirements\.txt|pyproject\.toml|pom\.xml|build\.gradle|go\.mod|Gemfile|composer\.json|Cargo\.toml)$/.test(p);
export const isLockfile = (p) => /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|go\.sum|Gemfile\.lock|composer\.lock|Cargo\.lock)$/.test(p);
export const isSensitiveFile = (p) => /(^|\/)(\.env(\..*)?|id_rsa|id_ed25519|.*\.(pem|p12|pfx|jks|keystore)|credentials(\.json)?|secrets?\.(json|ya?ml))$/i.test(p) && !/\.(example|sample|template)$/i.test(p);
export const isRiskyPath = (p) => /auth|login|session|crypt|token|password|payment|billing|permission|acl|security|sql|query|migrat|middleware/i.test(p);

export function scanHunks(file, hunks) {
  const out = [];
  const lang = langOf(file);
  for (const h of hunks) {
    for (const { n, t } of h.added) {
      if (t.length > 2000) continue; // minificato/generato
      for (const r of LINE_RULES) {
        if (r.langs && !r.langs.includes(lang)) continue;
        if (r.skipPath && r.skipPath.test(file)) continue;
        if (r.skipComment && /^\s*(\/\/|#|\*)/.test(t)) continue;
        if (r.re.test(t)) out.push({ rule: r.id, category: r.cat, severity: r.sev, file, line: n, message: r.msg, code: t.trim().slice(0, 160) });
      }
    }
  }
  return out;
}

const DEF_RE = [
  /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\*?\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/,
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
  /^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)()/,
  /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/,
  /^\s*(?:public|private|protected|static|final|\s)+[\w<>\[\],?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:throws [\w, ]+)?\s*\{?\s*$/,
  /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)/,
];
export function defOf(line) {
  for (const re of DEF_RE) { const m = line.match(re); if (m && m[1].length >= 4 && !/^(if|for|while|switch|catch|return|else)$/.test(m[1])) return { name: m[1], params: (m[2] || '').replace(/\s+/g, '') }; }
  return null;
}
