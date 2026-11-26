import zlib from 'node:zlib';
import { estimate, fit } from './tokens.js';

/* ====================================================================================
 * Documento di analisi -> regole compatte (100% locale, 0 token).
 * Si estraggono le regole/requisiti numerati (R1..Rn); all'AI vanno SOLO quelle pertinenti
 * alle modifiche rischiose, una volta sola, e il resto del documento resta sul PC.
 * ==================================================================================== */

/** Estrattore PDF best-effort senza dipendenze (stream FlateDecode + operatori di testo semplici). */
export function pdfToText(buf) {
  const s = buf.toString('latin1'); const out = [];
  const unesc = (t) => t.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', b: '', f: '' }[c] ?? (/^[0-7]/.test(c) ? String.fromCharCode(parseInt(c, 8)) : c)));
  const hex = (h) => { const b = Buffer.from(h.replace(/\s/g, '').padEnd(h.length + (h.length % 2), '0'), 'hex'); return b[0] === 0xfe && b[1] === 0xff ? b.subarray(2).swap16().toString('utf16le') : b.toString('latin1'); };
  const re = /stream\r?\n([\s\S]*?)\r?\nendstream/g; let m;
  while ((m = re.exec(s))) {
    const raw = Buffer.from(m[1], 'latin1'); let txt;
    try { txt = zlib.inflateSync(raw).toString('latin1'); } catch { txt = m[1]; }
    if (!/\bBT\b/.test(txt)) continue;
    for (const bt of txt.match(/BT[\s\S]*?ET/g) || []) {
      let line = '';
      for (const t of bt.matchAll(/\[((?:\\.|[^\]\\])*)\]\s*TJ|\(((?:\\.|[^\\)])*)\)\s*(?:Tj|'|")|<([0-9a-fA-F\s]+)>\s*Tj|\bT\*|\bTd\b|\bTD\b|\bTm\b/g)) {
        if (t[1] !== undefined) line += [...t[1].matchAll(/\(((?:\\.|[^\\)])*)\)|<([0-9a-fA-F\s]+)>|(-?\d+(?:\.\d+)?)/g)].map((p) => (p[1] !== undefined ? unesc(p[1]) : p[2] !== undefined ? hex(p[2]) : Number(p[3]) < -200 ? ' ' : '')).join('');
        else if (t[2] !== undefined) line += unesc(t[2]);
        else if (t[3] !== undefined) line += hex(t[3]);
        else line += '\n';
      }
      out.push(line);
    }
  }
  const text = out.join('\n').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const letters = (text.match(/[A-Za-zÀ-ÿ]/g) || []).length;
  const ok = text.length > 20 && letters / Math.max(1, text.length) > 0.5;
  return { text: ok ? text : '', warning: ok ? '' : 'PDF non leggibile (scansione o font incorporati): esportalo in .md o .txt e ricaricalo.' };
}

const CUE = /\b(deve|devono|dovr\w+|vietat\w+|non\s+(?:deve|devono|può|possono|è\s+consentit\w+)|obbligator\w+|sempre|mai|must|shall|should|never|always|required|forbidden|do\s+not|don't|given|when|then)\b/i;
const SECTION_RULES = /requisit|criteri|regol|rules|acceptance|vincol|non funzional|sicurezz|security|constraint/i;
const STOP = new Set(['questo', 'questa', 'quando', 'sempre', 'devono', 'deve', 'della', 'delle', 'degli', 'nella', 'nelle', 'dello', 'with', 'that', 'this', 'from', 'have', 'must', 'should', 'shall', 'sono', 'essere', 'viene', 'tutti', 'ogni', 'come', 'anche']);
export const words = (t) => [...new Set((t.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').match(/[a-z][a-z0-9_]{3,}/g) || []).filter((w) => !STOP.has(w)))];

/** documents: [{name,text}] -> {rules:[{id,text,kw}], stats} */
export function distill(documents) {
  const rules = []; const seen = new Set();
  const push = (sec, t, name) => {
    let x = t.replace(/^[\s\-*•·>\d.)\]\[xX✓☐☑]+/, '').replace(/\s+/g, ' ').replace(/[*_`]/g, '').trim();
    if (x.length < 25 || x.length > 600) return; // titoli e frammenti brevi non sono regole
    x = (sec ? `${sec.slice(0, 28)}: ` : '') + x; x = x.length > 170 ? x.slice(0, 167) + '…' : x;
    const key = x.toLowerCase().replace(/\W+/g, ''); if (seen.has(key)) return; seen.add(key);
    rules.push({ id: 'R' + (rules.length + 1), text: x, kw: words(x), src: name });
  };
  for (const d of documents) {
    let sec = '', inCode = false;
    for (const raw of String(d.text || '').split('\n')) {
      const t = raw.trim(); if (!t) continue;
      if (/^```/.test(t)) { inCode = !inCode; continue; } if (inCode) continue;
      const h = t.match(/^#{1,6}\s+(.*)$/) || (/^\d+(\.\d+)*[.)]?\s+[A-ZÀ-Ý][^.]{2,60}$/.test(t) && !/[.;:]$/.test(t) ? [0, t.replace(/^\d+(\.\d+)*[.)]?\s+/, '')] : null);
      if (h) { sec = h[1].replace(/[*_`]/g, '').trim(); continue; }
      const bullet = /^([-*•·]|\d+[.)]|\[[ xX]\])\s+/.test(t);
      if (bullet && (CUE.test(t) || SECTION_RULES.test(sec) || t.length >= 25)) push(sec, t, d.name);
      else if (CUE.test(t)) for (const sent of t.split(/(?<=[.;!?])\s+/)) if (CUE.test(sent)) push(sec, sent, d.name);
      if (rules.length >= 300) break;
    }
  }
  return { rules, stats: { rules: rules.length, docs: documents.length } };
}

const DOMAIN = {
  'reg-auth': 'auth autenticazione autorizzazione permessi ruolo accesso login sessione token sicurezza', 'reg-guard': 'validazione controllo input verifica null errore parametri', 'reg-err': 'errore eccezione gestione log fallback',
  'reg-op': 'condizione soglia limite confronto regola', 'reg-const': 'soglia limite valore configurazione costante', 'reg-test': 'test copertura', 'reg-await': 'asincrono concorrenza race attesa',
  'logic-db': 'database query dati transazione sql persistenza', 'logic-io': 'rete chiamata esterna file integrazione api', 'logic-sec': 'sicurezza auth token password crittografia', 'logic-input': 'input validazione utente sanificazione',
  'logic-cfg': 'configurazione soglia timeout limite', 'logic-env': 'configurazione ambiente variabili', 'reg-del': 'eliminazione rimozione compatibilita', 'reg-res': 'risorse connessioni leak rilascio',
};
/** Seleziona le regole pertinenti alle modifiche (ranking per sovrapposizione di parole) entro `tokens`. Assegna change.rules. */
export function pickRules(rules, changes, tokens) {
  if (!rules.length || tokens < 20) { changes.forEach((c) => { c.rules = []; }); return []; }
  const hits = new Map();
  for (const c of changes) {
    const cw = new Set([...words(c.where), ...words(c.route || ''), ...c.tags.flatMap((t) => words(DOMAIN[t] || t)), ...(c.idents || [])]);
    const scored = rules.map((r) => { let s = 0; for (const k of r.kw) if (cw.has(k)) s += 1 + k.length / 12; if (CUE.test(r.text)) s += 0.4; return { r, s }; }).filter((x) => x.s >= 1.5).sort((a, b) => b.s - a.s).slice(0, 2);
    c.rules = scored.map((x) => x.r.id);
    for (const { r, s } of scored) hits.set(r.id, (hits.get(r.id) || 0) + s);
  }
  const ranked = [...hits.entries()].sort((a, b) => b[1] - a[1]).map(([id]) => rules.find((r) => r.id === id));
  const out = []; let used = 0;
  for (const r of ranked) { const c = estimate(`${r.id} ${r.text}`) + 1; if (used + c > tokens) continue; out.push(r); used += c; }
  const keep = new Set(out.map((r) => r.id)); changes.forEach((c) => { c.rules = c.rules.filter((id) => keep.has(id)); });
  return out;
}

export const briefText = (note, tokens) => fit(String(note || '').replace(/\s+/g, ' ').trim(), tokens);
