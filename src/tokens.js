// Stima token senza dipendenze (~3.5 caratteri/token per codice). I conteggi reali del provider
// (usage) sovrascrivono la stima nel report quando disponibili.
export const estimate = (s) => Math.ceil((s || '').length / 3.5);

export function fit(text, tokens) {
  const max = Math.max(0, Math.floor(tokens * 3.5));
  return text.length <= max ? text : text.slice(0, Math.max(0, max - 1)) + '…';
}

/** Estrae i paragrafi piu' rilevanti dai documenti in input (ranking a parole chiave), entro `budget` token. */
export function retrieveDocs(docs, keywords, budget) {
  if (!docs.length || budget <= 0) return '';
  const kw = [...new Set(keywords.map((k) => k.toLowerCase()).filter((k) => k.length > 2))];
  const scored = [];
  for (const d of docs) {
    for (const para of d.text.split(/\n{2,}/)) {
      const p = para.trim();
      if (p.length < 20) continue;
      const low = p.toLowerCase();
      let s = 0;
      for (const k of kw) if (low.includes(k)) s += 1 + k.length / 20;
      if (/must|never|do not|vietat|obblig|non |deve/i.test(p)) s += 0.5; // regole normative
      if (s > 0) scored.push({ s: s / Math.sqrt(p.length / 200 + 1), t: `[${d.name}] ${p.replace(/\s+/g, ' ')}` });
    }
  }
  scored.sort((a, b) => b.s - a.s);
  let used = 0; const out = [];
  for (const { t } of scored) {
    const c = estimate(t);
    if (used + c > budget) { const rest = budget - used; if (rest > 30) { out.push(fit(t, rest)); } break; }
    out.push(t); used += c;
  }
  return out.join('\n');
}
