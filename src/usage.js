import fs from 'node:fs';
import path from 'node:path';
import { DATA } from './config.js';

// Contatore mensile persistente dei token consumati: e' il vero limite aziendale (es. 2000/mese).
const FILE = () => path.join(DATA, 'usage.json');
const monthKey = () => new Date().toISOString().slice(0, 7);

export function readUsage() {
  let u = {};
  try { u = JSON.parse(fs.readFileSync(FILE(), 'utf8')); } catch { /* nuovo */ }
  if (u.month !== monthKey()) u = { month: monthKey(), used: 0, calls: 0, log: [] };
  return u;
}
export function remaining(monthly) { return Math.max(0, monthly - readUsage().used); }
export function record(tokens, note) {
  const u = readUsage();
  u.used += tokens; u.calls++;
  u.log = [...(u.log || []), { t: new Date().toISOString(), tokens, note }].slice(-50);
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(FILE(), JSON.stringify(u));
  return u;
}

// Correzione manuale (es. allineare al consumo reale dal portale del provider, o azzerare).
export function setUsed(tokens) {
  const u = readUsage();
  u.used = Math.max(0, Math.round(Number(tokens) || 0));
  u.log = [...(u.log || []), { t: new Date().toISOString(), tokens: 0, note: `impostato manualmente a ${u.used}` }].slice(-50);
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(FILE(), JSON.stringify(u));
  return u;
}
