// npm run doctor: diagnostica dell'installazione dell'SDK Copilot (stessi controlli del FE), da terminale.
import { sdkStatus } from './copilot.js';
const s = await sdkStatus();
console.log(`Node ${s.node} · progetto ${s.root}`);
console.log(s.installed ? `✔ SDK Copilot installato (v${s.version})` : `✕ ${s.error}\n  ${s.hint || ''}`);
for (const a of s.attempts || []) console.log(`  ${a.found ? '✔' : '✕'} ${a.where}${a.version ? ' v' + a.version : ''}${a.error ? ' — ' + a.error : ''}`);
process.exit(s.installed ? 0 : 1);
