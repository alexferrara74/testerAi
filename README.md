# testerAi

Microservizio (BE Node + FE web, **zero dipendenze**) che analizza un branch git rispetto al branch da cui è stato staccato: vulnerabilità, errori, regressioni, elenco completo delle modifiche, report e checklist.

```bash
npm start            # http://127.0.0.1:4377  (PORT / HOST per cambiare)
npm test
```

## Flusso
1. **Analisi** → "Sfoglia…" per scegliere la cartella del repo, scegli branch e base (la base è dedotta: il branch con merge-base più vicino).
2. Opzionale: carica documenti (requisiti/linee guida) o incolla regole.
3. **Report**: riepilogo, checklist (con spunte salvate), ogni file modificato con righe +/- rispetto alla base, commit, segnalazioni per categoria; export Markdown.
4. **Configurazione AI**: provider (OpenAI-compatibile = Copilot/Azure/gateway aziendale, Anthropic, Ollama), URL, modello, key, header auth/extra, api-version e budget token. Test connessione incluso. La key può essere passata via `TESTERAI_API_KEY`.

## Come consuma pochi token (limite 2k/chiamata)
- **Livello 0 (0 token)**: regole statiche sulle sole righe aggiunte (segreti, injection, XSS, TLS, eval, conflitti, test `.only`…), simboli rimossi/cambiati ancora referenziati (`git grep`), test non toccati, lockfile, commit, branch indietro, working tree sporco.
- **Livello 1 (AI)**: all'AI vanno solo le segnalazioni medium+ e gli hunk rischiosi, in forma compatta `id|file:riga|codice`, ordinati per priorità e impacchettati in batch che stanno nel budget (`contesto − output − system − documenti`). Risposta forzata in JSON minimo (`bug`/`fp`/`ask`).
- **Domande**: il modello può chiedere `ask:[file,da,a]`; il tool risponde con uno snippet (max 40 righe, tagliato al budget) invece di inviare file interi.
- **Documenti**: ranking per parole chiave (nomi file/commit), si inviano solo i paragrafi pertinenti entro `docTokens`.
- **Cache** su disco delle risposte (re-run identico = 0 token), tetto `maxCalls`, guardia che tronca ogni prompt oltre il limite. Il report mostra token stimati/reali, chiamate e elementi non inviati.

## Sicurezza
Ascolta solo su 127.0.0.1, controllo Origin sulle API, `execFile` senza shell, ref git validati. La config è in `data/config.json` (0600, ignorata da git).

## Estensioni previste
Webhook/CI, regole per linguaggio, analisi per singolo commit, dipendenze vs advisory CVE.
