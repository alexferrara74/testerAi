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

## Budget token: 2000 al MESE
Il limite è un **contatore mensile persistente** (`data/usage.json`, si azzera a inizio mese) mostrato in alto nel FE. Ogni chiamata viene dimensionata sul residuo e **non parte** se non ci sta; i token contati sono quelli reali del provider (stima se assenti).
- Default: mese 2000 · per analisi 400 · per chiamata 600 · output 40 · max 3 chiamate · documenti 60 (tutto modificabile da FE, incluso il consumo del mese: aggiorna o azzera).
- **La parte pesante è a 0 token**: regole statiche, simboli rimossi/cambiati, diff, checklist, report. L'AI è solo un filtro finale.
- All'AI **non** vanno i casi certi (chiavi, conflitti, file `.env`): solo ambigui (SQL concat, XSS, exec…), regressioni e pochi hunk rischiosi, come `id|file:riga|codice` (≤90 caratteri).
- Prompt di sistema ~40 token; risposta forzata a `{"b":[ids],"f":[ids],"a":[[file,da,a]]}` (solo id, niente motivazioni).
- **Domande**: il modello può chiedere un contesto (`a`): riceve max 20 righe e solo se la quota residua lo consente.
- **Documenti**: si inviano solo i paragrafi pertinenti, entro `docTokens`.
- **Cache** su disco: stessa richiesta = 0 token. Il test di connessione costa ~15 token e viene contato.
- Disattiva "Usa AI" per un'analisi completamente gratuita.

## Verifica CVE delle dipendenze (0 token)
Confronta manifest e lockfile tra base e branch (`package.json`+`package-lock.json`, `requirements.txt` con versioni `==`, `go.mod`) e interroga [OSV.dev](https://osv.dev) **solo per le dipendenze aggiunte o cambiate**. Per ogni CVE: gravità, versione che la corregge, voce in checklist e tabella nel report. Cache su disco (default 24h) per limitare le chiamate di rete. In azienda l'URL è modificabile da FE (mirror/proxy interno di OSV); se la rete non è raggiungibile l'analisi prosegue e la voce risulta "non verificata". Senza lockfile le versioni `^x.y` sono valutate sul valore minimo del range (segnalato).

## Sicurezza
Ascolta solo su 127.0.0.1, controllo Origin sulle API, `execFile` senza shell, ref git validati. La config è in `data/config.json` (0600, ignorata da git).

## Estensioni previste
Webhook/CI, regole per linguaggio.
