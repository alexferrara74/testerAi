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
Il limite è un **contatore mensile persistente** (`~/.testerai/usage.json`, si azzera a inizio mese) mostrato in alto nel FE. Ogni chiamata viene dimensionata sul residuo e **non parte** se non ci sta; i token contati sono quelli reali del provider (stima se assenti).
- Default: mese 2000 · per analisi 400 · per chiamata 600 · output 40 · max 3 chiamate · documenti 60 (tutto modificabile da FE, incluso il consumo del mese: aggiorna o azzera).
- **La parte pesante è a 0 token**: regole statiche, simboli rimossi/cambiati, diff, checklist, report. L'AI è solo un filtro finale.
- All'AI **non** vanno i casi certi (chiavi, conflitti, file `.env`): solo ambigui (SQL concat, XSS, exec…), regressioni e pochi hunk rischiosi, come `id|file:riga|codice` (≤90 caratteri).
- Prompt di sistema ~40 token; risposta forzata a `{"b":[ids],"f":[ids],"a":[[file,da,a]]}` (solo id, niente motivazioni).
- **Domande**: il modello può chiedere un contesto (`a`): riceve max 20 righe e solo se la quota residua lo consente.
- **Documenti**: si inviano solo i paragrafi pertinenti, entro `docTokens`.
- **Cache** su disco: stessa richiesta = 0 token. Il test di connessione costa ~15 token e viene contato.
- Disattiva "Usa AI" per un'analisi completamente gratuita.

## Revisione riga per riga (checklist decisionale, 0 token)
Ogni hunk di ogni commit diventa una voce della scheda **Revisione**, classificata staticamente:
- **Logica inserita**: nuove condizioni, cicli, asincronia, gestione errori, I/O, accesso ai dati, sicurezza/autorizzazione, input non fidato, soglie/config, nuove funzioni.
- **Possibili regressioni**: controllo/validazione rimosso, gestione errori o controlli di accesso rimossi, `await` o rilascio risorse tolti, operatore/soglia modificati (`<`→`<=`, `&&`→`||`), test indeboliti o saltati, blocchi eliminati, file/test cancellati.
- **Livello**: *Problema* (da fixare o accettare esplicitamente), *Da verificare*, *Banale* (solo commenti/formattazione/riordino import).

Per ogni voce scegli **«Sono consapevole»** oppure **«Da fixare»** (nel codice). Poi committa il fix e premi **«Ri-analizza»**: le decisioni sono salvate per *contenuto* (non per commit/riga, quindi sopravvivono a rebase e ri-analisi); le voci «da fixare» che non risultano più nel branch finiscono tra i **fix verificati**; le modifiche riscritte o annullate in un commit successivo sono escluse dalle decisioni. «Tutto ok» per commit e «Banali → consapevole» accelerano la revisione; l'elenco «Da fixare» si copia come TODO e compare nell'export Markdown. La checklist ha la voce *Revisione di ogni modifica* che diventa verde solo quando tutto è deciso e nessun problema è bloccante.

## Verifica CVE delle dipendenze (0 token)
Confronta manifest e lockfile tra base e branch (`package.json`+`package-lock.json`, `requirements.txt` con versioni `==`, `go.mod`) e interroga [OSV.dev](https://osv.dev) **solo per le dipendenze aggiunte o cambiate**. Per ogni CVE: gravità, versione che la corregge, voce in checklist e tabella nel report. Cache su disco (default 24h) per limitare le chiamate di rete. In azienda l'URL è modificabile da FE (mirror/proxy interno di OSV); se la rete non è raggiungibile l'analisi prosegue e la voce risulta "non verificata". Senza lockfile le versioni `^x.y` sono valutate sul valore minimo del range (segnalato).

## Privacy: il codice non esce dal PC
- **Un solo punto di uscita** (`src/privacy.js`): ogni richiesta di rete passa da `guardedFetch`, che consente **solo** l'host dell'AI che configuri tu (e, se la abiliti, quello di OSV per le CVE: solo nome+versione dei pacchetti). Qualsiasi altro host, redirect o http verso host non locali è bloccato e registrato.
- **Modalità offline**: blocca tutto; l'analisi è comunque completa (0 token).
- **Segreti oscurati prima dell'invio** all'AI (chiavi, token, password, Bearer, email, IP, blob lunghi). Opzione `sendCode=false`: all'AI arrivano solo nome file e tipo di segnalazione, mai righe di codice.
- **CVE disattivata di default** (opt-in).
- **Registro** delle connessioni in uscita (host, scopo, byte, mai contenuto) visibile in Configurazione.
- **Dati fuori dal repo**: report, cache, quote e chiavi in `~/.testerai` (0600/0700), non nella cartella del progetto né in quella analizzata. Nessun telemetry, nessuna CDN: il FE è tutto locale.
- **git** viene eseguito con protocolli remoti disabilitati (nessun fetch/push); il server accetta solo Host locali (anti DNS-rebinding).
- Nota: i **documenti di contesto** che carichi, e i frammenti selezionati, vanno all'AI che hai configurato: sono sotto il tuo controllo.

## Sicurezza
Ascolta solo su 127.0.0.1, controllo Origin sulle API, `execFile` senza shell, ref git validati. La config è in `data/config.json` (0600, ignorata da git).

## Estensioni previste
Webhook/CI, regole per linguaggio.
