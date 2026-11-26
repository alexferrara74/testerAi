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

## Collegare l'AI (Configurazione → Preset rapido)
- **GitHub Copilot**: provider `copilot`. Scambia il tuo token GitHub (OAuth del login Copilot, `ghu_…`) con un token Copilot di breve durata (in cache) e chiama `api.githubcopilot.com` (Business/Enterprise: `api.business.` / `api.enterprise.githubcopilot.com`). Puoi incollare il token o spuntare «usa il login già presente», che legge `~/.config/github-copilot/` sul tuo PC (il token non passa mai dal browser). Integrazione non ufficiale: verifica che policy e ToS aziendali la consentano.
- **GitHub Models** (ufficiale): preset OpenAI-compatibile con un PAT con permesso `models:read`.
- Azure OpenAI, OpenAI, Anthropic Claude, Ollama/locale, qualsiasi gateway OpenAI-compatibile.
- Il guard di rete consente solo gli host del provider scelto (per Copilot anche l'host di scambio token, che riceve solo il token GitHub).

### Rete aziendale: proxy, certificati, «fetch failed»
Il tool usa un proprio trasporto di rete (non `fetch`, che ignora i proxy e nasconde la causa). Supporta **proxy HTTP/HTTPS con tunnel CONNECT** (campo «Proxy aziendale» oppure `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` dell'ambiente) e un **file CA aziendale** (campo «File CA» o `NODE_EXTRA_CA_CERTS`) quando la rete ispeziona TLS; la verifica dei certificati non viene mai disattivata. Il pulsante **Test connessione** fa una diagnostica a passi (token → scambio con GitHub → chiamata al modello) e mostra l'errore reale con un suggerimento (DNS, firewall/proxy, certificato, licenza). Nota: leggere il token Copilot dal PC è un'operazione su file locale, mentre scambio token e chiamata richiedono rete verso GitHub: sono due cose distinte.

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

## Cosa viene analizzato (e cosa no)
Solo i **commit del branch** (dal punto di stacco dal branch base) e le **modifiche locali non committate** («in pancia»: staged, unstaged e file nuovi, come voce `locale`, solo se sei sul branch analizzato). Il resto del codice non viene analizzato né inviato all'AI: viene solo *interrogato localmente* (`git grep`) per capire chi usa ciò che hai toccato; all'AI arriva soltanto il piccolo perimetro descritto qui sotto.

## Impatto fino all'endpoint
Per ogni modifica fatta in un punto **già esistente** il tool trova la funzione che la contiene, risale i chiamanti (fino a `maxDepth` livelli) e si ferma agli **endpoint**: route Express/Fastify/Koa, Flask/FastAPI, Spring, NestJS, Go (gin/net/http), file-route Next.js, eventi e job pianificati. Per ciascuno mostra la catena `funzione → … → POST /login`, i **chiamanti che il tuo branch non ha toccato** (rischio regressione), i test che nominano la funzione, e un livello di rischio che combina il tipo di modifica (controllo rimosso, operatore cambiato…) con quanti endpoint raggiunge. Le modifiche gravi che arrivano a un endpoint diventano segnalazioni `REG-IMPACT` (e voce di checklist). 
**Revisione AI a contesto chiuso.** Se l'AI è attiva, per le modifiche più rischiose il tool costruisce un *pacchetto* e basta: la funzione modificata (diff + corpo), le firme dei metodi che chiama, i chiamanti diretti (riga di chiamata) e la catena fino all'endpoint, tagliato per stare nel budget residuo. L'AI non ha strumenti e non vede il repository: risponde `{"v":"ok|risk|unsure","why":…}`. Può chiedere **un solo simbolo, e solo uno presente nel pacchetto** (un callee o un chiamante): il tool risponde con il corpo di quella funzione (max 25 righe); qualsiasi altra richiesta viene ignorata. Con «solo metadati» (`sendCode=false`) il pacchetto contiene solo nomi, percorso ed etichette: nessun codice. Il verdetto diventa `ok` (segnalazione declassata), `risk` (confermata) o `incerto`. Il costo rientra nelle stesse quote mensile/per analisi: una modifica pesa circa 150–300 token, quindi con 2000/mese conviene alzare «Max per analisi» a ~800 se vuoi più di un pacchetto per analisi.

Limiti: analisi testuale, non risolve dispatch dinamico/DI/riflessione né il prefisso con cui un router è montato; i nomi troppo generici (`get`, `run`…) fanno risalita parziale (segnalato).

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
