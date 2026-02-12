# 🚀 TierAlba - Guida Deploy Completa

## Cosa hai ora (tutto pronto e corretto):

```
tieralba-backend/
├── server.js              ← Backend API + serve il frontend
├── public/
│   ├── index.html         ← Dashboard (collegata al backend)
│   └── login.html         ← Pagina login/registrazione
├── database.sql           ← Script per creare le tabelle
├── package.json           ← Dipendenze Node.js
├── .env.example           ← Template variabili d'ambiente
├── .gitignore             ← File da escludere da Git
└── GUIDA-DEPLOY.md        ← Questa guida
```

---

## STEP 1: Crea il Database su Supabase (5 minuti)

1. Vai su **https://supabase.com** e registrati (usa GitHub, è più veloce)
2. Clicca **"New Project"**
3. Compila:
   - **Name**: `tieralba-db`
   - **Database Password**: crea una password FORTE e **SALVALA** da qualche parte!
   - **Region**: `West EU (Ireland)` o il più vicino a te
   - **Plan**: Free
4. Aspetta 2-3 minuti che crei il progetto
5. Nel menu a sinistra clicca **"SQL Editor"**
6. Clicca **"New Query"**
7. Copia TUTTO il contenuto del file `database.sql` e incollalo
8. Clicca il bottone verde **"Run"**
9. Dovresti vedere **"Success"** ✅

### Prendi la stringa di connessione:
1. Menu a sinistra → ⚙️ **"Settings"**
2. Clicca **"Database"**
3. Scorri fino a **"Connection string"** → tab **"URI"**
4. Copia la stringa
5. Sostituisci `[YOUR-PASSWORD]` con la password che hai scelto

Esempio:
```
postgresql://postgres.xxxx:TuaPasswordForte@aws-0-eu-west-1.pooler.supabase.com:6543/postgres
```

**Conserva questa stringa, ti serve nello Step 3!**

---

## STEP 2: Carica su GitHub (5 minuti)

1. Vai su **github.com** → clicca **"+"** in alto a destra → **"New repository"**
2. Nome: `tieralba-backend`
3. Seleziona **Private**
4. **NON** aggiungere README o .gitignore (li hai già)
5. Clicca **"Create repository"**

Poi nel terminale del tuo computer (dentro la cartella del progetto):

```bash
cd tieralba-backend
git init
git add .
git commit -m "TierAlba v1.0 - backend + frontend"
git branch -M main
git remote add origin https://github.com/TUOUSERNAME/tieralba-backend.git
git push -u origin main
```

---

## STEP 3: Deploy su Railway (10 minuti)

1. Vai su **https://railway.app** → Login con GitHub
2. Clicca **"New Project"**
3. Seleziona **"Deploy from GitHub repo"**
4. Scegli il repo `tieralba-backend`
5. Railway inizia automaticamente il deploy

### Configura le variabili d'ambiente:
1. Nel progetto Railway, clicca sulla tab **"Variables"**
2. Aggiungi queste variabili una per una:

| Variabile | Valore |
|-----------|--------|
| `DATABASE_URL` | La stringa di Supabase dello Step 1 |
| `JWT_SECRET` | Una stringa casuale lunga (vai su uuidgenerator.net e copia il valore) |
| `NODE_ENV` | `production` |
| `FRONTEND_URL` | `*` (per ora accetta tutto, dopo restringi) |

3. Railway si riavvia automaticamente dopo ogni variabile

### Genera il dominio pubblico:
1. Tab **"Settings"**
2. Sezione **"Networking"** → clicca **"Generate Domain"**
3. Copia l'URL (es: `tieralba-backend-production.up.railway.app`)

---

## STEP 4: Testa che funzioni! (2 minuti)

### Test 1 - Health Check
Apri nel browser:
```
https://TUO-URL.railway.app/health
```
Deve rispondere con JSON: `{"status":"ok",...}`

### Test 2 - Pagina Login
Apri nel browser:
```
https://TUO-URL.railway.app/login.html
```
Deve mostrare la pagina di login TierAlba

### Test 3 - Registra un utente
1. Nella pagina login, clicca **"Registrati"**
2. Inserisci nome, email e password (min 8 caratteri)
3. Clicca **"Crea Account"**
4. Se funziona, verrai reindirizzato alla dashboard!

### Test 4 - Dashboard
Apri nel browser:
```
https://TUO-URL.railway.app/index.html
```
Devi essere loggato per vedere i dati. Se non sei loggato, ti rimanda al login.

---

## STEP 5: Aggiorna l'URL nel frontend (opzionale)

Se il tuo URL Railway è diverso da `tieralba-backend-production.up.railway.app`, devi aggiornarlo nei file:

In `public/index.html` e `public/login.html`, cerca questa riga:
```javascript
: 'https://tieralba-backend-production.up.railway.app';
```
E sostituisci con il tuo URL Railway.

Poi fai push su GitHub:
```bash
git add .
git commit -m "Update API URL"
git push
```
Railway si aggiorna automaticamente.

---

## ✅ FATTO!

La tua dashboard è online! I tuoi clienti possono:
1. Andare su `https://TUO-URL.railway.app/login.html` per registrarsi
2. Accedere alla dashboard con le loro credenziali
3. Vedere statistiche reali dal database
4. Usare il calcolatore di trading
5. Connettere i loro broker

---

## 🔧 Problemi Comuni

**"Application error" su Railway:**
- Controlla i logs nella tab "Deployments" su Railway
- Verifica che tutte le variabili siano configurate

**"Connection refused" al database:**
- Verifica che la password in DATABASE_URL sia corretta
- Controlla che Supabase sia attivo (free plan si mette in pausa dopo 1 settimana di inattività)

**CORS error nel browser:**
- Assicurati che `FRONTEND_URL` sia `*` oppure contenga il tuo dominio

**Login non funziona:**
- Apri la Console del browser (F12) per vedere gli errori
- Verifica che l'URL nell'HTML punti al backend Railway corretto
