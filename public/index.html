// ============================================
// TIERALBA BACKEND API
// ============================================
// Questo è il server principale che gestisce:
// - Autenticazione utenti (login/register)
// - Gestione trade
// - Statistiche dashboard
// - Connessione broker MetaTrader
// ============================================

require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Stripe (optional - only if STRIPE_SECRET_KEY is set)
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

// ============================================
// CONFIGURAZIONE SERVER
// ============================================

const app = express();
const port = process.env.PORT || 3000;

// Connessione al database PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test connessione database
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Errore connessione database:', err.stack);
  } else {
    console.log('✅ Database connesso con successo');
    release();
  }
});

// ============================================
// MIDDLEWARE (funzioni che processano ogni richiesta)
// ============================================

// Helmet: protezione base contro attacchi comuni
// Configurato per permettere script inline nelle pagine frontend
app.use(helmet({
  contentSecurityPolicy: false
}));

// CORS: permette al frontend di comunicare con il backend
const allowedOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(null, true); // In production you can restrict this
  },
  credentials: true
}));

// Stripe webhook needs raw body - must be before express.json()
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });
  
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const customerEmail = session.customer_email || session.customer_details?.email;
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        
        // Get subscription to determine plan
        let plan = 'standard';
        if (subscriptionId) {
          const sub = await stripe.subscriptions.retrieve(subscriptionId);
          const priceId = sub.items.data[0]?.price?.id;
          // Map price IDs to plans
          const proPriceIds = (process.env.STRIPE_PRO_PRICE_IDS || '').split(',');
          if (proPriceIds.includes(priceId)) plan = 'pro';
        }
        
        // Update user
        if (customerEmail) {
          await pool.query(
            'UPDATE users SET plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3 WHERE LOWER(email) = LOWER($4)',
            [plan, customerId, subscriptionId, customerEmail]
          );
          console.log(`✅ User ${customerEmail} upgraded to ${plan}`);
        }
        break;
      }
      
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status;
        if (status === 'active') {
          const priceId = sub.items.data[0]?.price?.id;
          const proPriceIds = (process.env.STRIPE_PRO_PRICE_IDS || '').split(',');
          const plan = proPriceIds.includes(priceId) ? 'pro' : 'standard';
          await pool.query(
            'UPDATE users SET plan = $1 WHERE stripe_subscription_id = $2',
            [plan, sub.id]
          );
        }
        break;
      }
      
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        await pool.query(
          'UPDATE users SET plan = $1 WHERE stripe_subscription_id = $2',
          ['free', sub.id]
        );
        console.log(`⚠️ Subscription ${sub.id} cancelled - downgraded to free`);
        break;
      }
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }
  
  res.json({ received: true });
});

// Body parser: permette di leggere JSON nelle richieste
app.use(express.json());

// Serve frontend static files (login.html, index.html)
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting: previene spam/attacchi
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 100, // max 100 richieste per IP
  message: 'Troppe richieste, riprova tra 15 minuti'
});
app.use('/api/', limiter);

// Logging richieste (utile per debug)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ============================================
// MIDDLEWARE AUTENTICAZIONE
// ============================================
// Questa funzione verifica che l'utente sia loggato
// controllando il token JWT

const authenticateToken = (req, res, next) => {
  // Prende il token dall'header Authorization
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"
  
  if (!token) {
    return res.status(401).json({ 
      error: 'Accesso negato. Token non fornito.' 
    });
  }
  
  // Verifica che il token sia valido
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        error: 'Token non valido o scaduto' 
      });
    }
    
    // Salva l'ID utente nella richiesta per usarlo dopo
    req.userId = user.userId;
    next();
  });
};

// ============================================
// ENDPOINT: SALUTE DEL SERVER
// ============================================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'TierAlba API'
  });
});

// ============================================
// ENDPOINT: AUTENTICAZIONE
// ============================================

// REGISTRAZIONE NUOVO UTENTE
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, fullName } = req.body;
    const userName = name || fullName || '';
    
    // Validazione input
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email e password sono obbligatori' 
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ 
        error: 'La password deve essere di almeno 8 caratteri' 
      });
    }
    
    // Controlla se l'email esiste già
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        error: 'Email già registrata' 
      });
    }
    
    // Hash della password (crittografia)
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Crea l'utente nel database
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name, created_at',
      [email.toLowerCase(), passwordHash, userName]
    );
    
    const user = result.rows[0];
    
    // Genera token JWT (valido 7 giorni)
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({ 
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        plan: 'free'
      },
      token 
    });
    
  } catch (error) {
    console.error('Errore registrazione:', error);
    res.status(500).json({ 
      error: 'Errore durante la registrazione' 
    });
  }
});

// LOGIN UTENTE
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email e password sono obbligatori' 
      });
    }
    
    // Trova utente nel database
    const result = await pool.query(
      'SELECT id, email, name, password_hash, plan FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Email o password non corretti' 
      });
    }
    
    const user = result.rows[0];
    
    // Verifica password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ 
        error: 'Email o password non corretti' 
      });
    }
    
    // Genera token
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        plan: user.plan || 'free'
      },
      token
    });
    
  } catch (error) {
    console.error('Errore login:', error);
    res.status(500).json({ 
      error: 'Errore durante il login' 
    });
  }
});

// VERIFICA TOKEN (utile per il frontend)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, plan, created_at FROM users WHERE id = $1',
      [req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Errore verifica utente:', error);
    res.status(500).json({ error: 'Errore server' });
  }
});

// ============================================
// ENDPOINT: STATISTICHE DASHBOARD
// ============================================

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    
    // Ottieni l'equity più recente
    const equityResult = await pool.query(
      'SELECT equity FROM equity_snapshots WHERE user_id = $1 ORDER BY recorded_at DESC LIMIT 1',
      [userId]
    );
    
    // Calcola statistiche dai trade
    const statsResult = await pool.query(`
      SELECT 
        COUNT(*) as total_trades,
        SUM(CASE WHEN profit > 0 THEN 1 ELSE 0 END) as winning_trades,
        SUM(CASE WHEN profit < 0 THEN 1 ELSE 0 END) as losing_trades,
        SUM(profit) as total_profit,
        AVG(profit) as avg_profit,
        MAX(profit) as best_trade,
        MIN(profit) as worst_trade
      FROM trades 
      WHERE user_id = $1 AND closed_at IS NOT NULL
    `, [userId]);
    
    const stats = statsResult.rows[0];
    
    // Calcola win rate
    const totalTrades = parseInt(stats.total_trades) || 0;
    const winningTrades = parseInt(stats.winning_trades) || 0;
    const winRate = totalTrades > 0 ? (winningTrades / totalTrades * 100) : 0;
    
    // Calcola profit factor
    const winningSum = await pool.query(
      'SELECT SUM(profit) as sum FROM trades WHERE user_id = $1 AND profit > 0',
      [userId]
    );
    const losingSum = await pool.query(
      'SELECT SUM(ABS(profit)) as sum FROM trades WHERE user_id = $1 AND profit < 0',
      [userId]
    );
    
    const profitFactor = losingSum.rows[0].sum > 0 
      ? (winningSum.rows[0].sum / losingSum.rows[0].sum) 
      : 0;
    
    res.json({
      equity: parseFloat(equityResult.rows[0]?.equity) || 0,
      totalTrades,
      winningTrades,
      losingTrades: parseInt(stats.losing_trades) || 0,
      winRate: parseFloat(winRate.toFixed(1)),
      profitFactor: parseFloat(profitFactor.toFixed(2)),
      totalProfit: parseFloat(stats.total_profit) || 0,
      avgProfit: parseFloat(stats.avg_profit) || 0,
      bestTrade: parseFloat(stats.best_trade) || 0,
      worstTrade: parseFloat(stats.worst_trade) || 0
    });
    
  } catch (error) {
    console.error('Errore statistiche:', error);
    res.status(500).json({ error: 'Errore recupero statistiche' });
  }
});

// ============================================
// ENDPOINT: GESTIONE TRADE
// ============================================

// LISTA TRADE
app.get('/api/trades', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    const result = await pool.query(
      `SELECT * FROM trades 
       WHERE user_id = $1 
       ORDER BY closed_at DESC NULLS FIRST
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    
    // Conta totale trade
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM trades WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      trades: result.rows,
      total: parseInt(countResult.rows[0].count),
      limit,
      offset
    });
    
  } catch (error) {
    console.error('Errore recupero trade:', error);
    res.status(500).json({ error: 'Errore recupero trade' });
  }
});

// AGGIUNGI TRADE MANUALMENTE
app.post('/api/trades', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { symbol, type, lots, entryPrice, exitPrice, openedAt, closedAt } = req.body;
    
    // Validazione
    if (!symbol || !type || !lots || !entryPrice) {
      return res.status(400).json({ 
        error: 'Campi obbligatori: symbol, type, lots, entryPrice' 
      });
    }
    
    // Calcola profit (semplificato - da adattare per simbolo)
    let profit = 0;
    if (exitPrice) {
      const pipValue = 10; // Valore pip standard
      const pips = (exitPrice - entryPrice) * 10000;
      profit = pips * lots * pipValue * (type.toLowerCase() === 'buy' ? 1 : -1);
    }
    
    const result = await pool.query(
      `INSERT INTO trades (user_id, symbol, type, lots, entry_price, exit_price, profit, opened_at, closed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [userId, symbol, type.toUpperCase(), lots, entryPrice, exitPrice, profit, openedAt, closedAt]
    );
    
    res.status(201).json({ 
      success: true,
      trade: result.rows[0] 
    });
    
  } catch (error) {
    console.error('Errore aggiunta trade:', error);
    res.status(500).json({ error: 'Errore aggiunta trade' });
  }
});

// ELIMINA TRADE
app.delete('/api/trades/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const tradeId = req.params.id;
    
    const result = await pool.query(
      'DELETE FROM trades WHERE id = $1 AND user_id = $2 RETURNING id',
      [tradeId, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Trade non trovato' });
    }
    
    res.json({ success: true, message: 'Trade eliminato' });
    
  } catch (error) {
    console.error('Errore eliminazione trade:', error);
    res.status(500).json({ error: 'Errore eliminazione trade' });
  }
});

// ============================================
// ENDPOINT: STORICO EQUITY
// ============================================

app.get('/api/equity-history', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const days = parseInt(req.query.days) || 30;
    
    const result = await pool.query(
      `SELECT equity, recorded_at 
       FROM equity_snapshots 
       WHERE user_id = $1 
       AND recorded_at > NOW() - INTERVAL '1 day' * $2
       ORDER BY recorded_at ASC`,
      [userId, days]
    );
    
    res.json({ 
      history: result.rows.map(row => ({
        equity: parseFloat(row.equity),
        date: row.recorded_at
      }))
    });
    
  } catch (error) {
    console.error('Errore storico equity:', error);
    res.status(500).json({ error: 'Errore recupero storico' });
  }
});

// AGGIUNGI SNAPSHOT EQUITY
app.post('/api/equity-snapshot', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { equity } = req.body;
    
    if (!equity || isNaN(equity)) {
      return res.status(400).json({ error: 'Equity non valido' });
    }
    
    const result = await pool.query(
      'INSERT INTO equity_snapshots (user_id, equity) VALUES ($1, $2) RETURNING *',
      [userId, equity]
    );
    
    res.status(201).json({ 
      success: true,
      snapshot: result.rows[0] 
    });
    
  } catch (error) {
    console.error('Errore snapshot equity:', error);
    res.status(500).json({ error: 'Errore salvataggio equity' });
  }
});

// ============================================
// ENDPOINT: CONNESSIONE BROKER
// ============================================

app.post('/api/broker/connect', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { platform, apiKey, apiSecret, accountNumber } = req.body;
    
    // Validazione
    if (!platform || !apiKey || !apiSecret || !accountNumber) {
      return res.status(400).json({ 
        error: 'Tutti i campi sono obbligatori' 
      });
    }
    
    if (!['mt4', 'mt5'].includes(platform.toLowerCase())) {
      return res.status(400).json({ 
        error: 'Piattaforma non supportata. Usa MT4 o MT5' 
      });
    }
    
    // TODO: Qui dovresti validare le credenziali con l'API MetaTrader
    // TODO: Cripta apiKey e apiSecret prima di salvare
    
    // Controlla se esiste già una connessione attiva
    const existing = await pool.query(
      'SELECT id FROM broker_connections WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    
    if (existing.rows.length > 0) {
      // Disattiva la vecchia connessione
      await pool.query(
        'UPDATE broker_connections SET is_active = false WHERE user_id = $1',
        [userId]
      );
    }
    
    // Salva nuova connessione
    const result = await pool.query(
      `INSERT INTO broker_connections (user_id, platform, api_key_encrypted, api_secret_encrypted, account_number, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, platform, account_number, created_at`,
      [userId, platform.toLowerCase(), apiKey, apiSecret, accountNumber]
    );
    
    res.status(201).json({ 
      success: true,
      message: 'Broker connesso con successo',
      connection: result.rows[0]
    });
    
  } catch (error) {
    console.error('Errore connessione broker:', error);
    res.status(500).json({ error: 'Errore connessione broker' });
  }
});

// OTTIENI CONNESSIONI BROKER
app.get('/api/broker/connections', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    
    const result = await pool.query(
      `SELECT id, platform, account_number, is_active, created_at 
       FROM broker_connections 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    res.json({ connections: result.rows });
    
  } catch (error) {
    console.error('Errore recupero connessioni:', error);
    res.status(500).json({ error: 'Errore recupero connessioni' });
  }
});

// ============================================
// SERVE FRONTEND per route non-API
// ============================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ============================================
// GESTIONE ERRORI 404 (solo per API)
// ============================================

app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint non trovato',
    path: req.path 
  });
});

// ============================================
// AVVIO SERVER
// ============================================

// ============================================
// ENDPOINT: REFUND REQUESTS
// ============================================

app.post('/api/refund/request', authenticateToken, async (req, res) => {
  try {
    const { reason, details } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason is required' });

    const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    // Check for existing pending request
    const existing = await pool.query(
      'SELECT id FROM refund_requests WHERE user_id = $1 AND status = $2',
      [req.userId, 'pending']
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'You already have a pending refund request' });
    }

    await pool.query(
      'INSERT INTO refund_requests (user_id, email, reason, details) VALUES ($1, $2, $3, $4)',
      [req.userId, userResult.rows[0].email, reason, details || '']
    );

    res.json({ success: true, message: 'Refund request submitted successfully' });
  } catch (error) {
    console.error('Refund request error:', error);
    res.status(500).json({ error: 'Failed to submit refund request' });
  }
});

app.get('/api/refund/status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, reason, status, created_at, reviewed_at FROM refund_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5',
      [req.userId]
    );
    res.json({ requests: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT: STRIPE SUBSCRIPTION
// ============================================

// Create checkout session
app.post('/api/stripe/checkout', authenticateToken, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });
  
  try {
    const { priceId } = req.body;
    if (!priceId) return res.status(400).json({ error: 'Price ID required' });
    
    // Get user email
    const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer_email: userResult.rows[0].email,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba-backend-production-f18f.up.railway.app'}/index.html?upgrade=success`,
      cancel_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba-backend-production-f18f.up.railway.app'}/index.html?upgrade=cancelled`,
      metadata: { userId: req.userId.toString() }
    });
    
    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Get user plan
app.get('/api/user/plan', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT plan, stripe_customer_id, stripe_subscription_id FROM users WHERE id = $1',
      [req.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ plan: result.rows[0].plan || 'free' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Stripe billing portal (manage subscription)
app.post('/api/stripe/portal', authenticateToken, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Stripe not configured' });
  
  try {
    const result = await pool.query('SELECT stripe_customer_id FROM users WHERE id = $1', [req.userId]);
    if (!result.rows[0]?.stripe_customer_id) {
      return res.status(400).json({ error: 'No subscription found' });
    }
    
    const session = await stripe.billingPortal.sessions.create({
      customer: result.rows[0].stripe_customer_id,
      return_url: `${req.headers.origin || 'https://tieralba-backend-production-f18f.up.railway.app'}/index.html`
    });
    
    res.json({ url: session.url });
  } catch (error) {
    console.error('Portal error:', error);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// ============================================
// AVVIO SERVER
// ============================================

app.listen(port, () => {
  console.log('=================================');
  console.log('🚀 TierAlba API Server');
  console.log('=================================');
  console.log(`✅ Server avviato su porta ${port}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 URL: http://localhost:${port}`);
  console.log('=================================');
});

// Gestione graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM ricevuto. Chiusura graceful...');
  pool.end(() => {
    console.log('Pool database chiuso');
    process.exit(0);
  });
});
