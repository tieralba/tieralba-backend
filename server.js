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
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // Temp fix for MetaApi cert issue
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

// Resend (email - optional)
const { Resend } = process.env.RESEND_API_KEY ? require('resend') : { Resend: null };
const resend = Resend ? new Resend(process.env.RESEND_API_KEY) : null;

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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://js.stripe.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com", "https://nfs.faireconomy.media"],
      frameSrc: ["https://js.stripe.com"],
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS: solo origini autorizzate
const allowedOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, callback) {
    // Same-origin requests (frontend served from same domain) have no origin header
    if (!origin) return callback(null, true);
    // Check against allowed list, or allow if serving from same Railway domain
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
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
        let amount = 0;
        if (subscriptionId) {
          const sub = await stripe.subscriptions.retrieve(subscriptionId);
          const priceId = sub.items.data[0]?.price?.id;
          amount = (sub.items.data[0]?.price?.unit_amount || 0) / 100;
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

          // Credit referral commission
          try {
            const buyer = await pool.query('SELECT id, referred_by FROM users WHERE LOWER(email) = LOWER($1)', [customerEmail]);
            if (buyer.rows[0]?.referred_by) {
              const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [buyer.rows[0].referred_by]);
              if (referrer.rows.length > 0) {
                const commissionRate = 15;
                const saleAmount = amount || (plan === 'pro' ? 89.99 : 49.99);
                const commission = parseFloat((saleAmount * commissionRate / 100).toFixed(2));
                
                await pool.query(
                  'INSERT INTO referral_commissions (referrer_id, referred_id, referred_email, plan_purchased, sale_amount, commission_rate, commission_amount) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                  [referrer.rows[0].id, buyer.rows[0].id, customerEmail, plan, saleAmount, commissionRate, commission]
                );
                await pool.query(
                  'UPDATE users SET referral_balance = referral_balance + $1, referral_total_earned = referral_total_earned + $1 WHERE id = $2',
                  [commission, referrer.rows[0].id]
                );
                console.log(`💰 Referral commission: €${commission} credited to referrer`);
              }
            }
          } catch (refErr) {
            console.error('Referral commission error:', refErr);
          }
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

// Trust proxy (Railway runs behind a proxy)
app.set('trust proxy', 1);

// Rate limiting: previene spam/attacchi
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 100, // max 100 richieste per IP
  message: { error: 'Troppe richieste, riprova tra 15 minuti' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Rate limit stretto per auth (login, register, forgot-password)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 10, // max 10 tentativi per IP
  message: { error: 'Troppi tentativi, riprova tra 15 minuti' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

// Rate limit per admin endpoints
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Troppi tentativi admin' }
});
app.use('/api/admin/', adminLimiter);

// Logging richieste (solo in development)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

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

// Admin key verification middleware (timing-safe to prevent timing attacks)
const crypto = require('crypto');
function verifyAdminKey(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  const expectedKey = process.env.ADMIN_KEY;
  if (!adminKey || !expectedKey) return res.status(401).json({ error: 'Unauthorized' });
  
  const a = Buffer.from(String(adminKey));
  const b = Buffer.from(String(expectedKey));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ============================================
// PROTECTED EA FILE DOWNLOADS
// ============================================

app.get('/ea-files/:filename', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT plan, plan_expires_at FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const u = user.rows[0];
    const subActive = u.plan === 'standard' || u.plan === 'pro';
    const subNotExpired = !u.plan_expires_at || new Date(u.plan_expires_at) > new Date();

    if (!subActive || !subNotExpired) {
      return res.status(403).json({ error: 'Active subscription required to download EA files.' });
    }

    const filename = path.basename(req.params.filename);
    const filePath = path.join(__dirname, 'ea-files', filename);
    
    if (!require('fs').existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.download(filePath, filename);
  } catch (err) {
    console.error('EA download error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

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
    const { email, password, name, fullName, first_name, last_name, title, date_of_birth, country, phone, referralCode, marketing_consent } = req.body;
    
    // Sanitize inputs - strip HTML tags
    const sanitize = (str) => str ? String(str).replace(/<[^>]*>/g, '').trim() : '';
    const sanitizedEmail = sanitize(email).toLowerCase();
    const sanitizedName = sanitize(name) || (sanitize(first_name) + ' ' + sanitize(last_name)).trim() || sanitize(fullName) || '';
    const refCode = sanitize(referralCode).toUpperCase() || null;
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!sanitizedEmail || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (!emailRegex.test(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [sanitizedEmail]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Generate email verification token

    const verifyToken = crypto.randomBytes(32).toString('hex');
    
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, first_name, last_name, title, date_of_birth, country, phone, verify_token, email_verified, referred_by, marketing_consent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id, email, name, created_at`,
      [sanitizedEmail, passwordHash, sanitizedName, sanitize(first_name)||null, sanitize(last_name)||null, sanitize(title)||null, date_of_birth||null, sanitize(country)||null, sanitize(phone)||null, verifyToken, false, refCode, marketing_consent||false]
    );
    
    const user = result.rows[0];
    
    // Send welcome + verification email
    const baseUrl = process.env.APP_URL || 'https://tieralba-backend-production-f18f.up.railway.app';
    const verifyUrl = `${baseUrl}/api/auth/verify?token=${verifyToken}`;
    
    if (resend) {
      try {
        await resend.emails.send({
          from: process.env.EMAIL_FROM || 'TierAlba <onboarding@resend.dev>',
          to: [email.toLowerCase()],
          subject: 'Welcome to TierAlba — Verify Your Email',
          html: `
            <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;color:#f0ede6;padding:0;">
              <div style="background:#12131a;padding:32px 40px;border-bottom:1px solid rgba(255,255,255,0.06);">
                <h1 style="margin:0;font-size:24px;color:#c8aa6e;letter-spacing:-0.3px;">TierAlba</h1>
              </div>
              <div style="padding:40px;">
                <h2 style="margin:0 0 16px;font-size:22px;color:#f0ede6;">Welcome${userName ? ', ' + userName : ''}!</h2>
                <p style="color:#9b978f;font-size:15px;line-height:1.6;margin:0 0 24px;">
                  Thank you for joining TierAlba. Your trading dashboard is ready.
                </p>
                <p style="color:#9b978f;font-size:15px;line-height:1.6;margin:0 0 32px;">
                  Please verify your email address to unlock all features:
                </p>
                <div style="text-align:center;margin:0 0 32px;">
                  <a href="${verifyUrl}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#c8aa6e,#b89a5a);color:#0a0b0f;text-decoration:none;font-size:14px;font-weight:700;border-radius:8px;text-transform:uppercase;letter-spacing:1.2px;">
                    Verify Email
                  </a>
                </div>
                <p style="color:#5c5952;font-size:12px;margin:0;">
                  Or copy this link: ${verifyUrl}
                </p>
              </div>
              <div style="background:#12131a;padding:24px 40px;border-top:1px solid rgba(255,255,255,0.06);">
                <p style="color:#5c5952;font-size:12px;margin:0;text-align:center;">
                  © ${new Date().getFullYear()} TierAlba · Trading involves risk
                </p>
              </div>
            </div>
          `
        });
        console.log(`✅ Welcome email sent to ${email}`);
      } catch (emailErr) {
        console.error('Email send error:', emailErr);
        // Don't fail registration if email fails
      }
    }
    
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
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
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
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
      { expiresIn: '24h' }
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

// EMAIL VERIFICATION
app.get('/api/auth/verify', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send('Invalid verification link');
    
    const result = await pool.query(
      'UPDATE users SET email_verified = true, verify_token = NULL WHERE verify_token = $1 RETURNING email',
      [token]
    );
    
    if (result.rows.length === 0) {
      return res.send(`
        <html><body style="font-family:sans-serif;background:#0a0b0f;color:#f0ede6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
          <div style="text-align:center;">
            <h1 style="color:#e05252;">Invalid or Expired Link</h1>
            <p style="color:#9b978f;">This verification link is no longer valid.</p>
            <a href="/login.html" style="color:#c8aa6e;">Go to Login</a>
          </div>
        </body></html>
      `);
    }
    
    res.send(`
      <html><body style="font-family:sans-serif;background:#0a0b0f;color:#f0ede6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
        <div style="text-align:center;">
          <div style="font-size:48px;margin-bottom:16px;">✅</div>
          <h1 style="color:#c8aa6e;">Email Verified!</h1>
          <p style="color:#9b978f;">Your email <strong>${result.rows[0].email}</strong> has been verified successfully.</p>
          <a href="/login.html" style="display:inline-block;margin-top:20px;padding:12px 32px;background:linear-gradient(135deg,#c8aa6e,#b89a5a);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:8px;">Go to Dashboard</a>
        </div>
      </body></html>
    `);
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).send('Verification failed');
  }
});

// FORGOT PASSWORD — Send reset email
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await pool.query('SELECT id, name FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    
    // Always return success to prevent email enumeration
    if (user.rows.length === 0) {
      return res.json({ success: true });
    }


    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [resetToken, expires, user.rows[0].id]
    );

    const baseUrl = process.env.APP_URL || `https://${process.env.RAILWAY_PUBLIC_DOMAIN || 'tieralba-backend-production-f18f.up.railway.app'}`;
    const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
    const userName = user.rows[0].name || '';

    if (resend) {
      await resend.emails.send({
        from: process.env.EMAIL_FROM || 'TierAlba <onboarding@resend.dev>',
        to: [email.toLowerCase()],
        subject: 'TierAlba — Reset Your Password',
        html: `
          <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;color:#f0ede6;padding:0;">
            <div style="background:#12131a;padding:32px 40px;border-bottom:1px solid rgba(255,255,255,0.06);">
              <h1 style="margin:0;font-size:24px;color:#c8aa6e;letter-spacing:-0.3px;">TierAlba</h1>
            </div>
            <div style="padding:40px;">
              <h2 style="margin:0 0 16px;font-size:22px;color:#f0ede6;">Reset your password</h2>
              <p style="color:#9b978f;font-size:15px;line-height:1.6;margin:0 0 24px;">
                Hi${userName ? ' ' + userName : ''}, we received a request to reset your password. Click the button below to set a new one.
              </p>
              <div style="text-align:center;margin:0 0 32px;">
                <a href="${resetUrl}" style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#c8aa6e,#b89a5a);color:#0a0b0f;text-decoration:none;font-size:14px;font-weight:700;border-radius:8px;text-transform:uppercase;letter-spacing:1.2px;">
                  Reset Password
                </a>
              </div>
              <p style="color:#5c5952;font-size:12px;margin:0 0 8px;">This link expires in 1 hour.</p>
              <p style="color:#5c5952;font-size:12px;margin:0;">If you didn't request this, you can safely ignore this email.</p>
            </div>
            <div style="background:#12131a;padding:24px 40px;border-top:1px solid rgba(255,255,255,0.06);">
              <p style="color:#5c5952;font-size:12px;margin:0;text-align:center;">
                © ${new Date().getFullYear()} TierAlba · Trading involves risk
              </p>
            </div>
          </div>
        `
      });
      console.log(`📧 Password reset email sent to ${email}`);
    } else {
      console.log(`⚠️ Resend not configured. Reset URL: ${resetUrl}`);
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// RESET PASSWORD — Set new password with token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const user = await pool.query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [passwordHash, user.rows[0].id]
    );

    console.log(`🔒 Password reset completed for user ${user.rows[0].id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
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
      'SELECT SUM(profit) as sum FROM trades WHERE user_id = $1 AND profit > 0 AND closed_at IS NOT NULL',
      [userId]
    );
    const losingSum = await pool.query(
      'SELECT SUM(ABS(profit)) as sum FROM trades WHERE user_id = $1 AND profit < 0 AND closed_at IS NOT NULL',
      [userId]
    );
    
    const profitFactor = losingSum.rows[0].sum > 0 
      ? (winningSum.rows[0].sum / losingSum.rows[0].sum) 
      : 0;

    // Today's profit (trades closed today)
    const todayResult = await pool.query(
      `SELECT COALESCE(SUM(profit), 0) as today_profit
       FROM trades WHERE user_id = $1 AND closed_at IS NOT NULL 
       AND closed_at >= CURRENT_DATE`,
      [userId]
    );
    const todayProfit = parseFloat(todayResult.rows[0]?.today_profit) || 0;

    // Open trades count
    const openResult = await pool.query(
      'SELECT COUNT(*) as open_count FROM trades WHERE user_id = $1 AND closed_at IS NULL',
      [userId]
    );
    const openTrades = parseInt(openResult.rows[0]?.open_count) || 0;
    
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
      worstTrade: parseFloat(stats.worst_trade) || 0,
      todayProfit,
      openTrades
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
// ENDPOINT: CONNESSIONE BROKER (MetaApi)
// ============================================

app.post('/api/broker/connect', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { platform, accountNumber, investorPassword, brokerName } = req.body;
    
    if (!platform || !accountNumber || !investorPassword || !brokerName) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (!['mt4', 'mt5'].includes(platform.toLowerCase())) {
      return res.status(400).json({ error: 'Platform not supported. Use MT4 or MT5' });
    }

    const metaApiToken = process.env.METAAPI_TOKEN;
    if (!metaApiToken) {
      return res.status(500).json({ error: 'MetaApi not configured' });
    }

    // Create MetaApi account via REST API
    const metaApiRes = await fetch('https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'auth-token': metaApiToken
      },
      body: JSON.stringify({
        name: `TierAlba-${accountNumber}`,
        type: 'cloud',
        login: accountNumber,
        password: investorPassword,
        server: brokerName,
        platform: platform.toLowerCase(),
        magic: 0
      })
    });

    const metaAccount = await metaApiRes.json();
    
    if (metaAccount.error || !metaAccount.id) {
      console.error('MetaApi error:', metaAccount);
      return res.status(400).json({ 
        error: metaAccount.message || 'Failed to connect. Check your credentials and broker server name.' 
      });
    }

    // Deploy the account
    await fetch(`https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts/${metaAccount.id}/deploy`, {
      method: 'POST',
      headers: { 'auth-token': metaApiToken }
    });

    // Deactivate old connections
    const existing = await pool.query(
      'SELECT id FROM broker_connections WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    if (existing.rows.length > 0) {
      await pool.query('UPDATE broker_connections SET is_active = false WHERE user_id = $1', [userId]);
    }
    
    // Save new connection with MetaApi account ID
    const result = await pool.query(
      `INSERT INTO broker_connections (user_id, platform, account_number, broker_name, metaapi_account_id, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, platform, account_number, broker_name, created_at`,
      [userId, platform.toLowerCase(), accountNumber, brokerName, metaAccount.id]
    );
    
    res.status(201).json({ 
      success: true,
      message: 'Account connected successfully! Syncing data...',
      connection: result.rows[0]
    });
    
  } catch (error) {
    console.error('Broker connect error:', error);
    res.status(500).json({ error: 'Failed to connect broker' });
  }
});

// SYNC ACCOUNT DATA FROM METAAPI
app.post('/api/broker/sync', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const metaApiToken = process.env.METAAPI_TOKEN;
    if (!metaApiToken) return res.status(500).json({ error: 'MetaApi not configured' });

    const conn = await pool.query(
      'SELECT metaapi_account_id, account_number FROM broker_connections WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    if (conn.rows.length === 0) return res.status(400).json({ error: 'No active broker connection' });

    const accountId = conn.rows[0].metaapi_account_id;
    const baseUrl = 'https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai';

    // Step 1: Check account state
    const stateRes = await fetch(`${baseUrl}/users/current/accounts/${accountId}`, {
      headers: { 'auth-token': metaApiToken }
    });
    const stateText = await stateRes.text();
    let state;
    try { state = JSON.parse(stateText); } catch { 
      console.error('MetaApi state response not JSON:', stateText.substring(0, 200));
      return res.status(500).json({ error: 'MetaApi returned an invalid response. Try again in a minute.' });
    }

    console.log(`MetaApi account state: ${state.state}, connectionStatus: ${state.connectionStatus}`);

    if (state.state !== 'DEPLOYED') {
      await fetch(`${baseUrl}/users/current/accounts/${accountId}/deploy`, {
        method: 'POST',
        headers: { 'auth-token': metaApiToken }
      });
      return res.json({ success: false, error: 'Account is being deployed. Please try syncing again in 1-2 minutes.' });
    }

    if (state.connectionStatus !== 'CONNECTED') {
      return res.json({ success: false, error: `Account status: ${state.connectionStatus}. Please wait and try again.` });
    }

    // Step 2: Get client API URL
    const region = state.region || 'vint-hill';
    const clientUrl = `https://mt-client-api-v1.${region}.agiliumtrade.ai`;
    console.log(`MetaApi using client URL: ${clientUrl}`);

    // Step 3: Get account info (equity, balance)
    const infoRes = await fetch(`${clientUrl}/users/current/accounts/${accountId}/account-information`, {
      headers: { 'auth-token': metaApiToken }
    });
    const infoText = await infoRes.text();
    let info;
    try { info = JSON.parse(infoText); } catch {
      console.error('MetaApi info response not JSON:', infoText.substring(0, 200));
      return res.status(500).json({ error: 'Could not fetch account info. Try again in a minute.' });
    }

    if (info.equity !== undefined) {
      await pool.query(
        'INSERT INTO equity_snapshots (user_id, equity, balance, recorded_at) VALUES ($1, $2, $3, NOW())',
        [userId, info.equity, info.balance]
      );
    }

    let synced = 0;

    // Step 4: Get OPEN POSITIONS
    try {
      const posRes = await fetch(`${clientUrl}/users/current/accounts/${accountId}/positions`, {
        headers: { 'auth-token': metaApiToken }
      });
      const posText = await posRes.text();
      let positions = [];
      try { positions = JSON.parse(posText); } catch {
        console.error('MetaApi positions not JSON:', posText.substring(0, 200));
      }

      // Clear old open trades for this user then re-insert current open positions
      if (Array.isArray(positions) && positions.length > 0) {
        await pool.query('DELETE FROM trades WHERE user_id = $1 AND closed_at IS NULL AND external_id IS NOT NULL', [userId]);
        
        for (const pos of positions) {
          try {
            await pool.query(`
              INSERT INTO trades (user_id, symbol, type, lots, entry_price, profit, opened_at, closed_at, external_id)
              VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)
              ON CONFLICT (user_id, external_id) DO UPDATE SET profit = $6, lots = $4
            `, [
              userId,
              pos.symbol || 'UNKNOWN',
              (pos.type === 'POSITION_TYPE_BUY' ? 'BUY' : 'SELL'),
              pos.volume || 0,
              pos.openPrice || 0,
              pos.profit || 0,
              pos.time || new Date().toISOString(),
              'pos-' + (pos.id || pos.symbol + '-' + Date.now())
            ]);
            synced++;
          } catch (dbErr) {
            console.error('Position insert error:', dbErr.message);
          }
        }
      }
      console.log(`📊 Synced ${positions.length || 0} open positions`);
    } catch (posErr) {
      console.error('Positions fetch error:', posErr.message);
    }

    // Step 5: Get CLOSED DEALS (history-orders gives completed trades)
    try {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const now = new Date().toISOString();
      
      const tradesRes = await fetch(
        `${clientUrl}/users/current/accounts/${accountId}/history-deals/time/${thirtyDaysAgo}/${now}`,
        { headers: { 'auth-token': metaApiToken } }
      );
      const tradesText = await tradesRes.text();
      let rawDeals;
      try { rawDeals = JSON.parse(tradesText); } catch {
        console.error('MetaApi deals response not JSON:', tradesText.substring(0, 200));
        rawDeals = null;
      }

      // MetaAPI returns either an array directly or { deals: [...] }
      let deals = [];
      if (Array.isArray(rawDeals)) {
        deals = rawDeals;
      } else if (rawDeals && Array.isArray(rawDeals.deals)) {
        deals = rawDeals.deals;
      }

      console.log(`📊 MetaApi returned ${deals.length} deals`);

      // Filter only actual CLOSING trade deals
      // - Must be BUY or SELL type
      // - Must be DEAL_ENTRY_OUT (closing a position) — DEAL_ENTRY_IN is opening
      // - Must have a symbol (balance/credit operations don't)
      // - Exclude deals with 0 volume (not real trades)
      const tradingDeals = deals.filter(d => 
        (d.type === 'DEAL_TYPE_BUY' || d.type === 'DEAL_TYPE_SELL') &&
        d.entryType === 'DEAL_ENTRY_OUT' &&
        d.symbol &&
        d.volume > 0
      );

      console.log(`📊 Filtered to ${tradingDeals.length} closing deals`);

      for (const deal of tradingDeals) {
        try {
          await pool.query(`
            INSERT INTO trades (user_id, symbol, type, lots, entry_price, exit_price, profit, opened_at, closed_at, external_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (user_id, external_id) DO UPDATE SET profit = $7, exit_price = $6, closed_at = $9
          `, [
            userId,
            deal.symbol || 'UNKNOWN',
            deal.type === 'DEAL_TYPE_BUY' ? 'BUY' : 'SELL',
            deal.volume || 0,
            deal.price || 0,
            deal.price || 0,
            deal.profit || 0,
            deal.brokerTime || deal.time || new Date().toISOString(),
            deal.brokerTime || deal.time || new Date().toISOString(),
            'deal-' + (deal.id || `${Date.now()}-${synced}`)
          ]);
          synced++;
        } catch (dbErr) {
          console.error('Deal insert error:', dbErr.message);
        }
      }
    } catch (dealErr) {
      console.error('Deals fetch error:', dealErr.message);
    }

    console.log(`✅ Sync complete: ${synced} trades synced for user ${userId}`);

    res.json({ 
      success: true, 
      synced,
      account: {
        equity: info.equity || 0,
        balance: info.balance || 0,
        profit: (info.equity || 0) - (info.balance || 0)
      }
    });
    
  } catch (error) {
    console.error('Sync error:', error);
    res.status(500).json({ error: 'Sync failed. Please try again.' });
  }
});

// GET BROKER CONNECTIONS
app.get('/api/broker/connections', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      `SELECT id, platform, account_number, broker_name, is_active, created_at 
       FROM broker_connections WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    res.json({ connections: result.rows });
  } catch (error) {
    console.error('Connections error:', error);
    res.status(500).json({ error: 'Failed to get connections' });
  }
});

// DISCONNECT BROKER
app.post('/api/broker/disconnect', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE broker_connections SET is_active = false WHERE user_id = $1', [req.userId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

// PANIC: Close all open trades
app.post('/api/broker/close-all', authenticateToken, async (req, res) => {
  try {
    // Get active broker connection
    const conn = await pool.query(
      'SELECT * FROM broker_connections WHERE user_id = $1 AND is_active = true LIMIT 1',
      [req.userId]
    );

    if (conn.rows.length === 0) {
      return res.status(400).json({ error: 'No active broker connection' });
    }

    // Close all open trades in database (mark as closed at current time)
    const result = await pool.query(
      `UPDATE trades SET closed_at = NOW(), exit_price = entry_price, profit = 0 
       WHERE user_id = $1 AND closed_at IS NULL 
       RETURNING id`,
      [req.userId]
    );

    const closedCount = result.rowCount || 0;

    // Note: In production with MetaApi, you would also call:
    // metaApi.closeAllPositions(accountId)
    // For now we just update the database

    console.log(`PANIC: User ${req.userId} closed ${closedCount} trades`);
    res.json({ success: true, closed: closedCount, message: 'All trades marked as closed' });

  } catch (error) {
    console.error('Close-all error:', error);
    res.status(500).json({ error: 'Failed to close trades' });
  }
});

// ============================================
// ENDPOINT: REFERRAL SYSTEM
// ============================================

// Generate referral code on first access
app.get('/api/referral/info', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT id, email, referral_code, referral_balance, referral_total_earned, usdt_wallet FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    let { referral_code, referral_balance, referral_total_earned, usdt_wallet } = user.rows[0];

    // Auto-generate referral code if not set
    if (!referral_code) {

      referral_code = 'TIER-' + crypto.randomBytes(4).toString('hex').toUpperCase();
      await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [referral_code, req.userId]);
    }

    // Get referral stats
    const referrals = await pool.query(
      'SELECT COUNT(*) as count FROM users WHERE referred_by = $1',
      [referral_code]
    );

    const commissions = await pool.query(
      'SELECT * FROM referral_commissions WHERE referrer_id = $1 ORDER BY created_at DESC LIMIT 20',
      [req.userId]
    );

    const pendingPayouts = await pool.query(
      'SELECT * FROM referral_payouts WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10',
      [req.userId]
    );

    res.json({
      referral_code,
      balance: parseFloat(referral_balance) || 0,
      total_earned: parseFloat(referral_total_earned) || 0,
      total_referrals: parseInt(referrals.rows[0].count) || 0,
      usdt_wallet: usdt_wallet || '',
      commissions: commissions.rows,
      payouts: pendingPayouts.rows,
      commission_rate: 15,
      min_payout: 50
    });
  } catch (error) {
    console.error('Referral info error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save USDT wallet
app.post('/api/referral/wallet', authenticateToken, async (req, res) => {
  try {
    const { wallet } = req.body;
    if (!wallet || wallet.length < 10) return res.status(400).json({ error: 'Invalid wallet address' });
    await pool.query('UPDATE users SET usdt_wallet = $1 WHERE id = $2', [wallet.trim(), req.userId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Request payout
app.post('/api/referral/payout', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT referral_balance, usdt_wallet FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const balance = parseFloat(user.rows[0].referral_balance) || 0;
    const wallet = user.rows[0].usdt_wallet;

    if (balance < 50) return res.status(400).json({ error: 'Minimum payout is €50. Current balance: €' + balance.toFixed(2) });
    if (!wallet) return res.status(400).json({ error: 'Please set your USDT wallet address first' });

    // Check for existing pending payout
    const pending = await pool.query(
      'SELECT id FROM referral_payouts WHERE user_id = $1 AND status = $2',
      [req.userId, 'pending']
    );
    if (pending.rows.length > 0) return res.status(400).json({ error: 'You already have a pending payout request' });

    // Create payout and deduct balance
    await pool.query(
      'INSERT INTO referral_payouts (user_id, amount, usdt_wallet) VALUES ($1, $2, $3)',
      [req.userId, balance, wallet]
    );
    await pool.query('UPDATE users SET referral_balance = 0 WHERE id = $1', [req.userId]);

    res.json({ success: true, amount: balance, message: 'Payout request submitted! We will process it within 48 hours.' });
  } catch (error) {
    console.error('Payout error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// ENDPOINT: TRADING SIGNALS
// ============================================

// Get signals (for clients)
app.get('/api/signals', authenticateToken, async (req, res) => {
  try {
    // Check plan - only standard and pro
    const user = await pool.query('SELECT plan FROM users WHERE id = $1', [req.userId]);
    const plan = user.rows[0]?.plan || 'free';
    if (plan === 'free') return res.status(403).json({ error: 'Upgrade to Standard or Pro to access signals' });

    const limit = parseInt(req.query.limit) || 30;
    const result = await pool.query(
      'SELECT * FROM signals ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    res.json({ signals: result.rows });
  } catch (error) {
    console.error('Signals error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create signal (admin only)
app.post('/api/signals', verifyAdminKey, async (req, res) => {
  try {
    const { source, symbol, direction, entry_price, stop_loss, tp1, tp2, tp3, notes } = req.body;
    if (!symbol || !direction) return res.status(400).json({ error: 'Symbol and direction required' });

    const result = await pool.query(
      `INSERT INTO signals (source, symbol, direction, entry_price, stop_loss, tp1, tp2, tp3, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [source || 'team', symbol.toUpperCase(), direction.toUpperCase(), entry_price || null, stop_loss || null, tp1 || null, tp2 || null, tp3 || null, notes || null]
    );
    
    console.log(`📡 New signal: ${direction} ${symbol} @ ${entry_price}`);
    res.status(201).json({ success: true, signal: result.rows[0] });
  } catch (error) {
    console.error('Create signal error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update signal status (admin only)
app.put('/api/signals/:id', verifyAdminKey, async (req, res) => {
  try {
    const { status, result } = req.body;
    await pool.query(
      'UPDATE signals SET status = $1, result = $2, closed_at = CASE WHEN $1 = $3 THEN NOW() ELSE closed_at END WHERE id = $4',
      [status, result || null, 'closed', req.params.id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete signal (admin only)
app.delete('/api/signals/:id', verifyAdminKey, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM signals WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Signal not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('Delete signal error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all signals for admin
app.get('/api/admin/signals', verifyAdminKey, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 100');
    res.json({ signals: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// EA auto-close signal by symbol
app.post('/api/ea/close-signal', verifyAdminKey, async (req, res) => {
  try {
    const { symbol, result } = req.body;
    if (!symbol || !result) return res.status(400).json({ error: 'Symbol and result required' });

    // Close the most recent active signal for this symbol
    const updated = await pool.query(
      `UPDATE signals SET status = 'closed', result = $1, closed_at = NOW() 
       WHERE symbol = $2 AND status = 'active' 
       AND id = (SELECT id FROM signals WHERE symbol = $2 AND status = 'active' ORDER BY created_at DESC LIMIT 1)
       RETURNING id`,
      [result, symbol.toUpperCase()]
    );

    if (updated.rows.length > 0) {
      console.log(`📡 EA closed signal: ${symbol} → ${result}`);
      res.json({ success: true, closed_id: updated.rows[0].id });
    } else {
      res.json({ success: false, message: 'No active signal found for ' + symbol });
    }
  } catch (error) {
    console.error('EA close signal error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

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
      success_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba-backend-production-f18f.up.railway.app'}/dashboard?upgrade=success`,
      cancel_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba-backend-production-f18f.up.railway.app'}/dashboard?upgrade=cancelled`,
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
      return_url: `${req.headers.origin || 'https://tieralba-backend-production-f18f.up.railway.app'}/dashboard`
    });
    
    res.json({ url: session.url });
  } catch (error) {
    console.error('Portal error:', error);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// ============================================
// ============================================
// EA LICENSE VERIFICATION SYSTEM
// ============================================

// Generate a unique license key
function generateLicenseKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let segment = '';
    for (let i = 0; i < 5; i++) {
      segment += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    segments.push(segment);
  }
  return 'TA-' + segments.join('-');
}

// POST /api/ea/verify — Called by the EA from MetaTrader
app.post('/api/ea/verify', async (req, res) => {
  try {
    const { license_key, product, account } = req.body;

    if (!license_key) {
      return res.json({ valid: false, error: 'No license key provided' });
    }

    const result = await pool.query(
      `SELECT el.*, u.plan, u.plan_expires_at, u.email
       FROM ea_licenses el
       JOIN users u ON u.id = el.user_id
       WHERE el.license_key = $1 AND el.product = $2 AND el.is_active = true`,
      [license_key, product || 'any']
    );

    if (result.rows.length === 0) {
      return res.json({ valid: false, error: 'License not found or inactive' });
    }

    const license = result.rows[0];

    // Check if subscription is active
    const subActive = license.plan === 'standard' || license.plan === 'pro';
    const subNotExpired = !license.plan_expires_at || new Date(license.plan_expires_at) > new Date();

    if (!subActive || !subNotExpired) {
      return res.json({ valid: false, expired: true, error: 'Subscription expired' });
    }

    // Update last verification time and MT account
    await pool.query(
      `UPDATE ea_licenses SET last_verified = NOW(), mt_account = $1, verification_count = verification_count + 1
       WHERE id = $2`,
      [account || null, license.id]
    );

    return res.json({ valid: true, product: license.product, email: license.email });

  } catch (err) {
    console.error('EA verify error:', err);
    return res.json({ valid: false, error: 'Server error' });
  }
});

// GET /api/ea/license — Get user's license keys (requires auth)
app.get('/api/ea/license', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, license_key, product, is_active, created_at, last_verified, mt_account, verification_count
       FROM ea_licenses WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.userId]
    );
    res.json({ licenses: result.rows });
  } catch (err) {
    console.error('Get licenses error:', err);
    res.status(500).json({ error: 'Errore server' });
  }
});

// POST /api/ea/license/generate — Generate license keys for user (requires auth + active sub)
app.post('/api/ea/license/generate', authenticateToken, async (req, res) => {
  try {
    // Check subscription
    const user = await pool.query('SELECT plan, plan_expires_at FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const u = user.rows[0];
    const subActive = u.plan === 'standard' || u.plan === 'pro';
    const subNotExpired = !u.plan_expires_at || new Date(u.plan_expires_at) > new Date();

    if (!subActive || !subNotExpired) {
      return res.status(403).json({ error: 'Subscription not active. Renew to generate license keys.' });
    }

    // Check if already has licenses for both products
    const existing = await pool.query('SELECT product FROM ea_licenses WHERE user_id = $1 AND is_active = true', [req.userId]);
    const existingProducts = existing.rows.map(r => r.product);

    const products = ['tier_algo_gold', 'tier_algo_us100'];
    const newLicenses = [];

    for (const product of products) {
      if (!existingProducts.includes(product)) {
        const key = generateLicenseKey();
        const result = await pool.query(
          `INSERT INTO ea_licenses (user_id, license_key, product, is_active)
           VALUES ($1, $2, $3, true) RETURNING id, license_key, product, is_active, created_at`,
          [req.userId, key, product]
        );
        newLicenses.push(result.rows[0]);
      }
    }

    if (newLicenses.length === 0) {
      return res.json({ message: 'License keys already exist', licenses: existing.rows });
    }

    res.json({ message: 'License keys generated', licenses: newLicenses });

  } catch (err) {
    console.error('Generate license error:', err);
    res.status(500).json({ error: 'Errore server' });
  }
});

// POST /api/ea/license/revoke — Admin revoke a license
app.post('/api/ea/license/revoke', async (req, res) => {
  try {
    const { admin_key, license_id } = req.body;
    if (admin_key !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

    await pool.query('UPDATE ea_licenses SET is_active = false WHERE id = $1', [license_id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Revoke license error:', err);
    res.status(500).json({ error: 'Errore server' });
  }
});

// ============================================
// ENDPOINT: USER PROFILE & SECURITY
// ============================================

// Update profile name
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

    await pool.query('UPDATE users SET name = $1 WHERE id = $2', [name.trim(), req.userId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Change password
app.put('/api/user/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

    const user = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

    const newHash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.userId]);

    console.log(`🔒 User ${req.userId} changed password`);
    res.json({ success: true });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ============================================
// ENDPOINT: JOURNAL
// ============================================

// Get all journal entries
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT j.*, t.symbol as trade_symbol, t.type as trade_type, t.profit as trade_profit
      FROM journal_entries j
      LEFT JOIN trades t ON j.trade_id = t.id
      WHERE j.user_id = $1
      ORDER BY j.trade_date DESC NULLS LAST, j.created_at DESC
      LIMIT 200
    `, [req.userId]);
    res.json({ entries: result.rows });
  } catch (error) {
    console.error('Journal list error:', error);
    res.status(500).json({ error: 'Failed to load journal' });
  }
});

// Create journal entry
app.post('/api/journal', authenticateToken, async (req, res) => {
  try {
    const { symbol, direction, lots, risk_pct, entry_price, sl, tp, pnl, rr_planned,
            trade_date, setup, timeframe, mood, followed_rules, notes, trade_id, image } = req.body;
    if (!symbol) return res.status(400).json({ error: 'Pair is required' });

    const result = await pool.query(`
      INSERT INTO journal_entries (user_id, symbol, direction, lots, risk_pct, entry_price, sl, tp, pnl, rr_planned,
        trade_date, setup, timeframe, mood, followed_rules, notes, trade_id, image_url)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING id
    `, [
      req.userId, symbol||null, direction||null, lots||null, risk_pct||null,
      entry_price||null, sl||null, tp||null, pnl||null, rr_planned||null,
      trade_date||null, setup||null, timeframe||null, mood||null, followed_rules,
      notes||null, trade_id||null, image||null
    ]);

    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Journal create error:', error);
    res.status(500).json({ error: 'Failed to save entry' });
  }
});

// Update journal entry
app.put('/api/journal/:id', authenticateToken, async (req, res) => {
  try {
    const { symbol, direction, lots, risk_pct, entry_price, sl, tp, pnl, rr_planned,
            trade_date, setup, timeframe, mood, followed_rules, notes, trade_id, image } = req.body;

    const result = await pool.query(`
      UPDATE journal_entries SET
        symbol=$1, direction=$2, lots=$3, risk_pct=$4, entry_price=$5, sl=$6, tp=$7, pnl=$8,
        rr_planned=$9, trade_date=$10, setup=$11, timeframe=$12, mood=$13, followed_rules=$14,
        notes=$15, trade_id=$16, image_url=$17, updated_at=NOW()
      WHERE id=$18 AND user_id=$19 RETURNING id
    `, [
      symbol||null, direction||null, lots||null, risk_pct||null, entry_price||null,
      sl||null, tp||null, pnl||null, rr_planned||null, trade_date||null,
      setup||null, timeframe||null, mood||null, followed_rules, notes||null,
      trade_id||null, image||null, req.params.id, req.userId
    ]);

    if (result.rowCount === 0) return res.status(404).json({ error: 'Entry not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('Journal update error:', error);
    res.status(500).json({ error: 'Failed to update entry' });
  }
});

// Delete journal entry
app.delete('/api/journal/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM journal_entries WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.userId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Entry not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('Journal delete error:', error);
    res.status(500).json({ error: 'Failed to delete entry' });
  }
});

// ============================================
// ENDPOINT: SUPPORT MESSAGES
// ============================================

app.post('/api/support/message', authenticateToken, async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });

    const userResult = await pool.query('SELECT email, name FROM users WHERE id = $1', [req.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = userResult.rows[0];

    // Save to database
    await pool.query(
      `INSERT INTO support_messages (user_id, email, name, subject, message)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.userId, user.email, user.name || '', subject, message]
    );

    console.log(`📩 Support from ${user.email}: [${subject}] ${message.substring(0, 100)}`);

    // Send notification email (not the message itself, just a heads-up)
    if (resend) {
      try {
        await resend.emails.send({
          from: process.env.EMAIL_FROM || 'TierAlba <onboarding@resend.dev>',
          to: ['info@tieralba.com'],
          subject: '[TierAlba] New support request from ' + user.email,
          html: '<div style="font-family:sans-serif;padding:20px;">' +
            '<h3 style="color:#c8aa6e;">New Support Request</h3>' +
            '<p><strong>From:</strong> ' + (user.name || 'N/A') + ' (' + user.email + ')</p>' +
            '<p><strong>Subject:</strong> ' + subject + '</p>' +
            '<p style="color:#888;">View full message in Supabase → support_messages table</p>' +
            '</div>'
        });
      } catch (emailErr) {
        console.error('Support notification email error:', emailErr);
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Support message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ============================================
// SERVE FRONTEND per route non-API
// ============================================

// Landing page on root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Dashboard (requires login on client side)
app.get('/dashboard', (req, res) => {
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
