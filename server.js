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
// EMAIL TEMPLATE HELPERS
// ============================================
const LOGO_URL = 'https://tieralba.com/logo.png';

function emailFrom() {
  return process.env.EMAIL_FROM || 'TierAlba <noreply@tieralba.com>';
}

function emailWrapper(content) {
  return `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
      <img src="${LOGO_URL}" alt="TierAlba" style="height:40px;width:auto;" />
    </div>
    ${content}
    <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
      <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
    </div>
  </div>`;
}

// ============================================
// TELEGRAM BOT NOTIFICATIONS (Admin)
// ============================================
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramNotification(message) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML'
      })
    });
  } catch (err) {
    console.error('Telegram notification error (non-fatal):', err.message);
  }
}

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
        const customerEmail = (session.customer_email || session.customer_details?.email || '').toLowerCase();
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        const metadata = session.metadata || {};
        const productKey = metadata.productKey;
        const service = metadata.service;
        const planLabel = metadata.planLabel;
        const userId = metadata.userId;
        
        console.log(`✅ Payment completed: ${customerEmail} → ${service}/${planLabel} (key: ${productKey})`);
        
        if (!customerEmail) break;

        if (service === 'tradesalba') {
          // ─── TRADESALBA: subscription-based ───
          // Determine plan from priceId
          let taPlan = 'standard';
          if (subscriptionId) {
            const sub = await stripe.subscriptions.retrieve(subscriptionId);
            const priceId = sub.items.data[0]?.price?.id;
            const proPriceIds = [
              'price_1Sx9bMRo0AfnvbiMVTcum8SM', // Pro Monthly
              'price_1Sx9qRRo0AfnvbiMwhCq3fPx'  // Pro Yearly
            ];
            if (proPriceIds.includes(priceId)) taPlan = 'pro';
          }
          
          await pool.query(
            `UPDATE users SET 
              plan = $1, 
              stripe_customer_id = $2, 
              stripe_subscription_id = $3,
              active_services = COALESCE(active_services, '{}'::jsonb) || $4::jsonb
            WHERE LOWER(email) = LOWER($5)`,
            [taPlan, customerId, subscriptionId, JSON.stringify({ tradesalba: { plan: taPlan, status: 'active', activated_at: new Date().toISOString(), product_key: productKey } }), customerEmail]
          );
          console.log(`📊 TradesAlba ${taPlan} activated for ${customerEmail}`);
          sendTelegramNotification(`💰 <b>New Purchase</b>\n\n📧 ${customerEmail}\n📦 TradesAlba ${taPlan}\n💵 Product: ${productKey}`);
          
        } else if (service === 'tierpass') {
          // ─── TIER PASS: one-time, immediate access ───
          await pool.query(
            `UPDATE users SET 
              stripe_customer_id = COALESCE($1, stripe_customer_id),
              active_services = COALESCE(active_services, '{}'::jsonb) || $2::jsonb
            WHERE LOWER(email) = LOWER($3)`,
            [customerId, JSON.stringify({ tierpass: { plan: planLabel, status: 'active', activated_at: new Date().toISOString(), product_key: productKey } }), customerEmail]
          );
          console.log(`🏆 Tier Pass ${planLabel} activated for ${customerEmail}`);
          sendTelegramNotification(`💰 <b>New Purchase</b>\n\n📧 ${customerEmail}\n📦 Tier Pass — ${planLabel}\n💵 Product: ${productKey}`);
          
        } else if (service === 'tiermanage') {
          // ─── TIER MANAGE: one-time, immediate access ───
          await pool.query(
            `UPDATE users SET 
              stripe_customer_id = COALESCE($1, stripe_customer_id),
              active_services = COALESCE(active_services, '{}'::jsonb) || $2::jsonb
            WHERE LOWER(email) = LOWER($3)`,
            [customerId, JSON.stringify({ tiermanage: { plan: planLabel, status: 'active', activated_at: new Date().toISOString(), product_key: productKey } }), customerEmail]
          );
          console.log(`📈 Tier Manage ${planLabel} activated for ${customerEmail}`);
          sendTelegramNotification(`💰 <b>New Purchase</b>\n\n📧 ${customerEmail}\n📦 Tier Manage — ${planLabel}\n💵 Product: ${productKey}`);
        }

        // ─── RECORD PURCHASE ───
        const amount = session.amount_total ? session.amount_total / 100 : 0;
        try {
          await pool.query(
            `INSERT INTO purchases (user_id, email, service, plan_label, product_key, amount, stripe_session_id, stripe_customer_id, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'completed')`,
            [userId || null, customerEmail, service, planLabel, productKey, amount, session.id, customerId]
          );
        } catch (purchaseErr) {
          console.error('Purchase record error (non-fatal):', purchaseErr.message);
        }

        // ─── REFERRAL COMMISSION ───
        try {
          const buyer = await pool.query('SELECT id, referred_by FROM users WHERE LOWER(email) = LOWER($1)', [customerEmail]);
          if (buyer.rows[0]?.referred_by) {
            const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [buyer.rows[0].referred_by]);
            if (referrer.rows.length > 0) {
              const commissionRate = 15;
              const saleAmount = amount || 0;
              const commission = parseFloat((saleAmount * commissionRate / 100).toFixed(2));
              if (commission > 0) {
                await pool.query(
                  'INSERT INTO referral_commissions (referrer_id, referred_id, referred_email, plan_purchased, sale_amount, commission_rate, commission_amount) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                  [referrer.rows[0].id, buyer.rows[0].id, customerEmail, `${service}:${planLabel}`, saleAmount, commissionRate, commission]
                );
                await pool.query(
                  'UPDATE users SET referral_balance = referral_balance + $1, referral_total_earned = referral_total_earned + $1 WHERE id = $2',
                  [commission, referrer.rows[0].id]
                );
                console.log(`💰 Referral commission: €${commission} credited`);
                
                // Notify referrer about commission earned
                try {
                  if (resend) {
                    const referrerData = await pool.query('SELECT email, referral_balance FROM users WHERE id = $1', [referrer.rows[0].id]);
                    if (referrerData.rows[0]) {
                      const newBalance = parseFloat(referrerData.rows[0].referral_balance) || 0;
                      await resend.emails.send({
                        from: emailFrom(),
                        to: referrerData.rows[0].email,
                        subject: `TierAlba — You Earned €${commission.toFixed(2)} Commission! 💰`,
                        html: `
                          <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                            <div style="background:linear-gradient(135deg,#2a6b4a,#5ee0a0);padding:32px;text-align:center;">
                              <h1 style="color:#0a0b0f;margin:0;font-size:28px;">You Earned a Commission!</h1>
                            </div>
                            <div style="padding:40px 32px;color:#ece8de;">
                              <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Great news! Someone you referred just made a purchase.</p>
                              <div style="background:rgba(94,224,160,0.08);border:1px solid rgba(94,224,160,0.15);border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
                                <div style="font-size:42px;font-weight:700;color:#5ee0a0;">+€${commission.toFixed(2)}</div>
                                <div style="font-size:14px;color:#8e897e;margin-top:8px;">New balance: €${newBalance.toFixed(2)}</div>
                              </div>
                              ${newBalance >= 50 ? '<p style="font-size:16px;line-height:1.8;margin-bottom:24px;color:#5ee0a0;font-weight:600;">✅ Your balance is above €50 — you can request a payout!</p>' : `<p style="font-size:16px;line-height:1.8;margin-bottom:24px;">€${(50 - newBalance).toFixed(2)} more until you can request a payout (min €50).</p>`}
                              <div style="text-align:center;margin:32px 0;">
                                <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">View Dashboard</a>
                              </div>
                            </div>
                            <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                              <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                            </div>
                          </div>`
                      });
                    }
                  }
                } catch (notifErr) {
                  console.error('Referral notification email error (non-fatal):', notifErr.message);
                }
              }
            }
          }
        } catch (refErr) {
          console.error('Referral commission error:', refErr);
        }

        // ─── PURCHASE CONFIRMATION EMAIL (includes verify link for new users) ───
        try {
          if (resend && customerEmail) {
            const serviceNames = { tierpass: 'Tier Pass', tiermanage: 'Tier Manage', tradesalba: 'TradesAlba' };
            const serviceName = serviceNames[service] || service;
            
            // Check if user needs email verification
            let verifyBlock = '';
            try {
              const verifyCheck = await pool.query(
                'SELECT verify_token, email_verified, name FROM users WHERE LOWER(email) = LOWER($1)',
                [customerEmail]
              );
              if (verifyCheck.rows[0] && !verifyCheck.rows[0].email_verified && verifyCheck.rows[0].verify_token) {
                const baseUrl = process.env.APP_URL || 'https://tieralba.com';
                const verifyUrl = `${baseUrl}/api/auth/verify?token=${verifyCheck.rows[0].verify_token}`;
                verifyBlock = `
                  <div style="background:rgba(94,224,160,0.06);border:1px solid rgba(94,224,160,0.15);border-radius:12px;padding:20px;margin-bottom:24px;">
                    <p style="margin:0 0 12px;font-size:14px;color:#5ee0a0;font-weight:600;">📧 Verify your email to unlock all features</p>
                    <div style="text-align:center;">
                      <a href="${verifyUrl}" style="display:inline-block;padding:10px 28px;background:rgba(94,224,160,0.15);border:1px solid rgba(94,224,160,0.3);color:#5ee0a0;text-decoration:none;font-weight:600;border-radius:8px;font-size:13px;">Verify Email</a>
                    </div>
                  </div>`;
              }
            } catch (vErr) { /* non-fatal */ }

            const userName = await pool.query('SELECT name FROM users WHERE LOWER(email) = LOWER($1)', [customerEmail]);
            const displayName = userName.rows[0]?.name?.split(' ')[0] || 'there';

            await resend.emails.send({
              from: emailFrom(),
              to: customerEmail,
              subject: `TierAlba — Your ${serviceName} is Active! 🎉`,
              html: `
                <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                  <div style="background:linear-gradient(135deg,#c8a94e,#b59840);padding:40px 32px;text-align:center;">
                    <h1 style="color:#0a0b0f;margin:0;font-size:28px;">Thank You for Your Purchase!</h1>
                  </div>
                  <div style="padding:40px 32px;color:#ece8de;">
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Hi ${displayName},</p>
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Your <strong style="color:#c8a94e;">${serviceName} — ${planLabel}</strong> has been activated successfully.</p>
                    ${verifyBlock}
                    ${service === 'tierpass' || service === 'tiermanage' ? '<p style="font-size:16px;line-height:1.8;margin-bottom:24px;">📅 <strong>Next step:</strong> Book your private Zoom setup session. Our team will install the EA on your MetaTrader platform. Reply to this email or contact us at support@tieralba.com to schedule.</p>' : ''}
                    ${service === 'tradesalba' ? '<p style="font-size:16px;line-height:1.8;margin-bottom:24px;">🚀 <strong>Next step:</strong> Log in to your dashboard to access signals, journal, risk tools, and more.</p>' : ''}
                    <div style="text-align:center;margin:32px 0;">
                      <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Go to Dashboard</a>
                    </div>
                    <p style="font-size:14px;color:#8e897e;line-height:1.7;">If you have any questions, reply to this email or contact support@tieralba.com</p>
                  </div>
                  <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                    <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                  </div>
                </div>`
            });
            console.log(`📧 Purchase confirmation email sent to ${customerEmail}`);
          }
        } catch (emailErr) {
          console.error('Purchase email error (non-fatal):', emailErr.message);
        }
        break;
      }
      
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const status = sub.status;
        if (status === 'active') {
          const priceId = sub.items.data[0]?.price?.id;
          const proPriceIds = ['price_1Sx9bMRo0AfnvbiMVTcum8SM', 'price_1Sx9qRRo0AfnvbiMwhCq3fPx'];
          const plan = proPriceIds.includes(priceId) ? 'pro' : 'standard';
          const renewed = await pool.query(
            'UPDATE users SET plan = $1 WHERE stripe_subscription_id = $2 RETURNING email, name',
            [plan, sub.id]
          );

          // Send renewal confirmation email
          if (renewed.rows.length > 0 && resend) {
            try {
              const renewedUser = renewed.rows[0];
              const planLabel = plan === 'pro' ? 'Pro' : 'Standard';
              const nextBilling = sub.current_period_end ? new Date(sub.current_period_end * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : 'N/A';
              await resend.emails.send({
                from: emailFrom(),
                to: renewedUser.email,
                subject: `TierAlba — Your ${planLabel} Subscription Has Been Renewed ✅`,
                html: `
                  <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                    <div style="background:linear-gradient(135deg,#c8a94e,#b59840);padding:40px 32px;text-align:center;">
                      <h1 style="color:#0a0b0f;margin:0;font-size:28px;">Subscription Renewed!</h1>
                    </div>
                    <div style="padding:40px 32px;color:#ece8de;">
                      <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Hi${renewedUser.name ? ' ' + renewedUser.name.split(' ')[0] : ''},</p>
                      <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Your <strong style="color:#c8aa6e;">TradesAlba ${planLabel}</strong> subscription has been successfully renewed. You continue to have full access to all features.</p>
                      <div style="background:rgba(200,169,78,0.06);border:1px solid rgba(200,169,78,0.1);border-radius:12px;padding:20px;margin-bottom:24px;">
                        <p style="margin:0;font-size:14px;color:#8e897e;">📅 <strong style="color:#ece8de;">Next billing date:</strong> ${nextBilling}</p>
                      </div>
                      <div style="text-align:center;margin:32px 0;">
                        <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Go to Dashboard</a>
                      </div>
                      <p style="font-size:14px;color:#8e897e;line-height:1.7;">To manage your subscription, visit your dashboard or contact support@tieralba.com</p>
                    </div>
                    <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                      <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                    </div>
                  </div>`
              });
              console.log(`📧 Renewal confirmation email sent to ${renewedUser.email}`);
            } catch (renewEmailErr) {
              console.error('Renewal email error (non-fatal):', renewEmailErr.message);
            }
          }
        }
        break;
      }
      
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        // Downgrade plan to free
        const downgraded = await pool.query(
          `UPDATE users SET plan = 'free', 
           active_services = active_services - 'tradesalba'
           WHERE stripe_subscription_id = $1
           RETURNING id, email`,
          [sub.id]
        );
        // Deactivate all license keys for this user
        if (downgraded.rows.length > 0) {
          await pool.query(
            'UPDATE ea_licenses SET is_active = false WHERE user_id = $1',
            [downgraded.rows[0].id]
          );
          console.log(`🔑 License keys deactivated for user ${downgraded.rows[0].id}`);
          
          // Send cancellation email
          try {
            if (resend && downgraded.rows[0].email) {
              await resend.emails.send({
                from: emailFrom(),
                to: downgraded.rows[0].email,
                subject: 'TierAlba — Your Subscription Has Been Cancelled',
                html: `
                  <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                    <div style="padding:40px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.05);">
                      <h1 style="color:#ece8de;margin:0;font-size:26px;">We're Sorry to See You Go</h1>
                    </div>
                    <div style="padding:40px 32px;color:#ece8de;">
                      <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Your TierAlba subscription has been cancelled. Your access to premium features and EA licenses has been deactivated.</p>
                      <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">If this was a mistake or you'd like to reactivate, you can re-subscribe anytime from your dashboard.</p>
                      <div style="text-align:center;margin:32px 0;">
                        <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Reactivate Subscription</a>
                      </div>
                      <p style="font-size:14px;color:#8e897e;line-height:1.7;">We'd love your feedback — reply to this email and let us know what we could improve.</p>
                    </div>
                    <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                      <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                    </div>
                  </div>`
              });
              console.log(`📧 Cancellation email sent to ${downgraded.rows[0].email}`);
            }
          } catch (emailErr) {
            console.error('Cancellation email error (non-fatal):', emailErr.message);
          }
        }
        console.log(`⚠️ Subscription ${sub.id} cancelled - downgraded to free`);
        sendTelegramNotification(`⚠️ <b>Subscription Cancelled</b>\n\n📧 ${downgraded.rows[0]?.email || 'unknown'}\n🔑 Licenses deactivated`);
        break;
      }

      // ─── ABANDONED CHECKOUT ───
      case 'checkout.session.expired': {
        const expired = event.data.object;
        const abandonedEmail = expired.customer_email || expired.customer_details?.email;
        const abandonedMeta = expired.metadata || {};
        
        if (abandonedEmail && resend) {
          try {
            const serviceNames = { tierpass: 'Tier Pass', tiermanage: 'Tier Manage', tradesalba: 'TradesAlba' };
            const serviceName = serviceNames[abandonedMeta.service] || 'your selected plan';
            const planName = abandonedMeta.planLabel || '';
            
            await resend.emails.send({
              from: emailFrom(),
              to: abandonedEmail,
              subject: 'TierAlba — You Left Something Behind',
              html: `
                <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                  <div style="padding:40px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.05);">
                    <h1 style="color:#c8a94e;margin:0;font-size:28px;">Still Thinking?</h1>
                  </div>
                  <div style="padding:40px 32px;color:#ece8de;">
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Hi ${displayName},</p>
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">We noticed you didn't complete your <strong style="color:#c8a94e;">${serviceName} ${planName}</strong> checkout. No worries — your spot is still available.</p>
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Here's what you'll get:</p>
                    <ul style="font-size:15px;color:#8e897e;line-height:2;padding-left:20px;margin-bottom:32px;">
                      <li>94% challenge pass rate with Tier Pass</li>
                      <li>Professional funded account management</li>
                      <li>Premium trading dashboard with live signals</li>
                      <li>7-day money-back guarantee</li>
                    </ul>
                    <div style="text-align:center;margin:32px 0;">
                      <a href="https://tieralba.com/checkout?plan=${abandonedMeta.productKey || ''}" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Complete Your Purchase</a>
                    </div>
                    <p style="font-size:14px;color:#8e897e;line-height:1.7;">Questions? Reply to this email — we're here to help.</p>
                  </div>
                  <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                    <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                  </div>
                </div>`
            });
            console.log(`📧 Abandoned checkout email sent to ${abandonedEmail}`);
          } catch (emailErr) {
            console.error('Abandoned checkout email error (non-fatal):', emailErr.message);
          }
        }
        break;
      }

      // ─── PAYMENT FAILED ───
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const failedEmail = invoice.customer_email;
        
        if (failedEmail && resend) {
          try {
            await resend.emails.send({
              from: emailFrom(),
              to: failedEmail,
              subject: 'TierAlba — Payment Failed — Action Required',
              html: `
                <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                  <div style="background:#e87272;padding:32px;text-align:center;">
                    <h1 style="color:#fff;margin:0;font-size:24px;">⚠ Payment Failed</h1>
                  </div>
                  <div style="padding:40px 32px;color:#ece8de;">
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Your latest payment for TierAlba could not be processed. This may be due to insufficient funds, an expired card, or a bank decline.</p>
                    <p style="font-size:16px;line-height:1.8;margin-bottom:24px;"><strong style="color:#e87272;">If not resolved, your subscription will be cancelled</strong> and you will lose access to premium features and EA licenses.</p>
                    <div style="text-align:center;margin:32px 0;">
                      <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Update Payment Method</a>
                    </div>
                    <p style="font-size:14px;color:#8e897e;line-height:1.7;">Need help? Contact support@tieralba.com</p>
                  </div>
                  <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                    <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                  </div>
                </div>`
            });
            console.log(`📧 Payment failed email sent to ${failedEmail}`);
            sendTelegramNotification(`🔴 <b>Payment Failed</b>\n\n📧 ${failedEmail}`);
          } catch (emailErr) {
            console.error('Payment failed email error (non-fatal):', emailErr.message);
          }
        }
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

// ============================================
// MAINTENANCE MODE — coming soon ONLY on custom domain (tieralba.com)
// Railway domain shows the full site for testing
// Set MAINTENANCE_MODE=true and CUSTOM_DOMAIN=tieralba.com in env
// Remove or set MAINTENANCE_MODE=false when ready to launch
// ============================================
const MAINTENANCE_MODE = process.env.MAINTENANCE_MODE === 'true';
const CUSTOM_DOMAIN = process.env.CUSTOM_DOMAIN || 'tieralba.com';

if (MAINTENANCE_MODE) {
  app.use((req, res, next) => {
    const host = req.hostname || req.headers.host || '';
    // Only show coming soon on custom domain
    if (!host.includes(CUSTOM_DOMAIN)) return next();
    // Let API calls through
    if (req.path.startsWith('/api/') || req.path.startsWith('/health')) return next();
    // Let static files through
    if (req.path.match(/\.(png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|eot|webp)$/)) return next();
    // Coming soon for everything else
    return res.sendFile(path.join(__dirname, 'public', 'coming-soon.html'));
  });
  console.log('🚧 MAINTENANCE MODE ACTIVE — coming-soon on ' + CUSTOM_DOMAIN + ' only');
}

// SEO: Sitemap & Robots
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
});
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
});

// Explicit routes FIRST (before static, so landing.html is served on /)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/partner', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'partner.html'));
});

app.get('/about', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

app.get('/faq', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'faq.html'));
});

// Legal pages
['privacy-policy','terms-of-service','refund-policy','legal-notice','cookie-policy'].forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', `${page}.html`));
  });
});

// Checkout page
app.get('/checkout', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout.html'));
});

// Checkout success page
app.get('/checkout-success', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkout-success.html'));
});

// Serve frontend static files (CSS, JS, images, other HTML)
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// PRODUCT CATALOG — maps productKey to Stripe priceId and service type
// ============================================
const PRODUCT_CATALOG = {
  // TIER PASS (one-time) — service: tierpass, access: ea_license
  'tierpass-5k':    { priceId:'price_1T4QOGRo0AfnvbiMs6bhWvFT', mode:'payment', service:'tierpass', planLabel:'Bronze 5K', price:59 },
  'tierpass-10k':   { priceId:'price_1T46xCRo0AfnvbiMLk7ymv3u', mode:'payment', service:'tierpass', planLabel:'Silver 10K', price:99 },
  'tierpass-25k':   { priceId:'price_1T4QPURo0AfnvbiMgqgCy4vL', mode:'payment', service:'tierpass', planLabel:'Gold 25K', price:149 },
  'tierpass-50k':   { priceId:'price_1T4QQPRo0AfnvbiMlZh4ItLs', mode:'payment', service:'tierpass', planLabel:'Platinum 50K', price:199 },
  'tierpass-100k':  { priceId:'price_1T4QRHRo0AfnvbiMR4tk1UrV', mode:'payment', service:'tierpass', planLabel:'Emerald 100K', price:249 },
  'tierpass-200k':  { priceId:'price_1T4QS8Ro0AfnvbiMFB2JFCxF', mode:'payment', service:'tierpass', planLabel:'Diamond 200K', price:349 },
  // TIER MANAGE (one-time) — service: tiermanage
  'tiermanage-lite':    { priceId:'price_1T4QTTRo0AfnvbiMVkaj2o2t', mode:'payment', service:'tiermanage', planLabel:'Lite Funded', price:89 },
  'tiermanage-starter': { priceId:'price_1T4QUHRo0AfnvbiMWSUhvetr', mode:'payment', service:'tiermanage', planLabel:'Starter Funded', price:149 },
  'tiermanage-pro':     { priceId:'price_1T4QVERo0AfnvbiM4bChqkQH', mode:'payment', service:'tiermanage', planLabel:'Pro Funded', price:299 },
  // TRADESALBA (subscription) — service: tradesalba
  'tradesalba-standard-m': { priceId:'price_1Sx9ZARo0AfnvbiMbWiYdZ0n', mode:'subscription', service:'tradesalba', planLabel:'Standard Monthly', price:49, taPlan:'standard' },
  'tradesalba-standard-y': { priceId:'price_1Sx9hbRo0AfnvbiMmM69HQ6c', mode:'subscription', service:'tradesalba', planLabel:'Standard Yearly', price:399, taPlan:'standard' },
  'tradesalba-pro-m':      { priceId:'price_1Sx9bMRo0AfnvbiMVTcum8SM', mode:'subscription', service:'tradesalba', planLabel:'Pro Monthly', price:89, taPlan:'pro' },
  'tradesalba-pro-y':      { priceId:'price_1Sx9qRRo0AfnvbiMwhCq3fPx', mode:'subscription', service:'tradesalba', planLabel:'Pro Yearly', price:699, taPlan:'pro' },
};

// Reverse lookup: priceId → product info
const PRICE_TO_PRODUCT = {};
Object.entries(PRODUCT_CATALOG).forEach(([key, val]) => {
  PRICE_TO_PRODUCT[val.priceId] = { ...val, productKey: key };
});

// ============================================
// CHECKOUT API — Register + Create Stripe Session
// ============================================
app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(400).json({ error: 'Payment system not configured' });
  
  try {
    const { firstName, lastName, email, phone, country, password, marketing_consent, productKey, priceId, mode } = req.body;
    
    // Validate required fields
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (!productKey || !PRODUCT_CATALOG[productKey]) {
      return res.status(400).json({ error: 'Invalid product selected' });
    }
    
    const product = PRODUCT_CATALOG[productKey];
    const emailLower = email.toLowerCase().trim();
    
    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [emailLower]);
    
    let userId;
    
    if (existingUser.rows.length > 0) {
      // User exists — verify password to allow re-purchase
      const userCheck = await pool.query('SELECT id, password_hash FROM users WHERE LOWER(email) = $1', [emailLower]);
      const validPw = await bcrypt.compare(password, userCheck.rows[0].password_hash);
      if (!validPw) {
        return res.status(400).json({ error: 'An account with this email already exists. Please use the correct password or log in first.' });
      }
      userId = userCheck.rows[0].id;
    } else {
      // Create new user account
      const passwordHash = await bcrypt.hash(password, 10);
      const crypto = require('crypto');
      const verifyToken = crypto.randomBytes(32).toString('hex');
      const userName = `${firstName} ${lastName}`.trim();
      
      const result = await pool.query(
        `INSERT INTO users (email, password_hash, name, first_name, last_name, country, phone, verify_token, email_verified, marketing_consent, plan)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
        [emailLower, passwordHash, userName, firstName, lastName, country||null, phone||null, verifyToken, false, marketing_consent||false, 'free']
      );
      userId = result.rows[0].id;
      
      // NOTE: Welcome + verification email is sent by the webhook (checkout.session.completed)
      // together with purchase confirmation to avoid sending 2 emails at once
    }
    
    // Create Stripe checkout session
    const baseUrl = process.env.APP_URL || req.headers.origin || 'https://tieralba.com';
    
    const sessionConfig = {
      payment_method_types: ['card'],
      customer_email: emailLower,
      line_items: [{ price: product.priceId, quantity: 1 }],
      success_url: `${baseUrl}/checkout-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/checkout?plan=${productKey}&cancelled=true`,
      metadata: {
        userId: userId.toString(),
        productKey: productKey,
        service: product.service,
        planLabel: product.planLabel
      }
    };
    
    // Set mode based on product type
    if (product.mode === 'subscription') {
      sessionConfig.mode = 'subscription';
    } else {
      sessionConfig.mode = 'payment';
    }
    
    // For Klarna support (EU)
    if (product.mode === 'payment') {
      sessionConfig.payment_method_types = ['card', 'klarna'];
    }
    
    const session = await stripe.checkout.sessions.create(sessionConfig);
    
    console.log(`🛒 Checkout created: ${emailLower} → ${product.planLabel} (${product.service})`);
    
    res.json({ url: session.url });
    
  } catch (error) {
    console.error('Checkout error:', error);
    if (error.code === '23505') {
      return res.status(400).json({ error: 'An account with this email already exists.' });
    }
    res.status(500).json({ error: 'Failed to create checkout session. Please try again.' });
  }
});

// Trust proxy (Railway runs behind a proxy)
app.set('trust proxy', 1);

// Rate limiting: previene spam/attacchi
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 2000, // dashboard refresh ogni 15s = ~300 calls/15min per utente
  message: { error: 'Too many requests, please try again later' }
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
// EA LICENSE HELPER — Check if user has active service
// ============================================
// Returns true if user has TradesAlba sub OR active Tier Pass/Manage
function hasActiveService(user) {
  // TradesAlba subscription (standard/pro plan)
  if ((user.plan === 'standard' || user.plan === 'pro') && 
      (!user.plan_expires_at || new Date(user.plan_expires_at) > new Date())) {
    return true;
  }
  // Tier Pass or Tier Manage (one-time, stored in active_services)
  const services = user.active_services || {};
  if (services.tierpass?.status === 'active') return true;
  if (services.tiermanage?.status === 'active') return true;
  return false;
}

// ============================================
// PROTECTED EA FILE DOWNLOADS
// ============================================

app.get('/ea-files/:filename', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT plan, plan_expires_at, active_services FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (!hasActiveService(user.rows[0])) {
      return res.status(403).json({ error: 'Active service required to download EA files.' });
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
    const userName = name || ((first_name || '') + ' ' + (last_name || '')).trim() || fullName || '';
    const refCode = (referralCode || '').trim().toUpperCase() || null;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Generate email verification token
    const crypto = require('crypto');
    const verifyToken = crypto.randomBytes(32).toString('hex');
    
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, first_name, last_name, title, date_of_birth, country, phone, verify_token, email_verified, referred_by, marketing_consent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id, email, name, created_at`,
      [email.toLowerCase(), passwordHash, userName, first_name||null, last_name||null, title||null, date_of_birth||null, country||null, phone||null, verifyToken, false, refCode, marketing_consent||false]
    );
    
    const user = result.rows[0];
    
    // Send welcome + verification email
    const baseUrl = process.env.APP_URL || 'https://tieralba.com';
    const verifyUrl = `${baseUrl}/api/auth/verify?token=${verifyToken}`;
    
    if (resend) {
      try {
        await resend.emails.send({
          from: emailFrom(),
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
        sendTelegramNotification(`👤 <b>New User Registered</b>\n\n📧 ${email}\n👤 ${userName || 'N/A'}`);
      } catch (emailErr) {
        console.error('Email send error:', emailErr);
        // Don't fail registration if email fails
      }
    }
    
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
      'SELECT id, email, name, plan, active_services, created_at FROM users WHERE id = $1',
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
          <a href="/login" style="display:inline-block;margin-top:20px;padding:12px 32px;background:linear-gradient(135deg,#c8aa6e,#b89a5a);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:8px;">Go to Dashboard</a>
        </div>
      </body></html>
    `);
    
    // Send welcome onboarding email
    try {
      if (resend) {
        await resend.emails.send({
          from: emailFrom(),
          to: result.rows[0].email,
          subject: 'Welcome to TierAlba — Here\'s How to Get Started 🚀',
          html: `
            <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
              <div style="background:linear-gradient(135deg,#c8a94e,#b59840);padding:40px 32px;text-align:center;">
                <h1 style="color:#0a0b0f;margin:0;font-size:28px;">Welcome to TierAlba!</h1>
                <p style="color:rgba(10,11,15,0.7);margin:8px 0 0;font-size:15px;">Your email is verified. Let's get you started.</p>
              </div>
              <div style="padding:40px 32px;color:#ece8de;">
                <h2 style="font-size:20px;margin-bottom:24px;color:#c8a94e;">3 Ways We Can Help You:</h2>
                
                <div style="background:rgba(200,169,78,0.06);border:1px solid rgba(200,169,78,0.1);border-radius:12px;padding:20px;margin-bottom:16px;">
                  <h3 style="margin:0 0 8px;font-size:16px;">⚡ Tier Pass — Challenge Passing</h3>
                  <p style="margin:0;font-size:14px;color:#8e897e;line-height:1.6;">Our EA passes your prop firm challenge. 94% success rate. One-time payment.</p>
                </div>
                
                <div style="background:rgba(200,169,78,0.06);border:1px solid rgba(200,169,78,0.1);border-radius:12px;padding:20px;margin-bottom:16px;">
                  <h3 style="margin:0 0 8px;font-size:16px;">📈 Tier Manage — Account Management</h3>
                  <p style="margin:0;font-size:14px;color:#8e897e;line-height:1.6;">We manage your funded account for consistent monthly returns.</p>
                </div>
                
                <div style="background:rgba(200,169,78,0.06);border:1px solid rgba(200,169,78,0.1);border-radius:12px;padding:20px;margin-bottom:24px;">
                  <h3 style="margin:0 0 8px;font-size:16px;">📊 TradesAlba — Trading Dashboard</h3>
                  <p style="margin:0;font-size:14px;color:#8e897e;line-height:1.6;">Live signals, journal, risk tools, TradingView indicators, and broker integration.</p>
                </div>

                <div style="text-align:center;margin:32px 0;">
                  <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">Explore Your Dashboard</a>
                </div>

                <div style="background:rgba(94,224,160,0.06);border:1px solid rgba(94,224,160,0.1);border-radius:12px;padding:20px;margin-top:24px;">
                  <h3 style="margin:0 0 8px;font-size:15px;color:#5ee0a0;">💰 Earn 15% — Referral Program</h3>
                  <p style="margin:0;font-size:13px;color:#8e897e;line-height:1.6;">Share your referral link and earn 15% commission on every purchase. Find your link in the dashboard.</p>
                </div>

                <p style="font-size:14px;color:#8e897e;line-height:1.7;margin-top:24px;">Questions? Reply to this email — we're here to help.</p>
              </div>
              <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
              </div>
            </div>`
        });
        console.log(`📧 Welcome onboarding email sent to ${result.rows[0].email}`);
      }
    } catch (welcomeErr) {
      console.error('Welcome email error (non-fatal):', welcomeErr.message);
    }
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

    const crypto = require('crypto');
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [resetToken, expires, user.rows[0].id]
    );

    const baseUrl = process.env.APP_URL || `https://${process.env.RAILWAY_PUBLIC_DOMAIN || 'tieralba.com'}`;
    const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
    const userName = user.rows[0].name || '';

    if (resend) {
      await resend.emails.send({
        from: emailFrom(),
        to: [email.toLowerCase()],
        subject: 'TierAlba — Reset Your Password',
        html: `
          <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;color:#f0ede6;padding:0;">
            <div style="background:#12131a;padding:32px 40px;border-bottom:1px solid rgba(255,255,255,0.06);text-align:center;">
              <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
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

    const passwordHash = await bcrypt.hash(newPassword, 10);
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
      totalWinAmount: parseFloat(winningSum.rows[0]?.sum) || 0,
      totalLossAmount: parseFloat(losingSum.rows[0]?.sum) || 0,
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
      console.error('MetaApi error:', JSON.stringify(metaAccount));
      console.error('Sent data:', { login: accountNumber, server: brokerName, platform: platform.toLowerCase() });
      
      let errorMsg = metaAccount.message || 'Failed to connect.';
      // Make error more helpful
      if (errorMsg.includes('Invalid account') || errorMsg.includes('Account disabled') || errorMsg.includes('authenticate')) {
        errorMsg = `Connection failed. Please verify: 1) Account number "${accountNumber}" is correct, 2) Server name "${brokerName}" matches exactly what appears in your MetaTrader terminal (File → Login → Server field), 3) You are using the Investor/Viewer password (not the master password), 4) Platform (${platform.toUpperCase()}) matches your account type.`;
      }
      return res.status(400).json({ error: errorMsg });
    }

    // Deploy the account
    await fetch(`https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai/users/current/accounts/${metaAccount.id}/deploy`, {
      method: 'POST',
      headers: { 'auth-token': metaApiToken }
    });

    // Deactivate old connections and CLEAR old data
    const existing = await pool.query(
      'SELECT id FROM broker_connections WHERE user_id = $1 AND is_active = true',
      [userId]
    );
    if (existing.rows.length > 0) {
      await pool.query('UPDATE broker_connections SET is_active = false WHERE user_id = $1', [userId]);
      // Clear old broker data so new account starts fresh
      await pool.query('DELETE FROM trades WHERE user_id = $1', [userId]);
      await pool.query('DELETE FROM equity_snapshots WHERE user_id = $1', [userId]);
      console.log(`🧹 Cleared old trades & equity data for user ${userId} (new broker connected)`);
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
    // Clear trade data from old broker
    await pool.query('DELETE FROM trades WHERE user_id = $1', [req.userId]);
    await pool.query('DELETE FROM equity_snapshots WHERE user_id = $1', [req.userId]);
    console.log(`🧹 Broker disconnected + data cleared for user ${req.userId}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

// Reset broker data — clears old trades/equity and forces re-sync from current broker
app.post('/api/broker/reset-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    // Clear all old data
    const delTrades = await pool.query('DELETE FROM trades WHERE user_id = $1', [userId]);
    const delEquity = await pool.query('DELETE FROM equity_snapshots WHERE user_id = $1', [userId]);
    console.log(`🧹 Reset data for user ${userId}: ${delTrades.rowCount} trades, ${delEquity.rowCount} equity snapshots deleted`);
    res.json({ success: true, message: `Cleared ${delTrades.rowCount} trades and ${delEquity.rowCount} equity snapshots. Sync now to load fresh data.` });
  } catch (error) {
    console.error('Reset data error:', error);
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

// PANIC: Close all open trades
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
      const crypto = require('crypto');
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
    sendTelegramNotification(`💸 <b>Payout Request</b>\n\n💰 €${balance.toFixed(2)}\n🔗 ${wallet}`);
    
    // Send payout request confirmation + admin notification
    try {
      if (resend) {
        const userData = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
        if (userData.rows[0]) {
          // User confirmation
          await resend.emails.send({
            from: emailFrom(),
            to: userData.rows[0].email,
            subject: `TierAlba — Payout Request Received (€${balance.toFixed(2)})`,
            html: `
              <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                <div style="padding:40px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.05);">
                  <h1 style="color:#5ee0a0;margin:0;font-size:26px;">Payout Request Received</h1>
                </div>
                <div style="padding:40px 32px;color:#ece8de;">
                  <div style="background:rgba(94,224,160,0.08);border:1px solid rgba(94,224,160,0.15);border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
                    <div style="font-size:36px;font-weight:700;color:#5ee0a0;">€${balance.toFixed(2)}</div>
                    <div style="font-size:13px;color:#8e897e;margin-top:8px;">→ USDT (TRC-20)</div>
                  </div>
                  <p style="font-size:15px;line-height:1.8;color:#8e897e;margin-bottom:8px;"><strong style="color:#ece8de;">Wallet:</strong> ${wallet}</p>
                  <p style="font-size:15px;line-height:1.8;color:#8e897e;margin-bottom:24px;"><strong style="color:#ece8de;">Status:</strong> <span style="color:#c8a94e;">Processing (within 48h)</span></p>
                  <p style="font-size:14px;color:#8e897e;line-height:1.7;">You'll receive a confirmation once the transfer is complete.</p>
                </div>
                <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                  <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                </div>
              </div>`
          });
          
          // Admin notification
          const adminEmail = process.env.ADMIN_EMAIL || 'support@tieralba.com';
          await resend.emails.send({
            from: emailFrom(),
            to: adminEmail,
            subject: `[ADMIN] Payout Request: €${balance.toFixed(2)} → ${wallet}`,
            html: `<div style="font-family:monospace;padding:20px;background:#111;color:#eee;border-radius:8px;">
              <h2>New Payout Request</h2>
              <p><strong>User:</strong> ${userData.rows[0].email}</p>
              <p><strong>Amount:</strong> €${balance.toFixed(2)}</p>
              <p><strong>Wallet:</strong> ${wallet}</p>
              <p><strong>Time:</strong> ${new Date().toISOString()}</p>
            </div>`
          });
        }
      }
    } catch (emailErr) {
      console.error('Payout email error (non-fatal):', emailErr.message);
    }
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
app.post('/api/signals', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

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
app.put('/api/signals/:id', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

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
app.delete('/api/signals/:id', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

    const result = await pool.query('DELETE FROM signals WHERE id = $1 RETURNING id', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Signal not found' });

    console.log(`Signal ${req.params.id} deleted by admin`);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete signal error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all signals for admin
app.get('/api/admin/signals', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    
    if (adminKey !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

    const result = await pool.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 100');
    res.json({ signals: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// EA auto-close signal by symbol
app.post('/api/ea/close-signal', async (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });

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
    sendTelegramNotification(`🔄 <b>Refund Request</b>\n\n📧 ${userResult.rows[0].email}\n📋 ${reason}\n💬 ${(details || '').substring(0, 100)}`);
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
      success_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba.com'}/dashboard?upgrade=success`,
      cancel_url: `${req.headers.origin || process.env.FRONTEND_URL || 'https://tieralba.com'}/dashboard?upgrade=cancelled`,
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
      return_url: `${req.headers.origin || 'https://tieralba.com'}/dashboard`
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
      `SELECT el.*, u.plan, u.plan_expires_at, u.email, u.active_services
       FROM ea_licenses el
       JOIN users u ON u.id = el.user_id
       WHERE el.license_key = $1 AND el.product = $2 AND el.is_active = true`,
      [license_key, product || 'any']
    );

    if (result.rows.length === 0) {
      return res.json({ valid: false, error: 'License not found or inactive' });
    }

    const license = result.rows[0];

    // Check if user has any active service (sub OR tierpass/tiermanage)
    if (!hasActiveService(license)) {
      return res.json({ valid: false, expired: true, error: 'Service expired or inactive' });
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

// POST /api/ea/license/generate — Generate license keys for user (requires auth + active service)
app.post('/api/ea/license/generate', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT plan, plan_expires_at, active_services FROM users WHERE id = $1', [req.userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (!hasActiveService(user.rows[0])) {
      return res.status(403).json({ error: 'No active service. Purchase a plan to generate license keys.' });
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

    const newHash = await bcrypt.hash(newPassword, 10);
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
    sendTelegramNotification(`📩 <b>Support Message</b>\n\n📧 ${user.email}\n📋 ${subject}\n💬 ${message.substring(0, 150)}`);

    // Send notification email (not the message itself, just a heads-up)
    if (resend) {
      try {
        await resend.emails.send({
          from: emailFrom(),
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
// ============================================
// ADMIN PANEL API ENDPOINTS
// ============================================
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'info@tieralba.com').split(',').map(e => e.trim().toLowerCase());

function isAdmin(email) {
  return ADMIN_EMAILS.includes(email?.toLowerCase());
}

// Middleware: verify admin
async function authenticateAdmin(req, res, next) {
  // First verify JWT token
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    
    // Check if user is admin
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    
    if (!isAdmin(result.rows[0].email)) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Get all clients with services info
app.get('/api/admin/clients', authenticateAdmin, async (req, res) => {
  try {
    const users = await pool.query(
      `SELECT id, email, name, plan, active_services, stripe_customer_id, created_at 
       FROM users ORDER BY created_at DESC`
    );

    // Stats
    const totalUsers = users.rows.length;
    const activeServices = users.rows.filter(u => {
      const s = u.active_services || {};
      return Object.values(s).some(v => v.status === 'active');
    }).length;

    let totalRevenue = 0, monthRevenue = 0;
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    
    try {
      const rev = await pool.query('SELECT COALESCE(SUM(amount), 0) as total FROM purchases');
      totalRevenue = parseFloat(rev.rows[0].total || 0).toFixed(0);
      const monthRev = await pool.query('SELECT COALESCE(SUM(amount), 0) as total FROM purchases WHERE created_at >= $1', [monthStart]);
      monthRevenue = parseFloat(monthRev.rows[0].total || 0).toFixed(0);
    } catch (e) { /* purchases table might not exist yet */ }

    res.json({ 
      users: users.rows,
      stats: { total_users: totalUsers, active_services: activeServices, total_revenue: totalRevenue, month_revenue: monthRevenue }
    });
  } catch (error) {
    console.error('Admin clients error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get recent purchases
app.get('/api/admin/purchases', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM purchases ORDER BY created_at DESC LIMIT 50'
    );
    res.json({ purchases: result.rows });
  } catch (error) {
    // Table might not exist yet
    res.json({ purchases: [] });
  }
});

// Update user services & plan
app.post('/api/admin/update-user', authenticateAdmin, async (req, res) => {
  try {
    const { userId, active_services, plan } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    await pool.query(
      'UPDATE users SET active_services = $1, plan = $2 WHERE id = $3',
      [JSON.stringify(active_services || {}), plan || 'free', userId]
    );

    // If user no longer has any active service that grants EA access, deactivate their EA licenses
    // EA access comes from: tierpass, tiermanage, or a paid TradesAlba subscription (standard/pro)
    const services = active_services || {};
    const hasEAAccess = 
      services.tierpass?.status === 'active' ||
      services.tiermanage?.status === 'active' ||
      services.tradesalba?.status === 'active';
    
    if (!hasEAAccess) {
      const deactivated = await pool.query(
        'UPDATE ea_licenses SET is_active = false WHERE user_id = $1 AND is_active = true RETURNING id',
        [userId]
      );
      if (deactivated.rowCount > 0) {
        console.log(`🔑 Admin deactivated ${deactivated.rowCount} license(s) for user ${userId}`);
      }
    }

    console.log(`🔧 Admin updated user ${userId}: plan=${plan}, services=${JSON.stringify(active_services)}`);
    
    // Notify user about account changes
    if (resend) {
      try {
        const userData = await pool.query('SELECT email, name FROM users WHERE id = $1', [userId]);
        if (userData.rows[0]) {
          const u = userData.rows[0];
          const serviceNames = { tierpass: 'Tier Pass', tiermanage: 'Tier Manage', tradesalba: 'TradesAlba' };
          const activeList = Object.entries(services)
            .filter(([, v]) => v.status === 'active')
            .map(([k, v]) => `${serviceNames[k] || k} — ${v.plan || 'Active'}`)
            .join(', ') || 'None';
          
          await resend.emails.send({
            from: emailFrom(),
            to: u.email,
            subject: hasAnyActive 
              ? 'TierAlba — Your Account Has Been Updated ✅' 
              : 'TierAlba — Your Account Services Have Changed',
            html: `
              <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0b0f;border-radius:16px;overflow:hidden;">
                    <div style="padding:24px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06);">
                      <img src="https://tieralba.com/logo.png" alt="TierAlba" style="height:40px;width:auto;" />
                    </div>
                <div style="padding:40px 32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.05);">
                  <h1 style="color:#ece8de;margin:0;font-size:26px;">Account Update</h1>
                </div>
                <div style="padding:40px 32px;color:#ece8de;">
                  <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Hi${u.name ? ' ' + u.name.split(' ')[0] : ''},</p>
                  <p style="font-size:16px;line-height:1.8;margin-bottom:24px;">Your TierAlba account has been updated by our team.</p>
                  <div style="background:rgba(200,169,78,0.06);border:1px solid rgba(200,169,78,0.1);border-radius:12px;padding:20px;margin-bottom:24px;">
                    <p style="margin:0 0 8px;font-size:14px;color:#8e897e;"><strong style="color:#ece8de;">Plan:</strong> ${(plan || 'free').charAt(0).toUpperCase() + (plan || 'free').slice(1)}</p>
                    <p style="margin:0;font-size:14px;color:#8e897e;"><strong style="color:#ece8de;">Active services:</strong> ${activeList}</p>
                  </div>
                  ${!hasAnyActive ? '<p style="font-size:15px;line-height:1.8;margin-bottom:24px;color:#e87272;">Your EA license keys have been deactivated. If you believe this is an error, please contact support.</p>' : ''}
                  <div style="text-align:center;margin:32px 0;">
                    <a href="https://tieralba.com/dashboard" style="display:inline-block;padding:16px 40px;background:linear-gradient(135deg,#c8a94e,#b59840);color:#0a0b0f;text-decoration:none;font-weight:700;border-radius:10px;font-size:14px;">View Dashboard</a>
                  </div>
                  <p style="font-size:14px;color:#8e897e;line-height:1.7;">Questions? Contact support@tieralba.com</p>
                </div>
                <div style="padding:24px 32px;border-top:1px solid rgba(255,255,255,0.05);text-align:center;">
                  <p style="font-size:12px;color:#55514a;margin:0;">© ${new Date().getFullYear()} TierAlba · All rights reserved</p>
                </div>
              </div>`
          });
          console.log(`📧 Account update email sent to ${u.email}`);
        }
      } catch (notifErr) {
        console.error('Admin update notification email error (non-fatal):', notifErr.message);
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
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

app.listen(port, () => {
  console.log('=================================');
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) console.log('📱 Telegram notifications: ACTIVE');
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
