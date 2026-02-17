-- ============================================
-- TIERALBA DATABASE SCHEMA
-- ============================================
-- Questo file crea tutte le tabelle necessarie
-- Esegui questo SQL su Supabase dopo aver creato il progetto
-- ============================================

-- Tabella UTENTI
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Indice per ricerca veloce per email
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================

-- Tabella CONNESSIONI BROKER
CREATE TABLE IF NOT EXISTS broker_connections (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform VARCHAR(10) NOT NULL CHECK (platform IN ('mt4', 'mt5')),
  api_key_encrypted TEXT NOT NULL,
  api_secret_encrypted TEXT NOT NULL,
  account_number VARCHAR(50) NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Indice per ricerca per utente
CREATE INDEX IF NOT EXISTS idx_broker_user ON broker_connections(user_id);

-- ============================================

-- Tabella TRADE
CREATE TABLE IF NOT EXISTS trades (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  symbol VARCHAR(20) NOT NULL,
  type VARCHAR(10) NOT NULL CHECK (type IN ('BUY', 'SELL')),
  lots DECIMAL(10,2) NOT NULL,
  entry_price DECIMAL(10,5) NOT NULL,
  exit_price DECIMAL(10,5),
  profit DECIMAL(12,2) DEFAULT 0,
  opened_at TIMESTAMP,
  closed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Indici per query veloci
CREATE INDEX IF NOT EXISTS idx_trades_user ON trades(user_id);
CREATE INDEX IF NOT EXISTS idx_trades_closed ON trades(closed_at DESC);
CREATE INDEX IF NOT EXISTS idx_trades_symbol ON trades(symbol);

-- ============================================

-- Tabella SNAPSHOT EQUITY
CREATE TABLE IF NOT EXISTS equity_snapshots (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  equity DECIMAL(12,2) NOT NULL,
  recorded_at TIMESTAMP DEFAULT NOW()
);

-- Indici per query veloci
CREATE INDEX IF NOT EXISTS idx_equity_user ON equity_snapshots(user_id);
CREATE INDEX IF NOT EXISTS idx_equity_date ON equity_snapshots(recorded_at DESC);

-- ============================================

-- FUNZIONE per aggiornare timestamp automaticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger per aggiornare updated_at automaticamente
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_broker_updated_at BEFORE UPDATE ON broker_connections
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_trades_updated_at BEFORE UPDATE ON trades
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================

-- Tabella SIGNALS (Trading Signals)
CREATE TABLE IF NOT EXISTS signals (
  id SERIAL PRIMARY KEY,
  source VARCHAR(20) DEFAULT 'team',
  symbol VARCHAR(20) NOT NULL,
  direction VARCHAR(10) NOT NULL CHECK (direction IN ('BUY', 'SELL')),
  entry_price VARCHAR(20),
  stop_loss VARCHAR(20),
  tp1 VARCHAR(20),
  tp2 VARCHAR(20),
  tp3 VARCHAR(20),
  notes TEXT,
  status VARCHAR(20) DEFAULT 'active',
  result VARCHAR(20),
  closed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Indici per query veloci
CREATE INDEX IF NOT EXISTS idx_signals_status ON signals(status);
CREATE INDEX IF NOT EXISTS idx_signals_created ON signals(created_at DESC);

-- ============================================

-- Tabella EA LICENSES
CREATE TABLE IF NOT EXISTS ea_licenses (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  license_key VARCHAR(30) NOT NULL UNIQUE,
  product VARCHAR(50) NOT NULL DEFAULT 'any',
  is_active BOOLEAN NOT NULL DEFAULT true,
  mt_account BIGINT,
  verification_count INTEGER NOT NULL DEFAULT 0,
  last_verified TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ea_licenses_key ON ea_licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_ea_licenses_user ON ea_licenses(user_id);

-- ============================================

-- Tabella REFERRAL COMMISSIONS
CREATE TABLE IF NOT EXISTS referral_commissions (
  id SERIAL PRIMARY KEY,
  referrer_id INTEGER REFERENCES users(id),
  referred_id INTEGER REFERENCES users(id),
  referred_email VARCHAR,
  plan_purchased VARCHAR,
  sale_amount NUMERIC(10,2),
  commission_rate NUMERIC(4,2) DEFAULT 15.00,
  commission_amount NUMERIC(10,2),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commissions_referrer ON referral_commissions(referrer_id);

-- ============================================

-- Tabella REFERRAL PAYOUTS
CREATE TABLE IF NOT EXISTS referral_payouts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  amount NUMERIC(10,2) NOT NULL,
  usdt_wallet VARCHAR NOT NULL,
  status VARCHAR DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW(),
  processed_at TIMESTAMP,
  admin_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_payouts_user ON referral_payouts(user_id);
CREATE INDEX IF NOT EXISTS idx_payouts_status ON referral_payouts(status);

-- ============================================

-- Tabella REFUND REQUESTS
CREATE TABLE IF NOT EXISTS refund_requests (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR NOT NULL,
  reason VARCHAR NOT NULL,
  details TEXT,
  status VARCHAR DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at TIMESTAMP DEFAULT NOW(),
  reviewed_at TIMESTAMP,
  admin_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_refund_status ON refund_requests(status);
CREATE INDEX IF NOT EXISTS idx_refund_user ON refund_requests(user_id);

-- ============================================

-- Colonne aggiuntive per users (plan, stripe, referral, email verify)
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan VARCHAR DEFAULT 'free';
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by VARCHAR;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_balance NUMERIC(10,2) DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_total_earned NUMERIC(10,2) DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS usdt_wallet VARCHAR;

CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_users_plan ON users(plan);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);

-- Colonne aggiuntive per broker_connections
ALTER TABLE broker_connections ADD COLUMN IF NOT EXISTS broker_name VARCHAR;
ALTER TABLE broker_connections ADD COLUMN IF NOT EXISTS metaapi_account_id VARCHAR;
ALTER TABLE broker_connections ALTER COLUMN api_key_encrypted DROP NOT NULL;
ALTER TABLE broker_connections ALTER COLUMN api_secret_encrypted DROP NOT NULL;

-- Colonna balance per equity_snapshots
ALTER TABLE equity_snapshots ADD COLUMN IF NOT EXISTS balance DECIMAL(12,2);

-- Colonna external_id per trades (sync MetaApi)
ALTER TABLE trades ADD COLUMN IF NOT EXISTS external_id VARCHAR;
ALTER TABLE trades DROP CONSTRAINT IF EXISTS trades_type_check;
ALTER TABLE trades ADD CONSTRAINT trades_type_check CHECK (type IN ('BUY', 'SELL', 'buy', 'sell'));
CREATE UNIQUE INDEX IF NOT EXISTS idx_trades_external ON trades(user_id, external_id) WHERE external_id IS NOT NULL;

-- ============================================

-- DATI DI TEST (opzionale - per testare)
-- ATTENZIONE: Password è "password123" hashata
-- Email: test@tieralba.com

INSERT INTO users (email, password_hash, name) VALUES 
('test@tieralba.com', '$2b$10$XqBVvfF7J6YYYw8yQ.HrPOQG9KX8W7GYXO3Z3fZ3f3f3f3f3f3f3f', 'Test User')
ON CONFLICT (email) DO NOTHING;

-- Trade di esempio (opzionale)
-- Questi saranno collegati all'utente test@tieralba.com (id = 1)
INSERT INTO trades (user_id, symbol, type, lots, entry_price, exit_price, profit, opened_at, closed_at) VALUES
(1, 'EUR/USD', 'BUY', 0.5, 1.0845, 1.0892, 235.00, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
(1, 'GBP/USD', 'SELL', 0.3, 1.2634, 1.2618, 48.00, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days'),
(1, 'USD/JPY', 'BUY', 0.4, 149.82, 149.45, -148.00, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days')
ON CONFLICT DO NOTHING;

-- Snapshot equity di esempio
INSERT INTO equity_snapshots (user_id, equity, recorded_at) VALUES
(1, 50000, NOW() - INTERVAL '30 days'),
(1, 50500, NOW() - INTERVAL '25 days'),
(1, 51200, NOW() - INTERVAL '20 days'),
(1, 51800, NOW() - INTERVAL '15 days'),
(1, 52200, NOW() - INTERVAL '10 days'),
(1, 52600, NOW() - INTERVAL '5 days'),
(1, 52847, NOW())
ON CONFLICT DO NOTHING;

-- ============================================
-- FINE SCRIPT
-- ============================================

-- Per verificare che tutto sia stato creato:
SELECT 'Tables created successfully!' as status;
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
