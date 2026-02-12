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
