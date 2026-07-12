-- ═══════════════════════════════════════════════════════════
-- E-Social Verified Logs — Supabase Schema
-- Run this in Supabase SQL Editor (New Query → Run)
-- ═══════════════════════════════════════════════════════════

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ══════════════════════════════════════════════════
-- USERS TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    wallet_balance DECIMAL(12,2) DEFAULT 0,
    referral_code TEXT UNIQUE,
    referral_count INTEGER DEFAULT 0,
    referral_earnings DECIMAL(12,2) DEFAULT 0,
    referred_by UUID REFERENCES users(id) ON DELETE SET NULL,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);

-- ══════════════════════════════════════════════════
-- TRANSACTIONS TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'number_purchase', 'boost_purchase', 'account_purchase', 'giftcard_redeem', 'referral_bonus')),
    amount DECIMAL(12,2) NOT NULL,
    balance_after DECIMAL(12,2),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
    tx_ref TEXT,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_tx_ref ON transactions(tx_ref);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);

-- ══════════════════════════════════════════════════
-- NUMBER ORDERS TABLE (5SIM virtual numbers)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS number_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    order_id TEXT NOT NULL,
    product TEXT NOT NULL,
    country TEXT NOT NULL,
    phone_number TEXT,
    supplier_cost DECIMAL(12,2),
    user_price DECIMAL(12,2),
    profit DECIMAL(12,2) DEFAULT 0,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'received', 'cancelled', 'finished', 'expired')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_number_orders_user_id ON number_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_number_orders_order_id ON number_orders(order_id);
CREATE INDEX IF NOT EXISTS idx_number_orders_status ON number_orders(status);

-- ══════════════════════════════════════════════════
-- BOOST ORDERS TABLE (SMM Panel)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS boost_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    smm_order_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    service_name TEXT,
    link TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    supplier_cost DECIMAL(12,2),
    user_price DECIMAL(12,2),
    profit DECIMAL(12,2) DEFAULT 0,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'partial', 'cancelled', 'refunded')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_boost_orders_user_id ON boost_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_boost_orders_smm_order_id ON boost_orders(smm_order_id);
CREATE INDEX IF NOT EXISTS idx_boost_orders_status ON boost_orders(status);

-- ══════════════════════════════════════════════════
-- ACCOUNTS TABLE (Verified social media accounts for sale)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    platform TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    price DECIMAL(12,2) NOT NULL,
    country TEXT,
    followers_count INTEGER DEFAULT 0,
    has_og_email BOOLEAN DEFAULT FALSE,
    email_username TEXT,
    account_password TEXT,
    recovery_email TEXT,
    recovery_phone TEXT,
    extra_notes TEXT,
    status TEXT DEFAULT 'available' CHECK (status IN ('available', 'sold', 'reserved')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accounts_platform ON accounts(platform);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_price ON accounts(price);

-- ══════════════════════════════════════════════════
-- ACCOUNT PURCHASES TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS account_purchases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    price_paid DECIMAL(12,2) NOT NULL,
    purchased_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_account_purchases_user_id ON account_purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_account_purchases_account_id ON account_purchases(account_id);

-- ══════════════════════════════════════════════════
-- COUPONS TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS coupons (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT UNIQUE NOT NULL,
    discount_percent DECIMAL(5,2),
    discount_amount DECIMAL(12,2),
    max_uses INTEGER DEFAULT 100,
    used_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'expired', 'disabled')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons(code);
CREATE INDEX IF NOT EXISTS idx_coupons_status ON coupons(status);

-- ══════════════════════════════════════════════════
-- GIFT CARDS TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS gift_cards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT UNIQUE NOT NULL,
    amount DECIMAL(12,2) NOT NULL,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'redeemed', 'expired')),
    redeemed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    redeemed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gift_cards_code ON gift_cards(code);
CREATE INDEX IF NOT EXISTS idx_gift_cards_status ON gift_cards(status);

-- ══════════════════════════════════════════════════
-- TICKETS TABLE (Support)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tickets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    priority TEXT DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);

-- ══════════════════════════════════════════════════
-- TICKET REPLIES TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ticket_replies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    is_admin_reply BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ticket_replies_ticket_id ON ticket_replies(ticket_id);

-- ══════════════════════════════════════════════════
-- WITHDRAWALS TABLE
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS withdrawals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(12,2) NOT NULL,
    bank_name TEXT,
    account_number TEXT,
    account_name TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'completed')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id ON withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);

-- ══════════════════════════════════════════════════
-- SETTINGS TABLE (Admin profit markup, etc.)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default profit markup settings
INSERT INTO settings (key, value) VALUES
    ('markup_pct_numbers', '20'),
    ('markup_flat_numbers', '0'),
    ('markup_pct_boost', '25'),
    ('markup_flat_boost', '0'),
    ('markup_pct_accounts', '0'),
    ('markup_flat_accounts', '0')
ON CONFLICT (key) DO NOTHING;

-- ══════════════════════════════════════════════════
-- NOTIFICATIONS TABLE (Admin alerts)
-- ══════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info' CHECK (type IN ('info', 'warning', 'success', 'error')),
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);

-- ══════════════════════════════════════════════════
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Enable RLS on all tables for security
-- ══════════════════════════════════════════════════

-- Users: users can only read/update their own row
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- For server-side operations (using service_role key), RLS is bypassed
-- These policies are for if you ever allow direct client access

-- ══════════════════════════════════════════════════
-- TRIGGERS
-- ══════════════════════════════════════════════════

-- Auto-update updated_at on tickets
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_tickets_updated_at ON tickets;
CREATE TRIGGER update_tickets_updated_at
    BEFORE UPDATE ON tickets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ══════════════════════════════════════════════════
-- SEED DATA (Optional test data)
-- ══════════════════════════════════════════════════

-- Add a test verified account (Instagram example)
-- INSERT INTO accounts (platform, title, description, price, country, followers_count, has_og_email, email_username, account_password, status)
-- VALUES ('instagram', '@verified_handle', 'OG email included. 50k followers. Clean history.', 25000.00, 'Nigeria', 50000, TRUE, 'user@email.com', 'password123', 'available');

-- ══════════════════════════════════════════════════
-- DONE
-- ══════════════════════════════════════════════════
SELECT 'Schema created successfully! Tables: users, transactions, number_orders, boost_orders, accounts, account_purchases, coupons, gift_cards, tickets, ticket_replies, withdrawals, settings, notifications' AS status;
