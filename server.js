/* ═══════════════════════════════════════════════════════════
   E-Social Verified Logs — Backend Server
   Node.js + Express + Supabase
   Deploy on: Render.com (free tier) or Railway.app
   ═══════════════════════════════════════════════════════════ */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const axios      = require('axios');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase client ──
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

// ── Middleware ──
app.use(cors({
    origin: [
        process.env.FRONTEND_URL || '*',
        'http://localhost:3000',
        'http://localhost:5500',
        /\.netlify\.app$/,
        /\.netlify\.live$/,
    ],
    credentials: true
}));
app.use(express.json());

// ── JWT helper ──
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';
const signToken  = (user) => jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });

// ── Auth middleware ──
function auth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(h.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Session expired. Please login again.' });
    }
}
function adminOnly(req, res, next) {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only.' });
    next();
}

// ══════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        if (!email || !username || !password) return res.status(400).json({ error: 'All fields required.' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

        // Check if email exists
        const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
        if (existing) return res.status(409).json({ error: 'Email already registered.' });

        const { data: existingUser } = await supabase.from('users').select('id').eq('username', username).single();
        if (existingUser) return res.status(409).json({ error: 'Username already taken.' });

        const hashed = await bcrypt.hash(password, 12);
        const refCode = 'ESVL-' + Math.random().toString(36).slice(2, 7).toUpperCase();

        const { data: user, error } = await supabase.from('users').insert({
            id: uuidv4(),
            email,
            username,
            password_hash: hashed,
            role: 'user',
            status: 'active',
            wallet_balance: 0,
            referral_code: refCode,
            referral_count: 0,
            referral_earnings: 0,
            created_at: new Date().toISOString()
        }).select().single();

        if (error) throw error;

        const token = signToken(user);
        res.json({ token, user: safeUser(user) });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed. Try again.' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // ── ADMIN LOGIN (tap logo 5x) ──
        if (email === 'admin' || email === process.env.ADMIN_EMAIL) {
            const adminPass = process.env.ADMIN_PASSWORD || 'Emmy$1234';
            if (password !== adminPass) return res.status(401).json({ error: 'Incorrect admin password.' });
            const adminUser = {
                id: 'admin',
                email: process.env.ADMIN_EMAIL,
                username: process.env.ADMIN_USERNAME || 'Admin',
                role: 'admin',
                wallet_balance: 0
            };
            return res.json({ token: signToken(adminUser), user: adminUser });
        }

        // Regular user login (email OR username)
        let query = supabase.from('users').select('*');
        query = email.includes('@') ? query.eq('email', email) : query.eq('username', email);
        const { data: user } = await query.single();

        if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
        if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended. Contact support.' });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Invalid email or password.' });

        await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);

        res.json({ token: signToken(user), user: safeUser(user) });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed. Try again.' });
    }
});

// GET /api/auth/me
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        if (req.user.role === 'admin') {
            return res.json({ user: { id: 'admin', username: 'Admin', role: 'admin', wallet_balance: 0 } });
        }
        const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
        if (!user) return res.status(404).json({ error: 'User not found.' });
        res.json({ user: safeUser(user) });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get user.' });
    }
});

// PATCH /api/auth/profile
app.patch('/api/auth/profile', auth, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Username required.' });
        await supabase.from('users').update({ username }).eq('id', req.user.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Update failed.' });
    }
});

// ══════════════════════════════════════════════════
// WALLET ROUTES
// ══════════════════════════════════════════════════

// GET /api/wallet/balance
app.get('/api/wallet/balance', auth, async (req, res) => {
    try {
        const { data: user } = await supabase.from('users').select('wallet_balance, referral_count, referral_earnings').eq('id', req.user.id).single();
        res.json({
            balance: user?.wallet_balance || 0,
            referral_count: user?.referral_count || 0,
            referral_earnings: user?.referral_earnings || 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get balance.' });
    }
});

// POST /api/wallet/deposit — initialise Flutterwave payment
app.post('/api/wallet/deposit', auth, async (req, res) => {
    try {
        const { amount } = req.body;
        if (!amount || amount < 100) return res.status(400).json({ error: 'Minimum deposit is ₦100.' });
        const txRef = `ESVL-DEP-${Date.now()}-${req.user.id.slice(0, 8)}`;

        // Save pending transaction
        await supabase.from('transactions').insert({
            id: uuidv4(),
            user_id: req.user.id,
            type: 'deposit',
            amount,
            status: 'pending',
            tx_ref: txRef,
            description: `Wallet deposit of ₦${amount}`,
            created_at: new Date().toISOString()
        });

        res.json({ tx_ref: txRef, amount });
    } catch (err) {
        res.status(500).json({ error: 'Failed to initialise deposit.' });
    }
});

// GET /api/wallet/verify/:txRef — verify payment with Flutterwave
app.get('/api/wallet/verify/:txRef', auth, async (req, res) => {
    try {
        const { txRef } = req.params;

        // Verify with Flutterwave
        const flwRes = await axios.get(
            `https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref=${txRef}`,
            { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
        );

        const payment = flwRes.data?.data;
        if (!payment || payment.status !== 'successful') {
            return res.status(400).json({ error: 'Payment not confirmed.' });
        }

        const amount = payment.amount;

        // Check not already credited
        const { data: tx } = await supabase.from('transactions').select('*').eq('tx_ref', txRef).single();
        if (!tx) return res.status(404).json({ error: 'Transaction not found.' });
        if (tx.status === 'completed') return res.json({ success: true, already_credited: true });

        // Credit wallet
        const { data: user } = await supabase.from('users').select('wallet_balance, referred_by').eq('id', req.user.id).single();
        const newBalance = (user.wallet_balance || 0) + amount;
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.user.id);
        await supabase.from('transactions').update({ status: 'completed', balance_after: newBalance }).eq('tx_ref', txRef);

        // Referral commission (5%)
        if (user.referred_by) {
            const commission = Math.floor(amount * (parseInt(process.env.REFERRAL_PERCENT || '5') / 100));
            const { data: refUser } = await supabase.from('users').select('wallet_balance, referral_earnings').eq('id', user.referred_by).single();
            if (refUser) {
                await supabase.from('users').update({
                    wallet_balance: (refUser.wallet_balance || 0) + commission,
                    referral_earnings: (refUser.referral_earnings || 0) + commission
                }).eq('id', user.referred_by);
            }
        }

        res.json({ success: true, amount, new_balance: newBalance });
    } catch (err) {
        console.error('Verify error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Verification failed. Contact support.' });
    }
});

// GET /api/wallet/transactions
app.get('/api/wallet/transactions', auth, async (req, res) => {
    try {
        const { type = 'all', page = 1 } = req.query;
        let query = supabase.from('transactions').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).range((page-1)*20, page*20-1);
        if (type !== 'all') query = query.eq('type', type);
        const { data } = await query;
        res.json({ transactions: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get transactions.' });
    }
});

// ══════════════════════════════════════════════════
// VIRTUAL NUMBERS — 5SIM
// ══════════════════════════════════════════════════

const FIVESIM_BASE = 'https://5sim.net/v1';
const fivesimHeaders = () => ({ Authorization: `Bearer ${process.env.FIVESIM_API_KEY}`, Accept: 'application/json' });

// GET /api/numbers/countries
app.get('/api/numbers/countries', auth, async (req, res) => {
    try {
        const r = await axios.get(`${FIVESIM_BASE}/guest/countries`, { headers: fivesimHeaders() });
        res.json({ countries: r.data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch countries.' });
    }
});

// GET /api/numbers/products?country=russia
app.get('/api/numbers/products', auth, async (req, res) => {
    try {
        const { country = 'any' } = req.query;
        const r = await axios.get(`${FIVESIM_BASE}/guest/products/${country}/any`, { headers: fivesimHeaders() });
        res.json({ products: r.data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch products.' });
    }
});

// GET /api/numbers/prices
app.get('/api/numbers/prices', auth, async (req, res) => {
    try {
        const { country = 'any', product = 'any' } = req.query;
        const r = await axios.get(`${FIVESIM_BASE}/guest/prices?country=${country}&product=${product}`, { headers: fivesimHeaders() });
        res.json({ prices: r.data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch prices.' });
    }
});

// POST /api/numbers/buy
app.post('/api/numbers/buy', auth, async (req, res) => {
    try {
        const { country, product, operator = 'any' } = req.body;
        if (!country || !product) return res.status(400).json({ error: 'Country and product required.' });

        // Get supplier price from 5SIM
        const priceRes = await axios.get(`${FIVESIM_BASE}/guest/prices?country=${country}&product=${product}`, { headers: fivesimHeaders() });
        const productData = priceRes.data?.[country]?.[product];
        if (!productData) return res.status(404).json({ error: 'Product not available.' });

        const firstOp = Object.values(productData || {})[0];
        const supplierCost = firstOp?.cost || 0;

        // Get admin markup settings
        const { data: settings } = await supabase.from('settings').select('value').eq('key', 'markup_pct_numbers').single();
        const markupPct = parseFloat(settings?.value || '20');
        const { data: flatSettings } = await supabase.from('settings').select('value').eq('key', 'markup_flat_numbers').single();
        const markupFlat = parseFloat(flatSettings?.value || '0');

        // YOUR PRICE = supplier cost × (1 + markup%) + flat markup
        // Supplier cost is in USD, convert to NGN (approx rate)
        const NGN_RATE = 1600;
        const costNGN = supplierCost * NGN_RATE;
        const userPrice = Math.ceil(costNGN * (1 + markupPct / 100) + markupFlat);

        // Check user balance
        const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.id).single();
        if ((user?.wallet_balance || 0) < userPrice) {
            return res.status(402).json({ error: `Insufficient balance. Need ₦${userPrice}, you have ₦${user?.wallet_balance || 0}.`, required: userPrice, balance: user?.wallet_balance });
        }

        // Buy from 5SIM
        const buyRes = await axios.get(`${FIVESIM_BASE}/user/buy/activation/${country}/${operator}/${product}`, { headers: fivesimHeaders() });
        const order = buyRes.data;

        // Deduct from user wallet
        const newBalance = (user.wallet_balance || 0) - userPrice;
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.user.id);

        // Record transaction
        const txId = uuidv4();
        await supabase.from('transactions').insert({
            id: txId, user_id: req.user.id, type: 'number_purchase',
            amount: -userPrice, balance_after: newBalance, status: 'completed',
            tx_ref: `NUM-${order.id}`,
            description: `Virtual number: ${product} (${country})`,
            created_at: new Date().toISOString()
        });

        // Record order
        await supabase.from('number_orders').insert({
            id: uuidv4(), user_id: req.user.id, order_id: String(order.id),
            product, country, phone_number: order.phone,
            supplier_cost: costNGN, user_price: userPrice, profit: userPrice - costNGN,
            status: order.status || 'pending', created_at: new Date().toISOString()
        });

        res.json({ order, user_price: userPrice, new_balance: newBalance });
    } catch (err) {
        console.error('Buy number error:', err.response?.data || err.message);
        res.status(500).json({ error: err.response?.data?.message || 'Failed to buy number.' });
    }
});

// GET /api/numbers/sms/:orderId
app.get('/api/numbers/sms/:orderId', auth, async (req, res) => {
    try {
        const r = await axios.get(`${FIVESIM_BASE}/user/check/${req.params.orderId}`, { headers: fivesimHeaders() });
        // Update order status
        await supabase.from('number_orders').update({ status: r.data.status }).eq('order_id', String(req.params.orderId));
        res.json(r.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to check SMS.' });
    }
});

// POST /api/numbers/cancel/:orderId
app.post('/api/numbers/cancel/:orderId', auth, async (req, res) => {
    try {
        const r = await axios.get(`${FIVESIM_BASE}/user/cancel/${req.params.orderId}`, { headers: fivesimHeaders() });
        await supabase.from('number_orders').update({ status: 'cancelled' }).eq('order_id', String(req.params.orderId));
        res.json(r.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to cancel.' });
    }
});

// POST /api/numbers/finish/:orderId
app.post('/api/numbers/finish/:orderId', auth, async (req, res) => {
    try {
        const r = await axios.get(`${FIVESIM_BASE}/user/finish/${req.params.orderId}`, { headers: fivesimHeaders() });
        await supabase.from('number_orders').update({ status: 'finished' }).eq('order_id', String(req.params.orderId));
        res.json(r.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to finish.' });
    }
});

// GET /api/numbers/history
app.get('/api/numbers/history', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('number_orders').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
        res.json({ orders: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get history.' });
    }
});

// ══════════════════════════════════════════════════
// SOCIAL BOOST — SMM Panel
// ══════════════════════════════════════════════════

const smmApi = async (action, params = {}) => {
    const r = await axios.post(process.env.SMM_PANEL_URL || 'https://realsimplesocial.com/api', {
        key: process.env.SMM_PANEL_KEY,
        action,
        ...params
    });
    return r.data;
};

// GET /api/boost/services
app.get('/api/boost/services', auth, async (req, res) => {
    try {
        const data = await smmApi('services');
        res.json({ services: Array.isArray(data) ? data : [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch boost services.' });
    }
});

// POST /api/boost/order
app.post('/api/boost/order', auth, async (req, res) => {
    try {
        const { service_id, link, quantity } = req.body;
        if (!service_id || !link || !quantity) return res.status(400).json({ error: 'service_id, link, quantity required.' });

        // Get service price from SMM panel
        const services = await smmApi('services');
        const service = Array.isArray(services) ? services.find(s => String(s.service) === String(service_id)) : null;
        const supplierRate = service ? parseFloat(service.rate) : 0; // per 1000 units
        const supplierCost = (supplierRate / 1000) * quantity;

        // Apply markup
        const { data: settings } = await supabase.from('settings').select('value').eq('key', 'markup_pct_boost').single();
        const markupPct = parseFloat(settings?.value || '25');
        const { data: flatS } = await supabase.from('settings').select('value').eq('key', 'markup_flat_boost').single();
        const markupFlat = parseFloat(flatS?.value || '0');
        const userPrice = Math.ceil(supplierCost * (1 + markupPct / 100) + markupFlat);

        // Check balance
        const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.id).single();
        if ((user?.wallet_balance || 0) < userPrice) {
            return res.status(402).json({ error: `Insufficient balance. Need ₦${userPrice}.`, required: userPrice, balance: user?.wallet_balance });
        }

        // Place order with SMM panel
        const order = await smmApi('add', { service: service_id, link, quantity });

        // Deduct wallet
        const newBalance = (user.wallet_balance || 0) - userPrice;
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.user.id);

        await supabase.from('transactions').insert({
            id: uuidv4(), user_id: req.user.id, type: 'boost_purchase',
            amount: -userPrice, balance_after: newBalance, status: 'completed',
            tx_ref: `BOOST-${order.order}`,
            description: `Social boost: ${service?.name || service_id} × ${quantity}`,
            created_at: new Date().toISOString()
        });

        await supabase.from('boost_orders').insert({
            id: uuidv4(), user_id: req.user.id,
            smm_order_id: String(order.order),
            service_id: String(service_id), service_name: service?.name || '',
            link, quantity, supplier_cost: supplierCost,
            user_price: userPrice, profit: userPrice - supplierCost,
            status: 'pending', created_at: new Date().toISOString()
        });

        res.json({ success: true, order_id: order.order, user_price: userPrice, new_balance: newBalance });
    } catch (err) {
        console.error('Boost order error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Failed to place boost order.' });
    }
});

// GET /api/boost/order/:orderId
app.get('/api/boost/order/:orderId', auth, async (req, res) => {
    try {
        const status = await smmApi('status', { order: req.params.orderId });
        await supabase.from('boost_orders').update({ status: status.status?.toLowerCase() || 'pending' }).eq('smm_order_id', req.params.orderId);
        res.json(status);
    } catch (err) {
        res.status(500).json({ error: 'Failed to get order status.' });
    }
});

// GET /api/boost/history
app.get('/api/boost/history', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('boost_orders').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
        res.json({ orders: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get history.' });
    }
});

// ══════════════════════════════════════════════════
// VERIFIED ACCOUNTS
// ══════════════════════════════════════════════════

// GET /api/accounts
app.get('/api/accounts', auth, async (req, res) => {
    try {
        const { platform, search, sort = 'newest', limit = 50 } = req.query;
        let query = supabase.from('accounts').select('id, platform, title, description, price, country, followers_count, has_og_email, status, created_at').eq('status', 'available');
        if (platform) query = query.eq('platform', platform);
        if (search) query = query.ilike('title', `%${search}%`);
        if (sort === 'price_asc') query = query.order('price', { ascending: true });
        else if (sort === 'price_desc') query = query.order('price', { ascending: false });
        else if (sort === 'followers') query = query.order('followers_count', { ascending: false });
        else query = query.order('created_at', { ascending: false });
        query = query.limit(parseInt(limit));
        const { data } = await query;
        res.json({ accounts: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get accounts.' });
    }
});

// GET /api/accounts/meta/platforms
app.get('/api/accounts/meta/platforms', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('accounts').select('platform').eq('status', 'available');
        const platforms = [...new Set((data || []).map(a => a.platform))].sort();
        res.json({ platforms });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get platforms.' });
    }
});

// GET /api/accounts/purchased/mine
app.get('/api/accounts/purchased/mine', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('account_purchases')
            .select('*, account:account_id(*)')
            .eq('user_id', req.user.id)
            .order('purchased_at', { ascending: false });
        const purchases = (data || []).map(p => ({
            ...p.account,
            ...p,
            purchased_at: p.purchased_at
        }));
        res.json({ accounts: purchases });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get purchased accounts.' });
    }
});

// POST /api/accounts/:id/purchase
app.post('/api/accounts/:id/purchase', auth, async (req, res) => {
    try {
        const { data: account } = await supabase.from('accounts').select('*').eq('id', req.params.id).eq('status', 'available').single();
        if (!account) return res.status(404).json({ error: 'Account not found or already sold.' });

        const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.id).single();
        if ((user?.wallet_balance || 0) < account.price) {
            return res.status(402).json({ error: `Insufficient balance.`, required: account.price, balance: user?.wallet_balance });
        }

        // Deduct
        const newBalance = (user.wallet_balance || 0) - account.price;
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.user.id);

        // Mark account as sold
        await supabase.from('accounts').update({ status: 'sold' }).eq('id', account.id);

        // Record purchase (includes credentials)
        const purchaseId = uuidv4();
        await supabase.from('account_purchases').insert({
            id: purchaseId, user_id: req.user.id, account_id: account.id,
            price_paid: account.price, purchased_at: new Date().toISOString()
        });

        await supabase.from('transactions').insert({
            id: uuidv4(), user_id: req.user.id, type: 'account_purchase',
            amount: -account.price, balance_after: newBalance, status: 'completed',
            tx_ref: `ACC-${purchaseId}`,
            description: `Verified account: ${account.platform} — ${account.title}`,
            created_at: new Date().toISOString()
        });

        res.json({
            success: true,
            purchase: {
                id: purchaseId,
                account: {
                    platform: account.platform,
                    title: account.title,
                    email_username: account.email_username,
                    account_password: account.account_password,
                    recovery_email: account.recovery_email,
                    recovery_phone: account.recovery_phone,
                    extra_notes: account.extra_notes
                }
            },
            new_balance: newBalance
        });
    } catch (err) {
        console.error('Purchase error:', err);
        res.status(500).json({ error: 'Purchase failed. Try again.' });
    }
});

// ── Admin account management ──
app.get('/api/accounts/admin/list', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('accounts').select('*').order('created_at', { ascending: false });
        res.json({ accounts: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.post('/api/accounts/admin/add', auth, adminOnly, async (req, res) => {
    try {
        const { platform, title, description, price, country, followers_count, has_og_email,
                email_username, account_password, recovery_email, recovery_phone, extra_notes } = req.body;
        if (!platform || !title || !price || !email_username || !account_password) {
            return res.status(400).json({ error: 'Platform, title, price, username, and password are required.' });
        }
        const { data, error } = await supabase.from('accounts').insert({
            id: uuidv4(), platform, title, description, price: parseFloat(price),
            country, followers_count: parseInt(followers_count || '0'),
            has_og_email: !!parseInt(has_og_email || '0'),
            email_username, account_password,
            recovery_email, recovery_phone, extra_notes,
            status: 'available', created_at: new Date().toISOString()
        }).select().single();
        if (error) throw error;
        res.json({ success: true, account: data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add account.' });
    }
});

app.delete('/api/accounts/admin/:id', auth, adminOnly, async (req, res) => {
    try {
        await supabase.from('accounts').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete.' });
    }
});

// ══════════════════════════════════════════════════
// COUPONS
// ══════════════════════════════════════════════════

app.post('/api/coupons/validate', auth, async (req, res) => {
    try {
        const { code } = req.body;
        const { data: coupon } = await supabase.from('coupons').select('*').eq('code', code.toUpperCase()).eq('status', 'active').single();
        if (!coupon) return res.status(404).json({ error: 'Invalid or expired coupon.' });
        if (coupon.used_count >= coupon.max_uses) return res.status(400).json({ error: 'Coupon usage limit reached.' });
        res.json({ valid: true, coupon: { code: coupon.code, discount_percent: coupon.discount_percent, discount_amount: coupon.discount_amount, discount: coupon.discount_percent ? `${coupon.discount_percent}% off` : `₦${coupon.discount_amount} off` } });
    } catch (err) {
        res.status(500).json({ error: 'Failed to validate coupon.' });
    }
});

app.post('/api/coupons/apply', auth, async (req, res) => {
    try {
        const { code } = req.body;
        const { data: coupon } = await supabase.from('coupons').select('*').eq('code', code.toUpperCase()).single();
        if (!coupon) return res.status(404).json({ error: 'Coupon not found.' });
        await supabase.from('coupons').update({ used_count: (coupon.used_count || 0) + 1 }).eq('id', coupon.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to apply coupon.' });
    }
});

// ══════════════════════════════════════════════════
// GIFT CARDS
// ══════════════════════════════════════════════════

app.post('/api/giftcards/redeem', auth, async (req, res) => {
    try {
        const { code } = req.body;
        const { data: card } = await supabase.from('gift_cards').select('*').eq('code', code.toUpperCase()).eq('status', 'active').single();
        if (!card) return res.status(404).json({ error: 'Invalid or already redeemed gift card.' });

        const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.user.id).single();
        const newBalance = (user?.wallet_balance || 0) + card.amount;
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.user.id);
        await supabase.from('gift_cards').update({ status: 'redeemed', redeemed_by: req.user.id }).eq('id', card.id);

        await supabase.from('transactions').insert({
            id: uuidv4(), user_id: req.user.id, type: 'giftcard_redeem',
            amount: card.amount, balance_after: newBalance, status: 'completed',
            tx_ref: `GC-${card.id}`,
            description: `Gift card redeemed: ${code}`,
            created_at: new Date().toISOString()
        });

        res.json({ success: true, amount: card.amount, new_balance: newBalance });
    } catch (err) {
        res.status(500).json({ error: 'Failed to redeem gift card.' });
    }
});

// ══════════════════════════════════════════════════
// REFERRALS
// ══════════════════════════════════════════════════

app.get('/api/referrals/stats', auth, async (req, res) => {
    try {
        const { data: user } = await supabase.from('users').select('referral_code, referral_count, referral_earnings').eq('id', req.user.id).single();
        const origin = process.env.FRONTEND_URL || 'https://your-site.netlify.app';
        res.json({
            referral_code: user?.referral_code || '',
            referral_link: `${origin}/?ref=${user?.referral_code}`,
            total_referrals: user?.referral_count || 0,
            total_earnings: user?.referral_earnings || 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get referral stats.' });
    }
});

app.post('/api/referrals/apply', auth, async (req, res) => {
    try {
        const { code } = req.body;
        const { data: refUser } = await supabase.from('users').select('id').eq('referral_code', code).single();
        if (!refUser) return res.status(404).json({ error: 'Invalid referral code.' });
        await supabase.from('users').update({ referred_by: refUser.id }).eq('id', req.user.id);
        await supabase.from('users').update({ referral_count: supabase.raw('referral_count + 1') }).eq('id', refUser.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to apply referral.' });
    }
});

// ══════════════════════════════════════════════════
// TICKETS
// ══════════════════════════════════════════════════

app.post('/api/tickets', auth, async (req, res) => {
    try {
        const { subject, message, priority = 'medium' } = req.body;
        const { data } = await supabase.from('tickets').insert({
            id: uuidv4(), user_id: req.user.id, subject, message, priority, status: 'open',
            created_at: new Date().toISOString()
        }).select().single();
        res.json({ ticket: data });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create ticket.' });
    }
});

app.get('/api/tickets', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('tickets').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false });
        res.json({ tickets: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/tickets/:id', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('tickets').select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
        res.json({ ticket: data });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.post('/api/tickets/:id/reply', auth, async (req, res) => {
    try {
        await supabase.from('ticket_replies').insert({
            id: uuidv4(), ticket_id: req.params.id,
            user_id: req.user.id, message: req.body.message,
            created_at: new Date().toISOString()
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

// ══════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════

app.get('/api/admin/overview', auth, adminOnly, async (req, res) => {
    try {
        const [users, accounts, deposits, purchases, boosts, pending_w] = await Promise.all([
            supabase.from('users').select('id', { count: 'exact' }),
            supabase.from('accounts').select('id', { count: 'exact' }),
            supabase.from('transactions').select('amount').eq('type', 'deposit').eq('status', 'completed'),
            supabase.from('transactions').select('amount').in('type', ['account_purchase','number_purchase','boost_purchase']),
            supabase.from('boost_orders').select('id', { count: 'exact' }).eq('status', 'pending'),
            supabase.from('transactions').select('id', { count: 'exact' }).eq('type', 'withdrawal').eq('status', 'pending'),
        ]);

        const totalDeposits = (deposits.data || []).reduce((s, t) => s + (t.amount || 0), 0);
        const totalRevenue  = (purchases.data || []).reduce((s, t) => s + Math.abs(t.amount || 0), 0);

        const stats = {
            total_users: users.count || 0,
            total_accounts: accounts.count || 0,
            total_deposits: totalDeposits,
            total_revenue: totalRevenue,
            pending_boosts: boosts.count || 0,
            pending_withdrawals: pending_w.count || 0
        };

        // 7-day revenue
        const sevenDays = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date(); d.setDate(d.getDate() - i);
            sevenDays.push({ day: d.toISOString().slice(0, 10), deposits: 0, purchases: 0 });
        }

        res.json({ stats, revenue_daily: sevenDays, recent: { number_orders: [], boost_orders: [] } });
    } catch (err) {
        console.error('Admin overview error:', err);
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
    try {
        const { page = 1, search = '' } = req.query;
        let query = supabase.from('users').select('id, username, email, wallet_balance, role, status, created_at').order('created_at', { ascending: false }).range((page-1)*30, page*30-1);
        if (search) query = query.or(`email.ilike.%${search}%,username.ilike.%${search}%`);
        const { data } = await query;
        res.json({ users: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.patch('/api/admin/users/:id/status', auth, adminOnly, async (req, res) => {
    try {
        await supabase.from('users').update({ status: req.body.status }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/coupons', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
        res.json({ coupons: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.post('/api/admin/coupons', auth, adminOnly, async (req, res) => {
    try {
        const { code, discount_percent, max_uses = 100 } = req.body;
        const { data } = await supabase.from('coupons').insert({
            id: uuidv4(), code: code.toUpperCase(), discount_percent,
            max_uses, used_count: 0, status: 'active', created_at: new Date().toISOString()
        }).select().single();
        res.json({ coupon: data });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.delete('/api/admin/coupons/:id', auth, adminOnly, async (req, res) => {
    try {
        await supabase.from('coupons').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/giftcards', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('gift_cards').select('*').order('created_at', { ascending: false });
        res.json({ cards: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.post('/api/admin/giftcards', auth, adminOnly, async (req, res) => {
    try {
        const { amount, count = 1 } = req.body;
        const cards = Array.from({ length: count }, () => ({
            id: uuidv4(),
            code: 'ESVL-GIFT-' + Math.random().toString(36).slice(2, 12).toUpperCase(),
            amount: parseFloat(amount), status: 'active',
            created_at: new Date().toISOString()
        }));
        const { data } = await supabase.from('gift_cards').insert(cards).select();
        res.json({ cards: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/withdrawals', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('withdrawals').select('*, user:user_id(username)').order('created_at', { ascending: false });
        res.json({ withdrawals: (data || []).map(w => ({ ...w, username: w.user?.username })) });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.patch('/api/admin/withdrawals/:id', auth, adminOnly, async (req, res) => {
    try {
        const { status } = req.body;
        await supabase.from('withdrawals').update({ status }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/boosts', auth, adminOnly, async (req, res) => {
    try {
        const { status = 'all', page = 1 } = req.query;
        let query = supabase.from('boost_orders').select('*, user:user_id(username)').order('created_at', { ascending: false }).range((page-1)*30, page*30-1);
        if (status !== 'all') query = query.eq('status', status);
        const { data } = await query;
        res.json({ orders: (data || []).map(o => ({ ...o, username: o.user?.username })) });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/numbers', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('number_orders').select('*, user:user_id(username)').order('created_at', { ascending: false }).limit(100);
        res.json({ orders: (data || []).map(o => ({ ...o, username: o.user?.username })) });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

// Settings (profit markup stored here)
app.get('/api/admin/settings', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('settings').select('key, value');
        const settings = {};
        (data || []).forEach(s => { settings[s.key] = s.value; });
        // Defaults
        const defaults = { markup_pct_numbers: '20', markup_flat_numbers: '0', markup_pct_boost: '25', markup_flat_boost: '0', markup_pct_accounts: '0', markup_flat_accounts: '0' };
        res.json({ settings: { ...defaults, ...settings } });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.put('/api/admin/settings', auth, adminOnly, async (req, res) => {
    try {
        const entries = Object.entries(req.body);
        for (const [key, value] of entries) {
            await supabase.from('settings').upsert({ key, value: String(value) }, { onConflict: 'key' });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to save settings.' });
    }
});

app.get('/api/admin/profit-stats', auth, adminOnly, async (req, res) => {
    try {
        const [numOrders, boostOrders, accOrders] = await Promise.all([
            supabase.from('number_orders').select('profit'),
            supabase.from('boost_orders').select('profit'),
            supabase.from('transactions').select('amount').eq('type', 'account_purchase').eq('status', 'completed'),
        ]);
        const numProfit   = (numOrders.data || []).reduce((s, o) => s + (o.profit || 0), 0);
        const boostProfit = (boostOrders.data || []).reduce((s, o) => s + (o.profit || 0), 0);
        const accRevenue  = (accOrders.data || []).reduce((s, t) => s + Math.abs(t.amount || 0), 0);
        res.json({ numbers_profit: numProfit, boost_profit: boostProfit, accounts_revenue: accRevenue, total_revenue: numProfit + boostProfit + accRevenue });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/notifications', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('notifications').select('*').order('created_at', { ascending: false }).limit(20);
        res.json({ notifications: data || [] });
    } catch (err) {
        res.json({ notifications: [] });
    }
});

app.patch('/api/admin/notifications/read-all', auth, adminOnly, async (req, res) => {
    try {
        await supabase.from('notifications').update({ read: true }).eq('read', false);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/tickets/all', auth, adminOnly, async (req, res) => {
    try {
        const { data } = await supabase.from('tickets').select('*, user:user_id(username)').order('created_at', { ascending: false });
        res.json({ tickets: data || [] });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.patch('/api/admin/tickets/:id/close', auth, adminOnly, async (req, res) => {
    try {
        await supabase.from('tickets').update({ status: 'closed' }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed.' });
    }
});

app.get('/api/admin/api-health', auth, adminOnly, async (req, res) => {
    const checks = [];
    // 5SIM
    try {
        const start = Date.now();
        await axios.get(`${FIVESIM_BASE}/guest/countries`, { headers: fivesimHeaders(), timeout: 5000 });
        checks.push({ api: '5SIM', status: 'online', response_time: Date.now() - start });
    } catch { checks.push({ api: '5SIM', status: 'offline', error: 'Connection failed' }); }
    // SMM Panel
    try {
        const start = Date.now();
        await axios.post(process.env.SMM_PANEL_URL || 'https://realsimplesocial.com/api', { key: process.env.SMM_PANEL_KEY, action: 'services' }, { timeout: 5000 });
        checks.push({ api: 'SMM Panel', status: 'online', response_time: Date.now() - start });
    } catch { checks.push({ api: 'SMM Panel', status: 'offline', error: 'Connection failed' }); }
    // Supabase
    try {
        const start = Date.now();
        await supabase.from('users').select('id').limit(1);
        checks.push({ api: 'Supabase DB', status: 'online', response_time: Date.now() - start });
    } catch { checks.push({ api: 'Supabase DB', status: 'offline', error: 'DB error' }); }

    res.json({ health: checks, timestamp: new Date().toISOString() });
});

// ── Helpers ──
function safeUser(user) {
    const { password_hash, ...safe } = user;
    return safe;
}

// ── Health check ──
app.get('/', (req, res) => res.json({ status: 'ok', service: 'E-Social Verified Logs API', version: '1.0.0' }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ── Start ──
app.listen(PORT, () => {
    console.log(`\n✅ E-Social Verified Logs API running on port ${PORT}`);
    console.log(`🔑 Admin login: use email="${process.env.ADMIN_EMAIL}" or "admin" with your ADMIN_PASSWORD`);
    console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || 'not set — update FRONTEND_URL in .env'}\n`);
});
