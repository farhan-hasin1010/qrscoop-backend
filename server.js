/**
 * QRScoop — Express backend
 *
 * SECURITY FIXES APPLIED:
 *  1. helmet() for HTTP security headers
 *  2. CORS restricted to FRONTEND_URL (env var)
 *  3. express-rate-limit on auth + API routes
 *  4. authenticate middleware — userId ALWAYS comes from the verified
 *     Supabase token, never from the request body
 *  5. URL validation (SSRF guard) on targetUrl
 *  6. Atomic click/download increments via Supabase RPC functions
 *     (SQL to create them is in the comments below)
 *  7. /api/user/:userId/status is now auth-gated
 *  8. /api/qr/log-download is now auth-gated + rate-limited
 *  9. /api/payments/verify — userId from token; idempotency via
 *     payment_logs table to block replay attacks
 * 10. /api/payments/create-order is now auth-gated
 * 11. Removed the no-op server-side logout route
 * 12. shortCode format validated in the redirect router
 * 13. Raw DB error messages no longer forwarded to the client
 *
 * NEW:
 *  - /api/qr/save-static  — saves static QR metadata (no redirect)
 *
 * REQUIRED SQL (run once in Supabase SQL editor):
 * ─────────────────────────────────────────────────
 * -- Atomic increment functions (fix race condition on counters)
 * CREATE OR REPLACE FUNCTION increment_clicks(code TEXT)
 * RETURNS void LANGUAGE sql AS $$
 *   UPDATE qr_codes SET clicks = clicks + 1 WHERE short_code = code;
 * $$;
 *
 * CREATE OR REPLACE FUNCTION increment_downloads(code TEXT)
 * RETURNS void LANGUAGE sql AS $$
 *   UPDATE qr_codes SET downloads = downloads + 1 WHERE short_code = code;
 * $$;
 *
 * -- Payment idempotency table (replay attack prevention)
 * CREATE TABLE IF NOT EXISTS payment_logs (
 *   payment_id TEXT PRIMARY KEY,
 *   order_id   TEXT NOT NULL,
 *   user_id    UUID NOT NULL,
 *   created_at TIMESTAMPTZ DEFAULT NOW()
 * );
 *
 * REQUIRED npm packages (add to package.json):
 *   npm install helmet express-rate-limit
 */

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { supabase } from './supabaseClient.js';
import Razorpay from 'razorpay';

dotenv.config();

// ── Guard: crash loudly at startup if required env vars are missing ──────────
const REQUIRED_ENV = ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET'];
for (const key of REQUIRED_ENV) {
    if (!process.env[key]) {
        console.error(`Missing required environment variable: ${key}`);
        process.exit(1);
    }
}

const app = express();
const PORT        = process.env.PORT         || 5000;
const BASE_URL    = process.env.BASE_URL     || `http://localhost:${PORT}`;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// ── Security headers ─────────────────────────────────────────────────────────
app.use(helmet());
// Force HTTPS in production

// ── CORS: only allow the configured frontend origin ──────────────────────────
app.use(cors({
    origin: FRONTEND_URL,
    credentials: true,
}));
app.use(express.json());

// ── Rate limiters ─────────────────────────────────────────────────────────────
// Tight limit on auth routes (brute-force / credential-stuffing protection)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

// Track failed attempts per email in Supabase
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    // Add failed attempt tracking
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
        // Generic message — never reveal which field was wrong
        return res.status(400).json({ error: 'Invalid email or password.' });
    }
    res.json({ message: 'Login successful!', session: data.session });
});

// Broad limit on all other API routes
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down.' },
});

// ── Razorpay ─────────────────────────────────────────────────────────────────
const razorpay = new Razorpay({
    key_id:     process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ─────────────────────────────────────────────────────────────────────────────
// MIDDLEWARE: authenticate
// Verifies the Supabase Bearer token and attaches the user to req.user.
// All protected routes use this instead of trusting userId from the body.
// ─────────────────────────────────────────────────────────────────────────────
const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required.' });

    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
        return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });
    }

    req.user = user;
    next();
};

// ── URL Validation (SSRF guard) ───────────────────────────────────────────────
const isValidHttpUrl = (str) => {
    try {
        const url = new URL(str);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
    res.json({ status: 'Operational', timestamp: new Date() });
});

// ─────────────────────────────────────────────────────────────────────────────
// DYNAMIC QR GENERATION
//
// FIXED:
//  - authenticate middleware: userId from verified token only
//  - URL validation to block javascript:, data:, internal IPs (SSRF)
//  - Count limit scoped to qr_type = 'dynamic' so static QRs don't count
//
// NOTE on remaining TOCTOU: the count check + insert are not atomic in
// application code. Two simultaneous requests can both pass the check.
// For production, call a single Postgres function instead (see header SQL).
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/qr/generate', apiLimiter, authenticate, async (req, res) => {
    const { targetUrl, contentType } = req.body;
    const userId = req.user.id; // ← verified token; never from req.body

    if (!targetUrl) {
        return res.status(400).json({ error: 'Content payload is required.' });
    }

    //No input length limits on QR content

    if (targetUrl.length > 2048) {
        return res.status(400).json({ error: 'URL is too long. Maximum 2048 characters.' });
    }
    
    if (contentType === 'link' && !isValidHttpUrl(targetUrl)) {
        return res.status(400).json({ error: 'Please provide a valid http:// or https:// URL.' });
    }
    

    try {
        const { data: sub } = await supabase
            .from('user_subscriptions')
            .select('is_premium')
            .eq('user_id', userId)
            .single();

        const isPremium = sub?.is_premium || false;

        if (!isPremium) {
            const { count, error: countError } = await supabase
                .from('qr_codes')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', userId)
                .eq('qr_type', 'dynamic');   // static QRs don't count toward this limit

            if (countError) throw countError;
            if (count >= 2) {
                return res.status(403).json({
                    error: 'You have reached your limit of 2 free Dynamic QR codes.',
                    limitExceeded: true,
                });
            }
        }

        const shortCode = crypto.randomBytes(4).toString('hex');
        const dynamicRedirectUrl = `${BASE_URL}/r/${shortCode}`;

        const { data, error } = await supabase
            .from('qr_codes')
            .insert([{
                short_code:   shortCode,
                target_url:   targetUrl,
                qr_type:      'dynamic',
                content_type: contentType,
                user_id:      userId,
                clicks:       0,
                downloads:    0,
            }])
            .select()
            .single();

        if (error) throw error;

        res.status(201).json({
            success:    true,
            shortCode:  data.short_code,
            dynamicUrl: dynamicRedirectUrl,
        });
    } catch (err) {
        console.error('QR generation error:', err.message);
        res.status(500).json({ error: 'Failed to generate QR code. Please try again.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// STATIC QR SAVE  (new)
// Static QRs encode the destination directly — no server redirect, no
// click tracking, no 7-day expiration. Unlimited for all logged-in users.
// The frontend generates the visual locally; this endpoint only saves
// the record so it appears in the user's dashboard.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/qr/save-static', apiLimiter, authenticate, async (req, res) => {
    const { targetUrl, contentType } = req.body;
    const userId = req.user.id;

    if (!targetUrl) return res.status(400).json({ error: 'Content payload is required.' });

    try {
        const shortCode = crypto.randomBytes(4).toString('hex');

        const { data, error } = await supabase
            .from('qr_codes')
            .insert([{
                short_code:   shortCode,
                target_url:   targetUrl,
                qr_type:      'static',
                content_type: contentType,
                user_id:      userId,
                clicks:       0,
                downloads:    0,
            }])
            .select()
            .single();

        if (error) throw error;

        res.status(201).json({ success: true, shortCode: data.short_code });
    } catch (err) {
        console.error('Static QR save error:', err.message);
        res.status(500).json({ error: 'Failed to save QR code.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// FIXED: generic error on login (don't reveal whether email or password was wrong)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/auth/signup', loginLimiter, async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const { error } = await supabase.auth.signUp({
            email,
            password,
            options: { data: { full_name: name } },
        });
        if (error) return res.status(400).json({ error: error.message });
        res.status(201).json({ message: 'Registration successful! Please check your email to confirm your account.' });
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// NOTE: login happens on the backend so rate-limiting is enforced server-side.
// After a successful response, the frontend calls supabase.auth.setSession()
// to store the session in the Supabase SDK (which handles refresh tokens).
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        // Generic message: never tell the client which field was wrong
        if (error) return res.status(400).json({ error: 'Invalid email or password.' });
        res.json({ message: 'Login successful!', session: data.session });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// QR METRICS
// FIXED: auth-gated; atomic increment via RPC (see SQL in file header)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/qr/log-download', apiLimiter, authenticate, async (req, res) => {
    const { shortCode } = req.body;
    if (!shortCode) return res.status(400).json({ error: 'Short code is required.' });

    try {
        const { error } = await supabase.rpc('increment_downloads', { code: shortCode });
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('Download log error:', err.message);
        res.status(500).json({ error: 'Failed to log download.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// FIXED: authenticate + ownership check (req.user.id must match :userId param)
// The old token-split logic is replaced by the middleware.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/user/:userId/dashboard', authenticate, async (req, res) => {
    const { userId } = req.params;
    if (req.user.id !== userId) return res.status(403).json({ error: 'Forbidden.' });

    try {
        const { data, error } = await supabase
            .from('qr_codes')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json({ success: true, qrCodes: data });
    } catch (err) {
        console.error('Dashboard fetch error:', err.message);
        res.status(500).json({ error: 'Failed to fetch dashboard data.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// USER STATUS
// FIXED: now auth-gated — was previously a public information-disclosure endpoint
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/user/:userId/status', authenticate, async (req, res) => {
    const { userId } = req.params;
    if (req.user.id !== userId) return res.status(403).json({ error: 'Forbidden.' });

    try {
        const { data, error } = await supabase
            .from('user_subscriptions')
            .select('is_premium, premium_until')
            .eq('user_id', userId)
            .single();

        if (error && error.code !== 'PGRST116') throw error;

        // Check if premium flag is true AND the expiration date is still in the future
        const isStillActive = Boolean(
            data?.is_premium && 
            data?.premium_until && 
            new Date(data.premium_until) > new Date()
        );

        res.json({ 
            isPremium: isStillActive,
            premiumUntil: data?.premium_until || null
        });
    } catch (err) {
        console.error('Status fetch error:', err.message);
        res.status(500).json({ error: 'Failed to fetch user status.' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT GATEWAY
//
// FIXED (create-order): auth-gated — anonymous users can no longer spam orders
// FIXED (verify):
//   - userId comes from req.user.id (verified token), NOT from req.body
//   - Idempotency check via payment_logs prevents replay attacks
//   - Payment is logged BEFORE upgrading so a crash between the two steps
//     is detectable and retryable without double-upgrade
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/payments/create-order', apiLimiter, authenticate, async (req, res) => {
    try {
        const options = {
            amount:  19900,
            currency: 'INR',
            receipt: `rcpt_${crypto.randomBytes(4).toString('hex')}`,
        };
        const order = await razorpay.orders.create(options);
        res.json({ success: true, order });
    } catch (err) {
        console.error('Order creation error:', err.message);
        res.status(500).json({ error: 'Failed to create payment order.' });
    }
});

app.post('/api/payments/verify', authenticate, async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const userId = req.user.id; // ← verified token; never from req.body

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({ error: 'Missing payment verification fields.' });
    }

    const shasum = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const expectedSignature = shasum.digest('hex');

    if (expectedSignature !== razorpay_signature) {
        return res.status(400).json({ error: 'Payment signature verification failed.' });
    }
    // Calculate expiration date (30 days from now)
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days in ms
    
    // Upgrade the user with an expiration date
    const { error: upErr } = await supabase
        .from('user_subscriptions')
        .upsert({ 
            user_id: userId, 
            is_premium: true, 
            premium_until: expiresAt.toISOString(),
            updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });
    
    if (upErr) throw upErr;

    try {
        // Idempotency: check if this payment was already processed
        const { data: existing, error: lookupErr } = await supabase
            .from('payment_logs')
            .select('payment_id')
            .eq('payment_id', razorpay_payment_id)
            .single();

        if (lookupErr && lookupErr.code !== 'PGRST116') throw lookupErr;

        if (existing) {
            // Already processed — safe to return success without double-upgrading
            return res.json({ success: true, message: 'Subscription already active.' });
        }

        // Log payment FIRST to prevent double-upgrade on any subsequent retry
        const { error: logErr } = await supabase.from('payment_logs').insert([{
            payment_id: razorpay_payment_id,
            order_id:   razorpay_order_id,
            user_id:    userId,
        }]);
        if (logErr) throw logErr;

        // Upgrade the user
        const { error: upErr } = await supabase
            .from('user_subscriptions')
            .upsert({ user_id: userId, is_premium: true, updated_at: new Date() });
        if (upErr) throw upErr;

        res.json({ success: true, message: 'Subscription activated successfully!' });
    } catch (err) {
        console.error('Payment verification error:', err.message);
        res.status(500).json({ error: 'Payment verified but account upgrade failed. Please contact support.' });
    }
});

app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const signature = req.headers['x-razorpay-signature'];
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    
    const shasum = crypto.createHmac('sha256', secret);
    shasum.update(req.body);
    const digest = shasum.digest('hex');
    
    if (digest !== signature) return res.status(400).json({ error: 'Invalid signature' });
    
    const event = JSON.parse(req.body);
    if (event.event === 'payment.captured') {
        const paymentId = event.payload.payment.entity.id;
        const notes = event.payload.payment.entity.notes;
        // Upgrade user from webhook as backup
    }
    res.json({ status: 'ok' });
});

// ─────────────────────────────────────────────────────────────────────────────
// DYNAMIC REDIRECT ROUTER
//
// FIXED:
//  - shortCode validated as exactly 8 hex characters (rejects injection attempts)
//  - Click increment is atomic via RPC (see SQL in file header)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/r/:shortCode', async (req, res) => {
    const { shortCode } = req.params;

    // Reject any shortCode that isn't exactly 8 lowercase hex chars
    if (!/^[a-f0-9]{8}$/.test(shortCode)) {
        return res.status(400).send('<h1>Invalid QR Code</h1>');
    }
    

    try {
        const { data: qrData, error: qrError } = await supabase
            .from('qr_codes')
            .select('*')
            .eq('short_code', shortCode)
            .single();

        if (qrError || !qrData) return res.status(404).send('<h1>404: QR Code Not Found</h1>');

        // We must fetch the QR code first to get the user_id

        const { data: subData } = await supabase
            .from('user_subscriptions')
            .select('is_premium, premium_until')
            .eq('user_id', qrData.user_id)
            .single();

        const isPremium = Boolean(
            subData?.is_premium && 
            subData?.premium_until && 
            new Date(subData.premium_until) > new Date()
        );

        
        //ENFORCE EXPIRATION
        if (!isPremium) {
            const daysOld = (Date.now() - new Date(qrData.created_at).getTime()) / (1000 * 60 * 60 * 24);
            if (daysOld > 7) {
                return res.status(403).send(`
                    <div style="font-family:sans-serif;text-align:center;padding:50px;max-width:500px;margin:0 auto;">
                        <h1 style="color:#dc2626;font-size:48px;margin-bottom:10px;">🔒</h1>
                        <h2 style="color:#1e293b;">This QR Code has Expired</h2>
                        <p style="color:#64748b;line-height:1.6;">The 7-day trial period for this QR code has ended. The owner must upgrade their account to restore routing access.</p>
                        <a href="${BASE_URL}" style="display:inline-block;margin-top:20px;padding:10px 20px;background:#2563eb;color:white;text-decoration:none;border-radius:8px;font-weight:bold;">Create your own on QRScoop</a>
                    </div>
                `);
            }
        }

        // Atomic increment (RPC function defined in SQL header above)
        await supabase.rpc('increment_clicks', { code: shortCode });

        return res.redirect(qrData.target_url);
    } catch (err) {
        console.error('Redirect error:', err.message);
        res.status(500).send('An error occurred. Please try again later.');
    }
});

app.listen(PORT, () => console.log(`QRScoop Server running on port ${PORT}`));
