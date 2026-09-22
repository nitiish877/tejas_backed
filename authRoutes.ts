import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'crypto';
import { pool, dbEnabled } from './db';

const JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const router = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Brute-force se bachne ke liye: ek IP se 15 min me max 30 login/register try
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Bahut zyada attempts. Thodi der baad try karo.' },
});

// Guest/temp chat save: bina login ke khula endpoint hai, isliye DB flood se bachne ke liye limit
const ephemeralLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Bahut zyada requests. Thodi der baad try karo.' },
});

// Public share link padhne pe limit (scraping / abuse se bachne ke liye)
const shareReadLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Bahut zyada requests. Thodi der baad try karo.' },
});

// DB ya JWT_SECRET na ho to saaf message do (crash nahi)
function requireConfigured(_req: Request, res: Response, next: NextFunction) {
  if (!dbEnabled || !pool) {
    return res.status(503).json({ error: 'Account system abhi setup nahi hai (DATABASE_URL missing).' });
  }
  if (JWT_SECRET.length < 16) {
    return res.status(503).json({ error: 'Server setup incomplete (JWT_SECRET missing ya bahut chhota).' });
  }
  next();
}

function signToken(userId: string): string {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
}

function publicUser(row: any) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    provider: 'email' as const,
    // Subscription fields (default to free if missing)
    subscriptionPlan: row.subscription_plan || 'free',
    ownedPlans: Array.isArray(row.owned_plans) ? row.owned_plans : [],
    planExpiries: row.plan_expiries && typeof row.plan_expiries === 'object' ? row.plan_expiries : {},
    subscriptionStartedAt: row.subscription_started_at ? Number(row.subscription_started_at) : undefined,
    subscriptionExpiresAt: row.subscription_expires_at ? Number(row.subscription_expires_at) : undefined,
    lastPaymentId: row.last_payment_id || undefined,
  };
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { sub?: string };
    if (!payload.sub) throw new Error('bad token');
    res.locals.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

// Ephemeral (guest/temp) chats ke liye: JWT mile to logged-in user ke naam se,
// warna X-Guest-Id header se anonymous guest ke naam se save hota hai. Login zaroori nahi.
function resolveEphemeralOwner(req: Request): { ownerType: 'user' | 'guest'; ownerId: string } | null {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET) as { sub?: string };
      if (payload.sub) return { ownerType: 'user', ownerId: payload.sub };
    } catch {
      // invalid/expired token: guest id se fallback karo neeche
    }
  }
  const guestId = String(req.headers['x-guest-id'] || '').trim();
  if (/^guest_[a-z0-9]{6,80}$/.test(guestId)) return { ownerType: 'guest', ownerId: guestId };
  return null;
}

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

// ---------------- AUTH ----------------
router.post('/auth/register', requireConfigured, authLimiter, async (req: Request, res: Response) => {
  try {
    const name = String(req.body?.name || '').trim().slice(0, 60);
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Valid email daalo.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password kam se kam 8 characters ka hona chahiye.' });
    if (password.length > 128) return res.status(400).json({ error: 'Password bahut lamba hai.' });

    const exists = await pool!.query('SELECT 1 FROM users WHERE email = $1', [email]);
    if (exists.rowCount) return res.status(409).json({ error: 'Is email se account pehle se hai. Sign In karo.' });

    const id = randomUUID();
    const hash = await bcrypt.hash(password, 10);
    const displayName = name || email.split('@')[0];
    await pool!.query('INSERT INTO users (id, name, email, password_hash) VALUES ($1, $2, $3, $4)', [
      id,
      displayName,
      email,
      hash,
    ]);

    // Fetch the freshly inserted row so publicUser() gets all the subscription defaults
    const fresh = await pool!.query(
      `SELECT id, name, email, subscription_plan, owned_plans, plan_expiries,
              subscription_started_at, subscription_expires_at, last_payment_id
       FROM users WHERE id = $1`,
      [id]
    );

    res.status(201).json({ token: signToken(id), user: publicUser(fresh.rows[0]) });
  } catch (err: any) {
    // do requests ek saath aayein to UNIQUE constraint yahan pakdegi
    if (err?.code === '23505') return res.status(409).json({ error: 'Is email se account pehle se hai. Sign In karo.' });
    console.error('register error:', err);
    res.status(500).json({ error: 'Register nahi ho paya. Thodi der baad try karo.' });
  }
});

router.post('/auth/login', requireConfigured, authLimiter, async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return res.status(400).json({ error: 'Email aur password daalo.' });

    const result = await pool!.query(
      `SELECT id, name, email, password_hash, subscription_plan, owned_plans, plan_expiries,
              subscription_started_at, subscription_expires_at, last_payment_id
       FROM users WHERE email = $1`,
      [email]
    );
    const row = result.rows[0];
    // Email galat ho ya password, dono me same message (kaun sa galat hai ye leak na ho)
    const ok = row ? await bcrypt.compare(password, row.password_hash) : false;
    if (!ok) return res.status(401).json({ error: 'Email ya password galat hai.' });

    res.json({ token: signToken(row.id), user: publicUser(row) });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'Login nahi ho paya. Thodi der baad try karo.' });
  }
});

router.get('/auth/me', requireConfigured, requireAuth, async (_req: Request, res: Response) => {
  try {
    const result = await pool!.query(
      `SELECT id, name, email, subscription_plan, owned_plans, plan_expiries,
              subscription_started_at, subscription_expires_at, last_payment_id
       FROM users WHERE id = $1`,
      [res.locals.userId]
    );
    if (!result.rows[0]) return res.status(401).json({ error: 'Account not found' });
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/auth/me', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const name = String(req.body?.name || '').trim().slice(0, 60);
    if (!name) return res.status(400).json({ error: 'Name khali nahi ho sakta.' });
    const result = await pool!.query(
      `UPDATE users SET name = $1 WHERE id = $2
       RETURNING id, name, email, subscription_plan, owned_plans, plan_expiries,
                 subscription_started_at, subscription_expires_at, last_payment_id`,
      [name, res.locals.userId]
    );
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('update name error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save the user's subscription state after a payment (or after expiry auto-cleanup).
router.put('/auth/subscription', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const b = req.body || {};

    const subscriptionPlan = typeof b.subscriptionPlan === 'string' ? b.subscriptionPlan.slice(0, 20) : 'free';
    const ownedPlans = Array.isArray(b.ownedPlans)
      ? b.ownedPlans.filter((p: any) => typeof p === 'string').slice(0, 10)
      : [];
    const planExpiries = b.planExpiries && typeof b.planExpiries === 'object' ? b.planExpiries : {};
    const subscriptionStartedAt = Number(b.subscriptionStartedAt) || null;
    const subscriptionExpiresAt = Number(b.subscriptionExpiresAt) || null;
    const lastPaymentId = typeof b.lastPaymentId === 'string' ? b.lastPaymentId.slice(0, 100) : null;

    const result = await pool!.query(
      `UPDATE users SET
         subscription_plan = $1,
         owned_plans = $2::jsonb,
         plan_expiries = $3::jsonb,
         subscription_started_at = $4,
         subscription_expires_at = $5,
         last_payment_id = $6
       WHERE id = $7
       RETURNING id, name, email, subscription_plan, owned_plans, plan_expiries,
                 subscription_started_at, subscription_expires_at, last_payment_id`,
      [
        subscriptionPlan,
        JSON.stringify(ownedPlans),
        JSON.stringify(planExpiries),
        subscriptionStartedAt,
        subscriptionExpiresAt,
        lastPaymentId,
        res.locals.userId,
      ]
    );

    if (!result.rows[0]) return res.status(401).json({ error: 'Account not found' });
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('save subscription error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------- CHATS ----------------
router.get('/chats', requireConfigured, requireAuth, async (_req: Request, res: Response) => {
  try {
    const result = await pool!.query(
      `SELECT id, title, is_pinned, created_at, updated_at, messages
       FROM chats WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 500`,
      [res.locals.userId]
    );
    const chats = result.rows.map((r) => ({
      id: r.id,
      title: r.title,
      isPinned: r.is_pinned,
      createdAt: Number(r.created_at),
      updatedAt: Number(r.updated_at),
      messages: r.messages,
    }));
    res.json({ chats });
  } catch (err) {
    console.error('list chats error:', err);
    res.status(500).json({ error: 'Chats load nahi ho paye.' });
  }
});

router.put('/chats/:id', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const id = String(req.params.id).slice(0, 100);
    const b = req.body || {};
    if (!Array.isArray(b.messages)) return res.status(400).json({ error: 'messages array chahiye.' });
    if (b.messages.length > 1000) return res.status(400).json({ error: 'Chat bahut lambi hai.' });

    const title = String(b.title || 'New chat').slice(0, 200);
    const createdAt = Number(b.createdAt) || Date.now();
    const updatedAt = Number(b.updatedAt) || Date.now();

    await pool!.query(
      `INSERT INTO chats (id, user_id, title, is_pinned, created_at, updated_at, messages)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       ON CONFLICT (id, user_id) DO UPDATE SET
         title = EXCLUDED.title,
         is_pinned = EXCLUDED.is_pinned,
         updated_at = EXCLUDED.updated_at,
         messages = EXCLUDED.messages`,
      [id, res.locals.userId, title, Boolean(b.isPinned), createdAt, updatedAt, JSON.stringify(b.messages)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('save chat error:', err);
    res.status(500).json({ error: 'Chat save nahi ho payi.' });
  }
});

router.delete('/chats/:id', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const chatId = String(req.params.id);
    await pool!.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [chatId, res.locals.userId]);
    // Chat delete ho gayi to uska public share link bhi band
    await pool!.query('DELETE FROM shares WHERE chat_id = $1 AND owner_id = $2', [chatId, res.locals.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete chat error:', err);
    res.status(500).json({ error: 'Chat delete nahi ho payi.' });
  }
});

// ---------------- EPHEMERAL (GUEST / TEMP) CHATS ----------------
// Ye chats kabhi UI me wapas nahi laayi jaatin. Sirf 30 din ke liye DB me
// safety-net ke taur par rakhi jaati hain, phir apne aap delete ho jaati hain.
router.put('/ephemeral/chats/:id', requireConfigured, ephemeralLimiter, async (req: Request, res: Response) => {
  try {
    const owner = resolveEphemeralOwner(req);
    if (!owner) return res.status(400).json({ error: 'Guest id ya login chahiye.' });

    const id = String(req.params.id).slice(0, 100);
    const b = req.body || {};
    if (!Array.isArray(b.messages)) return res.status(400).json({ error: 'messages array chahiye.' });
    if (b.messages.length > 1000) return res.status(400).json({ error: 'Chat bahut lambi hai.' });

    const title = String(b.title || 'New chat').slice(0, 200);
    const createdAt = Number(b.createdAt) || Date.now();
    const updatedAt = Number(b.updatedAt) || Date.now();
    const isTemp = Boolean(b.isTemp);
    const expiresAt = createdAt + THIRTY_DAYS_MS;

    // Ek owner ki max 100 safety-net chats (bot DB bhar na sake)
    const known = await pool!.query(
      'SELECT 1 FROM ephemeral_chats WHERE id = $1 AND owner_type = $2 AND owner_id = $3',
      [id, owner.ownerType, owner.ownerId]
    );
    if (!known.rowCount) {
      const cnt = await pool!.query(
        'SELECT count(*)::int AS n FROM ephemeral_chats WHERE owner_type = $1 AND owner_id = $2',
        [owner.ownerType, owner.ownerId]
      );
      if (cnt.rows[0].n >= 100) return res.status(429).json({ error: 'Limit poori ho gayi.' });
    }

    await pool!.query(
      `INSERT INTO ephemeral_chats (id, owner_type, owner_id, is_temp, title, created_at, updated_at, expires_at, messages)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
       ON CONFLICT (id, owner_type, owner_id) DO UPDATE SET
         is_temp = EXCLUDED.is_temp,
         title = EXCLUDED.title,
         updated_at = EXCLUDED.updated_at,
         messages = EXCLUDED.messages`,
      [id, owner.ownerType, owner.ownerId, isTemp, title, createdAt, updatedAt, expiresAt, JSON.stringify(b.messages)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('save ephemeral chat error:', err);
    res.status(500).json({ error: 'Chat save nahi ho payi.' });
  }
});

// Guest login/register karke apna account bana le to us guest_id ki non-temp
// safety-net copies hata do (asli chats ab uske account me `chats` table me migrate ho chuki hain).
router.delete('/ephemeral/guest/:guestId', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const guestId = String(req.params.guestId).slice(0, 100);
    await pool!.query(
      `DELETE FROM ephemeral_chats WHERE owner_type = 'guest' AND owner_id = $1 AND is_temp = FALSE`,
      [guestId]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('purge guest ephemeral error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------- SHARE ----------------
// Chat ka ek read-only public snapshot banao. Sirf logged-in user hi share bana sakta hai.
router.post('/share/:chatId', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const chatId = String(req.params.chatId).slice(0, 100);
    const chatResult = await pool!.query(
      'SELECT title, messages FROM chats WHERE id = $1 AND user_id = $2',
      [chatId, res.locals.userId]
    );
    const chat = chatResult.rows[0];
    if (!chat) return res.status(404).json({ error: 'Chat nahi mili.' });

    const userResult = await pool!.query('SELECT name FROM users WHERE id = $1', [res.locals.userId]);
    const ownerName = userResult.rows[0]?.name || 'Tejas AI user';

    // Public snapshot me sirf ye fields jayengi (koi internal field leak nahi hogi)
    const safeMessages = (Array.isArray(chat.messages) ? chat.messages : [])
      .filter((m: any) => m && (m.role === 'user' || m.role === 'assistant'))
      .map((m: any) => ({
        id: String(m.id || '').slice(0, 100),
        role: m.role,
        content: String(m.content || '').slice(0, 100000),
        timestamp: Number(m.timestamp) || Date.now(),
      }));

    // Us chat ka link pehle se hai to wahi rakho aur snapshot naya kar do (har click pe naya link nahi)
    const existing = await pool!.query(
      'SELECT share_id FROM shares WHERE chat_id = $1 AND owner_id = $2 ORDER BY created_at DESC LIMIT 1',
      [chatId, res.locals.userId]
    );
    if (existing.rows[0]) {
      const shareId = existing.rows[0].share_id;
      await pool!.query(
        'UPDATE shares SET title = $1, messages = $2::jsonb, owner_name = $3 WHERE share_id = $4',
        [chat.title, JSON.stringify(safeMessages), ownerName, shareId]
      );
      return res.json({ shareId });
    }

    const shareId = randomUUID().replace(/-/g, '').slice(0, 16);
    await pool!.query(
      `INSERT INTO shares (share_id, chat_id, owner_id, owner_name, title, messages, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
      [shareId, chatId, res.locals.userId, ownerName, chat.title, JSON.stringify(safeMessages), Date.now()]
    );
    res.status(201).json({ shareId });
  } catch (err) {
    console.error('create share error:', err);
    res.status(500).json({ error: 'Share link nahi ban paya.' });
  }
});

// Public read: login ho ya na ho, koi bhi shared chat padh sakta hai.
router.get('/share/:shareId', requireConfigured, shareReadLimiter, async (req: Request, res: Response) => {
  try {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Cache-Control', 'no-store');
    const shareId = String(req.params.shareId).slice(0, 64);
    const result = await pool!.query(
      'SELECT title, messages, owner_name, created_at FROM shares WHERE share_id = $1',
      [shareId]
    );
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'Ye share link maujood nahi hai ya delete ho chuki hai.' });
    res.json({
      title: row.title,
      messages: row.messages,
      ownerName: row.owner_name,
      createdAt: Number(row.created_at),
    });
  } catch (err) {
    console.error('get share error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Apna share link wapas hatao (revoke) — sirf jisne banaya wahi hata sakta hai.
router.delete('/share/:shareId', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    await pool!.query('DELETE FROM shares WHERE share_id = $1 AND owner_id = $2', [
      String(req.params.shareId).slice(0, 64),
      res.locals.userId,
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete share error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// ---------------- PAYMENTS ----------------
// Save a payment record after a successful subscription purchase.
router.post('/payments', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const b = req.body || {};
    const id = randomUUID();
    await pool!.query(
      `INSERT INTO payments
         (id, user_id, plan, model_id, plan_name, amount, period, duration_days,
          payment_method, utr_number, tx_id, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        id,
        res.locals.userId,
        String(b.plan || '').slice(0, 20),
        String(b.modelId || '').slice(0, 100),
        String(b.planName || '').slice(0, 100),
        Number(b.amount) || 0,
        String(b.period || '').slice(0, 30),
        Number(b.durationDays) || 0,
        String(b.paymentMethod || 'upi').slice(0, 20),
        b.utrNumber ? String(b.utrNumber).slice(0, 100) : null,
        String(b.txId || '').slice(0, 100),
        Number(b.createdAt) || Date.now(),
      ]
    );
    res.status(201).json({ ok: true, id });
  } catch (err) {
    console.error('save payment error:', err);
    res.status(500).json({ error: 'Payment save nahi ho paya.' });
  }
});

// List the logged-in user's payment history.
router.get('/payments', requireConfigured, requireAuth, async (_req: Request, res: Response) => {
  try {
    const result = await pool!.query(
      `SELECT id, plan, model_id, plan_name, amount, period, duration_days,
              payment_method, utr_number, tx_id, created_at
       FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200`,
      [res.locals.userId]
    );
    const payments = result.rows.map((r) => ({
      id: r.id,
      plan: r.plan,
      modelId: r.model_id,
      planName: r.plan_name,
      amount: Number(r.amount),
      period: r.period,
      durationDays: Number(r.duration_days),
      paymentMethod: r.payment_method,
      utrNumber: r.utr_number || undefined,
      txId: r.tx_id,
      createdAt: Number(r.created_at),
    }));
    res.json({ payments });
  } catch (err) {
    console.error('list payments error:', err);
    res.status(500).json({ error: 'Payment history load nahi ho payi.' });
  }
});

// Single payment record (for the detail view / receipt).
router.get('/payments/:id', requireConfigured, requireAuth, async (req: Request, res: Response) => {
  try {
    const result = await pool!.query(
      `SELECT id, plan, model_id, plan_name, amount, period, duration_days,
              payment_method, utr_number, tx_id, created_at
       FROM payments WHERE id = $1 AND user_id = $2`,
      [String(req.params.id).slice(0, 100), res.locals.userId]
    );
    const r = result.rows[0];
    if (!r) return res.status(404).json({ error: 'Payment not found.' });
    res.json({
      payment: {
        id: r.id,
        plan: r.plan,
        modelId: r.model_id,
        planName: r.plan_name,
        amount: Number(r.amount),
        period: r.period,
        durationDays: Number(r.duration_days),
        paymentMethod: r.payment_method,
        utrNumber: r.utr_number || undefined,
        txId: r.tx_id,
        createdAt: Number(r.created_at),
      },
    });
  } catch (err) {
    console.error('get payment error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------- SHARES (list user's own shares) ----------------
router.get('/shares', requireConfigured, requireAuth, async (_req: Request, res: Response) => {
  try {
    const result = await pool!.query(
      `SELECT share_id, chat_id, title, created_at
       FROM shares WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 200`,
      [res.locals.userId]
    );
    const shares = result.rows.map((r) => ({
      shareId: r.share_id,
      chatId: r.chat_id,
      title: r.title,
      createdAt: Number(r.created_at),
    }));
    res.json({ shares });
  } catch (err) {
    console.error('list shares error:', err);
    res.status(500).json({ error: 'Share list load nahi ho payi.' });
  }
});
export default router;