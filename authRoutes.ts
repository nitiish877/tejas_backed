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

function publicUser(row: { id: string; name: string; email: string }) {
  return { id: row.id, name: row.name, email: row.email, provider: 'email' as const };
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
  const guestId = String(req.headers['x-guest-id'] || '').trim().slice(0, 100);
  if (guestId) return { ownerType: 'guest', ownerId: guestId };
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

    res.status(201).json({ token: signToken(id), user: publicUser({ id, name: displayName, email }) });
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

    const result = await pool!.query('SELECT id, name, email, password_hash FROM users WHERE email = $1', [email]);
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
    const result = await pool!.query('SELECT id, name, email FROM users WHERE id = $1', [res.locals.userId]);
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
      'UPDATE users SET name = $1 WHERE id = $2 RETURNING id, name, email',
      [name, res.locals.userId]
    );
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('update name error:', err);
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
    await pool!.query('DELETE FROM chats WHERE id = $1 AND user_id = $2', [String(req.params.id), res.locals.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete chat error:', err);
    res.status(500).json({ error: 'Chat delete nahi ho payi.' });
  }
});

// ---------------- EPHEMERAL (GUEST / TEMP) CHATS ----------------
// Ye chats kabhi UI me wapas nahi laayi jaatin. Sirf 30 din ke liye DB me
// safety-net ke taur par rakhi jaati hain, phir apne aap delete ho jaati hain.
router.put('/ephemeral/chats/:id', requireConfigured, async (req: Request, res: Response) => {
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
router.delete('/ephemeral/guest/:guestId', requireConfigured, async (req: Request, res: Response) => {
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

    const shareId = randomUUID().replace(/-/g, '').slice(0, 16);
    await pool!.query(
      `INSERT INTO shares (share_id, chat_id, owner_id, owner_name, title, messages, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
      [shareId, chatId, res.locals.userId, ownerName, chat.title, JSON.stringify(chat.messages), Date.now()]
    );
    res.status(201).json({ shareId });
  } catch (err) {
    console.error('create share error:', err);
    res.status(500).json({ error: 'Share link nahi ban paya.' });
  }
});

// Public read: login ho ya na ho, koi bhi shared chat padh sakta hai.
router.get('/share/:shareId', requireConfigured, async (req: Request, res: Response) => {
  try {
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

export default router;