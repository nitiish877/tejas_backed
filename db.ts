import { Pool } from 'pg';

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();

// DATABASE_URL na ho to app guest-mode me chalta rahega (login/chat-sync band)
export const dbEnabled = Boolean(DATABASE_URL);

function needsSsl(url: string): boolean {
  if (/sslmode=disable/i.test(url)) return false;
  // Local ya Railway ke private network pe SSL nahi chahiye; Neon/Supabase/public URL pe chahiye
  return !/(localhost|127\.0\.0\.1|\.railway\.internal)/i.test(url);
}

export const pool: Pool | null = dbEnabled
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: needsSsl(DATABASE_URL) ? { rejectUnauthorized: false } : false,
      max: 5,
    })
  : null;

export async function initDb(): Promise<void> {
  if (!pool) {
    console.warn('DATABASE_URL set nahi hai -> login/register aur chat sync disabled (guest mode only).');
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id         TEXT NOT NULL,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT NOT NULL DEFAULT 'New chat',
      is_pinned  BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL,
      messages   JSONB NOT NULL DEFAULT '[]'::jsonb,
      PRIMARY KEY (id, user_id)
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS chats_user_updated_idx ON chats (user_id, updated_at DESC);`);

  // Guest aur Temp chats: kabhi UI me wapas nahi dikhayi jaatin, sirf 30 din ke liye
  // safety-net ke taur par DB me rehti hain, phir apne aap delete ho jaati hain.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ephemeral_chats (
      id          TEXT NOT NULL,
      owner_type  TEXT NOT NULL,      -- 'guest' | 'user'
      owner_id    TEXT NOT NULL,      -- guest_id (anonymous) ya logged-in user_id
      is_temp     BOOLEAN NOT NULL DEFAULT FALSE,
      title       TEXT NOT NULL DEFAULT 'New chat',
      messages    JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at  BIGINT NOT NULL,
      updated_at  BIGINT NOT NULL,
      expires_at  BIGINT NOT NULL,    -- created_at + 30 din
      PRIMARY KEY (id, owner_type, owner_id)
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS ephemeral_chats_expiry_idx ON ephemeral_chats (expires_at);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS ephemeral_chats_owner_idx ON ephemeral_chats (owner_type, owner_id);`);

  // Share links: chat ka ek read-only public snapshot. Login ho ya na ho, share_id se koi bhi padh sakta hai.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shares (
      share_id    TEXT PRIMARY KEY,
      chat_id     TEXT NOT NULL,
      owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      owner_name  TEXT NOT NULL,
      title       TEXT NOT NULL DEFAULT 'Shared chat',
      messages    JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at  BIGINT NOT NULL
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS shares_owner_idx ON shares (owner_id);`);

  console.log('Database ready (users, chats, ephemeral_chats, shares tables).');
}

// 30 din se purani guest/temp chats hamesha ke liye delete kar do (auto-cleanup).
export async function purgeExpiredEphemeralChats(): Promise<number> {
  if (!pool) return 0;
  const result = await pool.query('DELETE FROM ephemeral_chats WHERE expires_at < $1', [Date.now()]);
  return result.rowCount || 0;
}