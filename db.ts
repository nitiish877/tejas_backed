import { Pool } from 'pg';

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();

export const dbEnabled = Boolean(DATABASE_URL);

function needsSsl(url: string): boolean {
  if (/sslmode=disable/i.test(url)) return false;
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
    console.warn('DATABASE_URL set nahi hai -> guest mode only.');
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
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS subscription_plan TEXT DEFAULT 'free',
      ADD COLUMN IF NOT EXISTS owned_plans JSONB DEFAULT '[]'::jsonb,
      ADD COLUMN IF NOT EXISTS plan_expiries JSONB DEFAULT '{}'::jsonb,
      ADD COLUMN IF NOT EXISTS subscription_started_at BIGINT,
      ADD COLUMN IF NOT EXISTS subscription_expires_at BIGINT,
      ADD COLUMN IF NOT EXISTS last_payment_id TEXT;
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT 'email',
      ADD COLUMN IF NOT EXISTS provider_id TEXT,
      ADD COLUMN IF NOT EXISTS avatar_url TEXT;
  `);
  await pool.query(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;`);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_provider_idx
      ON users (provider, provider_id)
      WHERE provider_id IS NOT NULL;
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

  // Trash support: deleted_at is set when the chat moves to trash.
  // Chats older than 60 days in trash are hard-deleted by purgeOldChats().
  await pool.query(`
    ALTER TABLE chats
      ADD COLUMN IF NOT EXISTS deleted_at BIGINT;
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS chats_user_updated_idx ON chats (user_id, updated_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS chats_user_deleted_idx ON chats (user_id, deleted_at);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ephemeral_chats (
      id          TEXT NOT NULL,
      owner_type  TEXT NOT NULL,
      owner_id    TEXT NOT NULL,
      is_temp     BOOLEAN NOT NULL DEFAULT FALSE,
      title       TEXT NOT NULL DEFAULT 'New chat',
      messages    JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at  BIGINT NOT NULL,
      updated_at  BIGINT NOT NULL,
      expires_at  BIGINT NOT NULL,
      PRIMARY KEY (id, owner_type, owner_id)
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS ephemeral_chats_expiry_idx ON ephemeral_chats (expires_at);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS ephemeral_chats_owner_idx ON ephemeral_chats (owner_type, owner_id);`);

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
  await pool.query(`CREATE INDEX IF NOT EXISTS shares_chat_idx ON shares (chat_id);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id             TEXT PRIMARY KEY,
      user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan           TEXT NOT NULL,
      model_id       TEXT NOT NULL,
      plan_name      TEXT NOT NULL,
      amount         INTEGER NOT NULL,
      period         TEXT NOT NULL,
      duration_days  INTEGER NOT NULL,
      payment_method TEXT NOT NULL,
      utr_number     TEXT,
      tx_id          TEXT NOT NULL,
      created_at     BIGINT NOT NULL
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS payments_user_idx ON payments (user_id, created_at DESC);`);

  console.log('Database ready (users, chats, ephemeral_chats, shares, payments).');
}

// 30 din se purani guest/temp chats hamesha ke liye delete kar do.
export async function purgeExpiredEphemeralChats(): Promise<number> {
  if (!pool) return 0;
  const result = await pool.query('DELETE FROM ephemeral_chats WHERE expires_at < $1', [Date.now()]);
  return result.rowCount || 0;
}

// 60 din se purani trashed chats ko hard-delete kar do.
export async function purgeOldChats(): Promise<number> {
  if (!pool) return 0;
  const cutoff = Date.now() - 60 * 24 * 60 * 60 * 1000;
  const result = await pool.query(
    `DELETE FROM chats WHERE deleted_at IS NOT NULL AND deleted_at < $1`,
    [cutoff]
  );
  return result.rowCount || 0;
}