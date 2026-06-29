/**
 * Database Migration Script
 * Run: npm run migrate
 * 
 * Creates all required tables for multi-tenant Equinox Mail.
 * Safe to run multiple times (uses IF NOT EXISTS).
 */
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});

const SCHEMA = `
-- Users table (authentication and multi-tenancy)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255) DEFAULT '',
  role VARCHAR(50) DEFAULT 'user',
  is_active BOOLEAN DEFAULT true,
  last_login_at TIMESTAMP,
  last_login_ip VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Login history for IP tracking (admin feature)
CREATE TABLE IF NOT EXISTS login_history (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  ip_address VARCHAR(100) NOT NULL,
  user_agent TEXT,
  success BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Gmail accounts (per user)
CREATE TABLE IF NOT EXISTS accounts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  connected_at TIMESTAMP DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'active',
  refresh_token TEXT,
  access_token TEXT,
  expires_at BIGINT,
  UNIQUE(user_id, email)
);

-- Contacts (per user)
CREATE TABLE IF NOT EXISTS contacts (
  id VARCHAR(50) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  name VARCHAR(255) DEFAULT '',
  list_name VARCHAR(255) DEFAULT 'Unassigned',
  company VARCHAR(255) DEFAULT '',
  first_name VARCHAR(255) DEFAULT '',
  variables JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Campaigns (per user)
CREATE TABLE IF NOT EXISTS campaigns (
  id VARCHAR(50) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(50) DEFAULT 'normal',
  status VARCHAR(50) DEFAULT 'draft',
  contact_list_name VARCHAR(255),
  subject TEXT,
  body_template TEXT,
  sender_email VARCHAR(255),
  delay_seconds INTEGER DEFAULT 5,
  send_limit INTEGER,
  sender_emails JSONB DEFAULT '[]',
  emails_per_hour_per_account INTEGER,
  total_contacts INTEGER DEFAULT 0,
  sent_count INTEGER DEFAULT 0,
  success_count INTEGER DEFAULT 0,
  failed_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  started_at TIMESTAMP
);

-- Campaign logs (per user)
CREATE TABLE IF NOT EXISTS campaign_logs (
  id VARCHAR(50) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  campaign_id VARCHAR(50) REFERENCES campaigns(id) ON DELETE CASCADE,
  timestamp TIMESTAMP DEFAULT NOW(),
  recipient VARCHAR(255),
  sender VARCHAR(255),
  status VARCHAR(50),
  subject TEXT,
  error_message TEXT
);

-- Email queue (per user)
CREATE TABLE IF NOT EXISTS email_queue (
  id VARCHAR(50) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  campaign_id VARCHAR(50) REFERENCES campaigns(id) ON DELETE CASCADE,
  recipient_email VARCHAR(255),
  recipient_name VARCHAR(255),
  sender_email VARCHAR(255),
  status VARCHAR(50) DEFAULT 'pending',
  subject TEXT,
  body TEXT,
  delay_until BIGINT
);

-- Admin restrictions (IP bans, user restrictions)
CREATE TABLE IF NOT EXISTS admin_restrictions (
  id SERIAL PRIMARY KEY,
  type VARCHAR(50) NOT NULL,
  value VARCHAR(255) NOT NULL,
  reason TEXT,
  created_by INTEGER REFERENCES users(id),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_user_id ON contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_list_name ON contacts(user_id, list_name);
CREATE INDEX IF NOT EXISTS idx_contacts_user_list_created ON contacts(user_id, list_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id);
CREATE INDEX IF NOT EXISTS idx_campaign_logs_user_id ON campaign_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_campaign_logs_campaign_id ON campaign_logs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_email_queue_campaign_id ON email_queue(campaign_id);
CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status);
CREATE INDEX IF NOT EXISTS idx_email_queue_campaign_status_delay ON email_queue(campaign_id, status, delay_until);
CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_restrictions_type ON admin_restrictions(type);

-- Create default admin user (password: admin123)
INSERT INTO users (email, password_hash, name, role)
VALUES ('admin@equinox.mail', '$2a$10$f6FKZTBO.rLR8BnYf6IPAeO8B51N3W5q3H4aSeFpNIxHjvwfDJn/2', 'Admin', 'admin')
ON CONFLICT (email) DO NOTHING;
`;

async function migrate() {
  const client = await pool.connect();
  try {
    console.log('Running database migrations...');
    await client.query(SCHEMA);
    console.log('Database migration completed successfully!');
    console.log('');
    console.log('Default admin account:');
    console.log('  Email: admin@equinox.mail');
    console.log('  Password: admin123');
    console.log('');
    console.log('Please change the admin password after first login!');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
