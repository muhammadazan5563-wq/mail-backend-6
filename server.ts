import express from 'express';
import path from 'path';
import fs from 'fs';
import dns from 'dns';
import net from 'net';
import dotenv from 'dotenv';
import { query } from './db.js';
import {
  AuthRequest,
  requireAuth,
  requireAdmin,
  checkIpRestriction,
  generateToken,
  hashPassword,
  comparePassword,
  getClientIp,
  recordLogin
} from './auth.js';

dotenv.config();

// Default OAuth credentials fallback
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '641354509885-r4i89bqh96nhqh8scpn1i3tshesurjmr.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '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';

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// CORS
const CORS_ORIGINS = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (CORS_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  // Cache preflight responses for 1 hour — browsers won't re-send OPTIONS for cached routes
  res.setHeader('Access-Control-Max-Age', '3600');
  if (req.method === 'OPTIONS') {
    // Return immediately for preflight — no middleware chain needed
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Apply IP restriction check globally
app.use(checkIpRestriction as any);

// Get exact redirect URI dynamically
const getRedirectUri = (req: any) => {
  const appUrlEnv = process.env.APP_URL;
  if (appUrlEnv) {
    const cleaned = appUrlEnv.endsWith('/') ? appUrlEnv.slice(0, -1) : appUrlEnv;
    return `${cleaned}/api/auth/callback`;
  }
  const host = req.get('host') || 'localhost:3000';
  const protocol = req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  return `${protocol}://${host}/api/auth/callback`;
};

// Custom helper: RFC 2822 email encoder
const constructRawEmail = (to: string, fromName: string, fromEmail: string, subject: string, body: string, replyTo?: string) => {
  const fromHeader = fromName ? `${fromName} <${fromEmail}>` : fromEmail;
  const emailLines = [
    `From: ${fromHeader}`,
    `To: <${to}>`,
    `Subject: =?utf-8?B?${Buffer.from(subject).toString('base64')}?=`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
  ];
  if (replyTo) {
    emailLines.splice(2, 0, `Reply-To: <${replyTo}>`);
  }
  emailLines.push('', body);
  const rawEmail = emailLines.join('\r\n');
  return Buffer.from(rawEmail)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

// Refreshes a Google OAuth access token
const refreshGoogleToken = async (refreshToken: string) => {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Failed to refresh Google token: ${errText}`);
  }

  const data = await response.json() as any;
  return {
    accessToken: data.access_token as string,
    expiresIn: data.expires_in as number,
  };
};

/* ==========================================================================
   AUTH ROUTES (Public - no token required)
   ========================================================================== */

// Register new user
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    // Check if user already exists
    const existing = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // Hash password and create user
    const passwordHash = await hashPassword(password);
    const result = await query(
      `INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, 'user') RETURNING id, email, name, role`,
      [email.toLowerCase(), passwordHash, name || '']
    );

    const user = result.rows[0];
    const token = generateToken({ id: user.id, email: user.email, name: user.name, role: user.role });

    // Record login
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';
    await recordLogin(user.id, ip, userAgent, true);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  try {
    const result = await query(
      'SELECT id, email, password_hash, name, role, is_active FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    if (!user.is_active) {
      await recordLogin(user.id, ip, userAgent, false);
      return res.status(403).json({ error: 'Your account has been deactivated. Contact admin.' });
    }

    const validPassword = await comparePassword(password, user.password_hash);
    if (!validPassword) {
      await recordLogin(user.id, ip, userAgent, false);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Check if user is restricted
    const restriction = await query(
      `SELECT id FROM admin_restrictions WHERE type = 'user_ban' AND value = $1 AND is_active = true`,
      [user.id.toString()]
    );
    if (restriction.rows.length > 0) {
      await recordLogin(user.id, ip, userAgent, false);
      return res.status(403).json({ error: 'Your account has been restricted. Contact admin.' });
    }

    const token = generateToken({ id: user.id, email: user.email, name: user.name, role: user.role });
    await recordLogin(user.id, ip, userAgent, true);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (err: any) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Get current user profile
app.get('/api/auth/me', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      'SELECT id, email, name, role, created_at, last_login_at FROM users WHERE id = $1',
      [req.user!.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch profile.' });
  }
});

// Change password
app.post('/api/auth/change-password', requireAuth as any, async (req: AuthRequest, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  try {
    const result = await query('SELECT password_hash FROM users WHERE id = $1', [req.user!.id]);
    const valid = await comparePassword(currentPassword, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const newHash = await hashPassword(newPassword);
    await query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, req.user!.id]);
    res.json({ success: true, message: 'Password updated successfully.' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to change password.' });
  }
});

/* ==========================================================================
   OAUTH ROUTES (Gmail connection - requires auth)
   ========================================================================== */

// 1. OAuth Initiate - now requires auth, stores user_id in state
// Support both /api/auth/url (legacy) and /api/oauth/url (new)
app.get(['/api/auth/url', '/api/oauth/url'], requireAuth as any, (req: AuthRequest, res) => {
  const redirectUri = getRedirectUri(req);
  const scopes = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ];

  // Encode user_id in state parameter for callback
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id })).toString('base64');

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: scopes.join(' '),
    access_type: 'offline',
    prompt: 'consent',
    state
  });

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  res.json({ url: authUrl, redirectUri });
});

// 2. OAuth Callback (public - Google redirects here)
app.get('/api/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('OAuth callback is missing authorization code.');
  }

  let userId: number | null = null;
  try {
    if (state) {
      const decoded = JSON.parse(Buffer.from(state as string, 'base64').toString());
      userId = decoded.userId;
    }
  } catch (e) {
    // state parsing failed
  }

  if (!userId) {
    return res.status(400).send('Invalid OAuth state. Please try connecting your account again.');
  }

  try {
    const redirectUri = getRedirectUri(req);

    // Exchange code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code: code as string,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });

    if (!tokenResponse.ok) {
      const errText = await tokenResponse.text();
      return res.status(400).send(`Failed exchanging OAuth code for tokens: ${errText}`);
    }

    const tokenData = await tokenResponse.json() as any;
    const { access_token, refresh_token, expires_in } = tokenData;

    // Fetch user details
    const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    if (!profileResponse.ok) {
      return res.status(400).send('Failed calling Google userinfo API.');
    }

    const profileData = await profileResponse.json() as any;
    const { email } = profileData;

    if (!email) {
      return res.status(400).send('Google account has no associated email.');
    }

    // Save or update account in DB (scoped to user)
    const existing = await query(
      'SELECT id, refresh_token FROM accounts WHERE user_id = $1 AND email = $2',
      [userId, email.toLowerCase()]
    );

    const expiresAt = Date.now() + (expires_in * 1000);

    if (existing.rows.length > 0) {
      const existingRefresh = existing.rows[0].refresh_token;
      await query(
        `UPDATE accounts SET access_token = $1, refresh_token = COALESCE($2, $3), expires_at = $4, status = 'active', connected_at = NOW() WHERE id = $5`,
        [access_token, refresh_token || null, existingRefresh, expiresAt, existing.rows[0].id]
      );
    } else {
      await query(
        `INSERT INTO accounts (user_id, email, access_token, refresh_token, expires_at, status) VALUES ($1, $2, $3, $4, $5, 'active')`,
        [userId, email.toLowerCase(), access_token, refresh_token, expiresAt]
      );
    }

    // Send popup closing logic
    res.send(`
      <html>
        <head><title>Authentication Successful</title></head>
        <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background-color: #fcfbfd; color: #1f1b2d;">
          <div style="max-width: 400px; margin: 0 auto; padding: 30px; border-radius: 12px; background: white; box-shadow: 0 4px 12px rgba(124, 92, 252, 0.08);">
            <div style="font-size: 48px; margin-bottom: 20px;">💜</div>
            <h2 style="color: #7C5CFC; margin-bottom: 10px;">Equinox Mail Connected</h2>
            <p style="color: #645a80; line-height: 1.5; font-size: 14px;">Your Gmail account <strong>${email}</strong> has been linked successfully.</p>
            <p style="color: #948ba4; font-size: 12px; margin-top: 25px;">You can close this window now.</p>
          </div>
          <script>
            if (window.opener) {
              window.opener.postMessage({ type: 'OAUTH_AUTH_SUCCESS', email: '${email}' }, '*');
              setTimeout(() => { window.close(); }, 1200);
            } else {
              setTimeout(() => { window.location.href = '/'; }, 1500);
            }
          </script>
        </body>
      </html>
    `);

  } catch (error: any) {
    console.error('OAuth Callback Error:', error);
    res.status(500).send(`Authentication error: ${error.message}`);
  }
});

/* ==========================================================================
   USER DATA ROUTES (All scoped to authenticated user)
   ========================================================================== */

// Get Connected Accounts (user-scoped)
app.get('/api/accounts', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      'SELECT email, connected_at, status, CASE WHEN refresh_token IS NOT NULL THEN \'active\' ELSE \'expired\' END as computed_status FROM accounts WHERE user_id = $1 ORDER BY connected_at DESC',
      [req.user!.id]
    );
    const safeAccounts = result.rows.map(a => ({
      email: a.email,
      connectedAt: a.connected_at,
      status: a.computed_status
    }));
    res.json(safeAccounts);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch accounts.' });
  }
});

// Disconnect Account (user-scoped)
app.delete('/api/accounts/:email', requireAuth as any, async (req: AuthRequest, res) => {
  const { email } = req.params;
  try {
    await query('DELETE FROM accounts WHERE user_id = $1 AND email = $2', [req.user!.id, email.toLowerCase()]);
    res.json({ success: true, email });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to disconnect account.' });
  }
});

// GET Contacts (user-scoped) — supports server-side pagination
app.get('/api/contacts', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(2000, Math.max(1, parseInt(req.query.limit as string) || 500));
    const listName = req.query.listName as string | undefined;
    const offset = (page - 1) * limit;

    // Build WHERE clause
    let whereSql = 'WHERE user_id = $1';
    const params: any[] = [userId];
    let paramIdx = 2;

    if (listName) {
      whereSql += ` AND LOWER(list_name) = LOWER($${paramIdx})`;
      params.push(listName);
      paramIdx++;
    }

    // Get total count
    const countResult = await query(`SELECT COUNT(*) as total FROM contacts ${whereSql}`, params);
    const total = parseInt(countResult.rows[0].total);
    const totalPages = Math.max(1, Math.ceil(total / limit));

    // Get paginated results
    const result = await query(
      `SELECT id, email, name, list_name as "listName", company, first_name as "firstName", variables, created_at as "createdAt" FROM contacts ${whereSql} ORDER BY created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
      [...params, limit, offset]
    );

    res.json({
      contacts: result.rows,
      total,
      page,
      totalPages,
      limit
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch contacts.' });
  }
});

// GET Contact Lists summary (user-scoped) — lightweight, returns list names + counts only
app.get('/api/contacts/lists', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      'SELECT list_name as "listName", COUNT(*) as count FROM contacts WHERE user_id = $1 GROUP BY list_name ORDER BY list_name',
      [req.user!.id]
    );
    res.json(result.rows.map(r => ({ listName: r.listName || 'Unassigned', count: parseInt(r.count) })));
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch contact lists.' });
  }
});

// POST Contacts (user-scoped) - batch insert for large lists
app.post('/api/contacts', requireAuth as any, async (req: AuthRequest, res) => {
  const newContacts = req.body;
  const userId = req.user!.id;

  try {
    const contactsArray = Array.isArray(newContacts) ? newContacts : [newContacts];

    // Batch insert in chunks of 2000 for performance (larger batches = fewer round-trips)
    const BATCH_SIZE = 2000;
    
    // Process batches concurrently in groups of 3 to maximize throughput
    // while not overwhelming the connection pool
    const CONCURRENCY = 3;
    const batches: any[][] = [];
    for (let i = 0; i < contactsArray.length; i += BATCH_SIZE) {
      batches.push(contactsArray.slice(i, i + BATCH_SIZE));
    }

    const processBatch = async (batch: any[]) => {
      const ids: string[] = [];
      const emails: string[] = [];
      const names: string[] = [];
      const listNames: string[] = [];
      const companies: string[] = [];
      const firstNames: string[] = [];
      const variables: string[] = [];

      for (const c of batch) {
        ids.push(c.id || Math.random().toString(36).substr(2, 9));
        emails.push((c.email || '').trim());
        names.push((c.name || '').trim());
        listNames.push((c.listName || 'Unassigned').trim());
        companies.push(c.company || '');
        firstNames.push(c.firstName || '');
        variables.push(JSON.stringify(c.variables || {}));
      }

      await query(
        `INSERT INTO contacts (id, user_id, email, name, list_name, company, first_name, variables)
         SELECT unnest($1::text[]), $2, unnest($3::text[]), unnest($4::text[]), unnest($5::text[]), unnest($6::text[]), unnest($7::text[]), unnest($8::jsonb[])
         ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name, list_name = EXCLUDED.list_name, company = EXCLUDED.company, first_name = EXCLUDED.first_name, variables = EXCLUDED.variables`,
        [ids, userId, emails, names, listNames, companies, firstNames, variables]
      );
    };

    // Process batches with controlled concurrency
    for (let i = 0; i < batches.length; i += CONCURRENCY) {
      const concurrentBatches = batches.slice(i, i + CONCURRENCY);
      await Promise.all(concurrentBatches.map(processBatch));
    }

    res.json({ success: true, count: contactsArray.length });
  } catch (err: any) {
    console.error('Error saving contacts:', err);
    res.status(500).json({ error: 'Failed to save contacts.' });
  }
});

// Delete individual Contact (user-scoped)
app.delete('/api/contacts/:listName/:id', requireAuth as any, async (req: AuthRequest, res) => {
  const { listName, id } = req.params;
  try {
    await query('DELETE FROM contacts WHERE user_id = $1 AND id = $2 AND LOWER(list_name) = LOWER($3)', [req.user!.id, id, listName]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete contact.' });
  }
});

// Delete whole list (user-scoped)
app.delete('/api/contacts/:listName', requireAuth as any, async (req: AuthRequest, res) => {
  const { listName } = req.params;
  try {
    await query('DELETE FROM contacts WHERE user_id = $1 AND LOWER(list_name) = LOWER($2)', [req.user!.id, listName]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete list.' });
  }
});

// Edit single contact (user-scoped)
app.put('/api/contacts/:listName/:id', requireAuth as any, async (req: AuthRequest, res) => {
  const { listName, id } = req.params;
  const updates = req.body;
  try {
    const result = await query(
      'SELECT * FROM contacts WHERE user_id = $1 AND id = $2 AND LOWER(list_name) = LOWER($3)',
      [req.user!.id, id, listName]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    await query(
      `UPDATE contacts SET 
        name = COALESCE($1, name), 
        email = COALESCE($2, email), 
        company = COALESCE($3, company), 
        first_name = COALESCE($4, first_name),
        variables = COALESCE($5, variables)
      WHERE user_id = $6 AND id = $7`,
      [
        updates.name !== undefined ? updates.name : null,
        updates.email !== undefined ? updates.email : null,
        updates.company !== undefined ? updates.company : null,
        updates.firstName !== undefined ? updates.firstName : null,
        updates.variables !== undefined ? JSON.stringify(updates.variables) : null,
        req.user!.id,
        id
      ]
    );

    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to update contact.' });
  }
});

// GET Campaigns (user-scoped)
app.get('/api/campaigns', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      `SELECT id, name, type, status, contact_list_name as "contactListName", subject, body_template as "bodyTemplate",
       sender_email as "senderEmail", delay_seconds as "delaySeconds", send_limit as "sendLimit",
       sender_emails as "senderEmails", emails_per_hour_per_account as "emailsPerHourPerAccount",
       total_contacts as "totalContacts", sent_count as "sentCount", success_count as "successCount",
       failed_count as "failedCount", created_at as "createdAt", started_at as "startedAt",
       reply_to as "replyTo", sender_name as "senderName"
       FROM campaigns WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user!.id]
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch campaigns.' });
  }
});

// POST Create Campaign (user-scoped)
app.post('/api/campaigns', requireAuth as any, async (req: AuthRequest, res) => {
  const campaignData = req.body;
  const userId = req.user!.id;
  const id = Math.random().toString(36).substr(2, 9);

  try {
    await query(
      `INSERT INTO campaigns (id, user_id, name, type, status, contact_list_name, subject, body_template, sender_email, delay_seconds, send_limit, sender_emails, emails_per_hour_per_account, total_contacts, reply_to, sender_name)
       VALUES ($1, $2, $3, $4, 'draft', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        id, userId, campaignData.name, campaignData.type,
        campaignData.contactListName, campaignData.subject, campaignData.bodyTemplate,
        campaignData.senderEmail || null, Number(campaignData.delaySeconds || 5),
        campaignData.sendLimit ? Number(campaignData.sendLimit) : null,
        JSON.stringify(campaignData.senderEmails || []),
        campaignData.emailsPerHourPerAccount ? Number(campaignData.emailsPerHourPerAccount) : null,
        Number(campaignData.totalContacts || 0),
        campaignData.replyTo || null,
        campaignData.senderName || null
      ]
    );

    const result = await query('SELECT * FROM campaigns WHERE id = $1', [id]);
    const campaign = result.rows[0];

    res.json({
      id: campaign.id,
      name: campaign.name,
      type: campaign.type,
      status: campaign.status,
      contactListName: campaign.contact_list_name,
      subject: campaign.subject,
      bodyTemplate: campaign.body_template,
      senderEmail: campaign.sender_email,
      delaySeconds: campaign.delay_seconds,
      sendLimit: campaign.send_limit,
      senderEmails: campaign.sender_emails,
      emailsPerHourPerAccount: campaign.emails_per_hour_per_account,
      totalContacts: campaign.total_contacts,
      sentCount: campaign.sent_count,
      successCount: campaign.success_count,
      failedCount: campaign.failed_count,
      createdAt: campaign.created_at,
      startedAt: campaign.started_at,
      replyTo: campaign.reply_to,
      senderName: campaign.sender_name
    });
  } catch (err: any) {
    console.error('Error creating campaign:', err);
    res.status(500).json({ error: 'Failed to create campaign.' });
  }
});

// PUT Edit Campaign (user-scoped)
app.put('/api/campaigns/:id', requireAuth as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  const updates = req.body;
  const userId = req.user!.id;

  try {
    // Verify ownership
    const existing = await query('SELECT * FROM campaigns WHERE id = $1 AND user_id = $2', [id, userId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    const campaign = existing.rows[0];

    // Handle status transitions
    if (updates.status && updates.status !== campaign.status) {
      if (updates.status === 'running' && campaign.status !== 'running') {
        await initializeCampaignQueue(campaign, userId);
        await query('UPDATE campaigns SET started_at = COALESCE(started_at, NOW()) WHERE id = $1', [id]);
      }
      // Update status immediately so the API responds fast
      await query('UPDATE campaigns SET status = $1 WHERE id = $2', [updates.status, id]);

      // For stop/pause: clean up the email queue asynchronously so the response is not blocked
      if (updates.status === 'stopped') {
        query('DELETE FROM email_queue WHERE campaign_id = $1 AND status = $2', [id, 'pending'])
          .catch((e: any) => console.error('Async queue cleanup error (stopped):', e));
      } else if (updates.status === 'paused') {
        query("UPDATE email_queue SET status = 'paused' WHERE campaign_id = $1 AND status = 'pending'", [id])
          .catch((e: any) => console.error('Async queue pause error:', e));
      }
    }

    // Update editable fields
    if (updates.name) await query('UPDATE campaigns SET name = $1 WHERE id = $2', [updates.name, id]);
    if (updates.subject) await query('UPDATE campaigns SET subject = $1 WHERE id = $2', [updates.subject, id]);
    if (updates.bodyTemplate) await query('UPDATE campaigns SET body_template = $1 WHERE id = $2', [updates.bodyTemplate, id]);
    if (updates.delaySeconds !== undefined) await query('UPDATE campaigns SET delay_seconds = $1 WHERE id = $2', [Number(updates.delaySeconds), id]);
    if (updates.emailsPerHourPerAccount !== undefined) await query('UPDATE campaigns SET emails_per_hour_per_account = $1 WHERE id = $2', [Number(updates.emailsPerHourPerAccount), id]);
    if (updates.replyTo !== undefined) await query('UPDATE campaigns SET reply_to = $1 WHERE id = $2', [updates.replyTo || null, id]);
    if (updates.senderName !== undefined) await query('UPDATE campaigns SET sender_name = $1 WHERE id = $2', [updates.senderName || null, id]);

    const updated = await query(
      `SELECT id, name, type, status, contact_list_name as "contactListName", subject, body_template as "bodyTemplate",
       sender_email as "senderEmail", delay_seconds as "delaySeconds", send_limit as "sendLimit",
       sender_emails as "senderEmails", emails_per_hour_per_account as "emailsPerHourPerAccount",
       total_contacts as "totalContacts", sent_count as "sentCount", success_count as "successCount",
       failed_count as "failedCount", created_at as "createdAt", started_at as "startedAt",
       reply_to as "replyTo", sender_name as "senderName"
       FROM campaigns WHERE id = $1`, [id]
    );

    res.json(updated.rows[0]);
  } catch (err: any) {
    console.error('Error updating campaign:', err);
    res.status(500).json({ error: 'Failed to update campaign.' });
  }
});

// DELETE Campaign (user-scoped)
app.delete('/api/campaigns/:id', requireAuth as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  try {
    await query('DELETE FROM email_queue WHERE campaign_id = $1 AND user_id = $2', [id, req.user!.id]);
    await query('DELETE FROM campaign_logs WHERE campaign_id = $1 AND user_id = $2', [id, req.user!.id]);
    await query('DELETE FROM campaigns WHERE id = $1 AND user_id = $2', [id, req.user!.id]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete campaign.' });
  }
});

// GET Campaign Logs (user-scoped)
app.get('/api/campaigns/:id/logs', requireAuth as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  try {
    const result = await query(
      `SELECT id, campaign_id as "campaignId", timestamp, recipient, sender, status, subject, error_message as "errorMessage"
       FROM campaign_logs WHERE campaign_id = $1 AND user_id = $2 ORDER BY timestamp DESC`,
      [id, req.user!.id]
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});

// GET Global Logs (user-scoped)
app.get('/api/global-logs', requireAuth as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      `SELECT id, campaign_id as "campaignId", timestamp, recipient, sender, status, subject, error_message as "errorMessage"
       FROM campaign_logs WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 100`,
      [req.user!.id]
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});

// POST Send Direct Single Email (user-scoped)
app.post('/api/send-direct', requireAuth as any, async (req: AuthRequest, res) => {
  const { senderEmail, recipientEmail, subject, body } = req.body;
  const userId = req.user!.id;

  if (!senderEmail || !recipientEmail || !subject || !body) {
    return res.status(400).json({ error: 'Missing required parameters: senderEmail, recipientEmail, subject, body' });
  }

  try {
    await sendGmailApi(userId, senderEmail, recipientEmail, '', subject, body);

    const logId = Math.random().toString(36).substr(2, 9);
    await query(
      `INSERT INTO campaign_logs (id, user_id, campaign_id, recipient, sender, status, subject) VALUES ($1, $2, 'direct', $3, $4, 'success', $5)`,
      [logId, userId, recipientEmail, senderEmail, subject]
    );

    res.json({ success: true });
  } catch (err: any) {
    console.error('Direct send failure:', err);

    const logId = Math.random().toString(36).substr(2, 9);
    await query(
      `INSERT INTO campaign_logs (id, user_id, campaign_id, recipient, sender, status, subject, error_message) VALUES ($1, $2, 'direct', $3, $4, 'failed', $5, $6)`,
      [logId, userId, recipientEmail, senderEmail, subject, err.message]
    );

    res.status(500).json({ error: err.message || 'Failed to send direct email' });
  }
});

/* ==========================================================================
   EMAIL VALIDATION (public-ish but requires auth)
   ========================================================================== */

// Typo domain lookup
const TYPOS: Record<string, string> = {
  'gamil.com': 'gmail.com', 'gmal.com': 'gmail.com', 'gmaill.com': 'gmail.com',
  'gamil.co': 'gmail.com', 'yaho.com': 'yahoo.com', 'iclod.com': 'icloud.com',
  'hotmial.com': 'hotmail.com', 'hotail.com': 'hotmail.com', 'msn.co': 'msn.com',
  'outlook.co': 'outlook.com', 'yahoo.co': 'yahoo.com'
};

const DISPOSABLE = [
  'mailinator.com', 'yopmail.com', 'temp-mail.org', 'tempmail.com',
  'dispostable.com', 'guerrillamail.com', 'sharklasers.com', '10minutemail.com',
  'trashmail.com', 'getairmail.com', 'temp-mail.com', 'tempmail.net'
];

// POST /api/validate-emails (requires auth)
app.post('/api/validate-emails', requireAuth as any, async (req: AuthRequest, res) => {
  const { emails } = req.body;
  if (!Array.isArray(emails)) {
    return res.status(400).json({ error: 'Expected "emails" parameter to be an array of strings' });
  }

  const promises = emails.map(async (rawEmail: string) => {
    const email = (rawEmail || '').trim();
    if (!email) {
      return { id: Math.random().toString(36).substr(2, 9), email: '', status: 'invalid', reason: 'Empty row', domain: '', selected: false };
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return { id: Math.random().toString(36).substr(2, 9), email, status: 'invalid', reason: 'Malformed address', domain: '', selected: false };
    }

    const parts = email.split('@');
    const domain = parts[1].toLowerCase();

    if (TYPOS[domain]) {
      return { id: Math.random().toString(36).substr(2, 9), email, status: 'invalid', reason: `Domain typo (did you mean ${TYPOS[domain]}?)`, domain, selected: false };
    }

    if (DISPOSABLE.includes(domain)) {
      return { id: Math.random().toString(36).substr(2, 9), email, status: 'invalid', reason: 'Disposable/temporary domain', domain, selected: false };
    }

    // DNS MX check
    try {
      const mxRecords = await dns.promises.resolveMx(domain);
      if (!mxRecords || mxRecords.length === 0) {
        return { id: Math.random().toString(36).substr(2, 9), email, status: 'invalid', reason: 'No MX records found', domain, selected: false };
      }
      return { id: Math.random().toString(36).substr(2, 9), email, status: 'valid', reason: 'MX records verified', domain, selected: true };
    } catch (err) {
      return { id: Math.random().toString(36).substr(2, 9), email, status: 'invalid', reason: 'Domain does not exist', domain, selected: false };
    }
  });

  const results = await Promise.all(promises);
  res.json(results);
});

/* ==========================================================================
   ADMIN ROUTES (requires admin role)
   ========================================================================== */

// GET all users (admin)
app.get('/api/admin/users', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      `SELECT id, email, name, role, is_active, last_login_at, last_login_ip, created_at FROM users ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// GET user details with stats (admin)
app.get('/api/admin/users/:id', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  try {
    const userResult = await query('SELECT id, email, name, role, is_active, last_login_at, last_login_ip, created_at FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const accountsCount = await query('SELECT COUNT(*) as count FROM accounts WHERE user_id = $1', [id]);
    const contactsCount = await query('SELECT COUNT(*) as count FROM contacts WHERE user_id = $1', [id]);
    const campaignsCount = await query('SELECT COUNT(*) as count FROM campaigns WHERE user_id = $1', [id]);
    const logsCount = await query('SELECT COUNT(*) as count FROM campaign_logs WHERE user_id = $1', [id]);

    res.json({
      ...userResult.rows[0],
      stats: {
        accounts: parseInt(accountsCount.rows[0].count),
        contacts: parseInt(contactsCount.rows[0].count),
        campaigns: parseInt(campaignsCount.rows[0].count),
        emailsSent: parseInt(logsCount.rows[0].count)
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch user details.' });
  }
});

// Toggle user active status (admin)
app.put('/api/admin/users/:id/toggle-active', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  try {
    await query('UPDATE users SET is_active = NOT is_active, updated_at = NOW() WHERE id = $1', [id]);
    const result = await query('SELECT id, email, name, role, is_active FROM users WHERE id = $1', [id]);
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to toggle user status.' });
  }
});

// Change user role (admin)
app.put('/api/admin/users/:id/role', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be "user" or "admin".' });
  }
  try {
    await query('UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2', [role, id]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to update role.' });
  }
});

// Delete user (admin)
app.delete('/api/admin/users/:id', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  const userId = parseInt(id);
  if (userId === req.user!.id) {
    return res.status(400).json({ error: 'Cannot delete your own account.' });
  }
  try {
    await query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete user.' });
  }
});

// GET login history (admin)
app.get('/api/admin/login-history', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { userId, limit } = req.query;
  try {
    let sql = `SELECT lh.*, u.email as user_email, u.name as user_name FROM login_history lh JOIN users u ON lh.user_id = u.id`;
    const params: any[] = [];

    if (userId) {
      sql += ' WHERE lh.user_id = $1';
      params.push(userId);
    }

    sql += ' ORDER BY lh.created_at DESC LIMIT $' + (params.length + 1);
    params.push(Number(limit) || 100);

    const result = await query(sql, params);
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch login history.' });
  }
});

// GET restrictions (admin)
app.get('/api/admin/restrictions', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  try {
    const result = await query(
      `SELECT ar.*, u.email as created_by_email FROM admin_restrictions ar LEFT JOIN users u ON ar.created_by = u.id ORDER BY ar.created_at DESC`
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch restrictions.' });
  }
});

// POST add restriction (admin)
app.post('/api/admin/restrictions', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { type, value, reason } = req.body;
  if (!type || !value) {
    return res.status(400).json({ error: 'Type and value are required.' });
  }
  if (!['ip_ban', 'user_ban'].includes(type)) {
    return res.status(400).json({ error: 'Type must be "ip_ban" or "user_ban".' });
  }
  try {
    const result = await query(
      `INSERT INTO admin_restrictions (type, value, reason, created_by) VALUES ($1, $2, $3, $4) RETURNING *`,
      [type, value, reason || '', req.user!.id]
    );
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to add restriction.' });
  }
});

// DELETE restriction (admin)
app.delete('/api/admin/restrictions/:id', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  const { id } = req.params;
  try {
    await query('DELETE FROM admin_restrictions WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to remove restriction.' });
  }
});

// GET admin dashboard stats
app.get('/api/admin/stats', requireAuth as any, requireAdmin as any, async (req: AuthRequest, res) => {
  try {
    const usersCount = await query('SELECT COUNT(*) as count FROM users');
    const activeUsers = await query('SELECT COUNT(*) as count FROM users WHERE is_active = true');
    const totalCampaigns = await query('SELECT COUNT(*) as count FROM campaigns');
    const totalEmails = await query('SELECT COUNT(*) as count FROM campaign_logs');
    const totalContacts = await query('SELECT COUNT(*) as count FROM contacts');
    const recentLogins = await query(
      `SELECT lh.*, u.email as user_email, u.name as user_name FROM login_history lh JOIN users u ON lh.user_id = u.id ORDER BY lh.created_at DESC LIMIT 20`
    );

    res.json({
      totalUsers: parseInt(usersCount.rows[0].count),
      activeUsers: parseInt(activeUsers.rows[0].count),
      totalCampaigns: parseInt(totalCampaigns.rows[0].count),
      totalEmailsSent: parseInt(totalEmails.rows[0].count),
      totalContacts: parseInt(totalContacts.rows[0].count),
      recentLogins: recentLogins.rows
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch admin stats.' });
  }
});

/* ==========================================================================
   QUEUE MANAGEMENT & RUNNER
   ========================================================================== */

async function initializeCampaignQueue(campaign: any, userId: number) {
  // Check if queue items already exist
  const existingResult = await query(
    'SELECT COUNT(*) as count FROM email_queue WHERE campaign_id = $1',
    [campaign.id]
  );
  const existingCount = parseInt(existingResult.rows[0].count);

  if (existingCount > 0) {
    // Resume: restore paused items to pending, then shift all pending items forward
    const now = Date.now();
    let intervalMs = (campaign.delay_seconds || 5) * 1000;

    if (campaign.type === 'auto') {
      const senders = campaign.sender_emails || [];
      const activeSendersNum = senders.length || 1;
      const ratePerHourPerAcct = campaign.emails_per_hour_per_account || 100;
      intervalMs = Math.max(1, Math.round((3600 / (ratePerHourPerAcct * activeSendersNum)) * 1000));
    }

    // Restore any paused items back to pending so the dispatcher picks them up
    await query(
      "UPDATE email_queue SET status = 'pending' WHERE campaign_id = $1 AND status = 'paused'",
      [campaign.id]
    );

    const pendingItems = await query(
      'SELECT id FROM email_queue WHERE campaign_id = $1 AND status = $2 ORDER BY delay_until ASC',
      [campaign.id, 'pending']
    );

    let runningDelay = 1000;
    for (const item of pendingItems.rows) {
      await query('UPDATE email_queue SET delay_until = $1 WHERE id = $2', [now + runningDelay, item.id]);
      runningDelay += intervalMs;
    }
    return;
  }

  // Find contacts for this campaign — use cursor-style pagination to avoid loading all into memory
  const countResult = await query(
    'SELECT COUNT(*) as total FROM contacts WHERE user_id = $1 AND LOWER(list_name) = LOWER($2)',
    [userId, campaign.contact_list_name]
  );
  const totalAvailable = parseInt(countResult.rows[0].total);

  if (totalAvailable === 0) return;

  let limit = totalAvailable;
  if (campaign.type === 'normal' && campaign.send_limit) {
    limit = Math.min(limit, campaign.send_limit);
  }

  let intervalMs = (campaign.delay_seconds || 5) * 1000;
  const now = Date.now();

  if (campaign.type === 'auto') {
    const senders = campaign.sender_emails || [];
    const activeSendersNum = senders.length || 1;
    const ratePerHourPerAcct = campaign.emails_per_hour_per_account || 100;
    intervalMs = Math.max(1, Math.round((3600 / (ratePerHourPerAcct * activeSendersNum)) * 1000));
  }

  // Process contacts in batches of 1000 to avoid memory issues with 50K+ contacts
  const QUEUE_BATCH_SIZE = 1000;
  let globalIdx = 0;
  let offset = 0;

  while (globalIdx < limit) {
    const batchLimit = Math.min(QUEUE_BATCH_SIZE, limit - globalIdx);
    const contactsBatch = await query(
      'SELECT * FROM contacts WHERE user_id = $1 AND LOWER(list_name) = LOWER($2) ORDER BY created_at ASC LIMIT $3 OFFSET $4',
      [userId, campaign.contact_list_name, batchLimit, offset]
    );

    if (contactsBatch.rows.length === 0) break;

    // Build batch insert arrays
    const ids: string[] = [];
    const userIds: number[] = [];
    const campaignIds: string[] = [];
    const recipientEmails: string[] = [];
    const recipientNames: string[] = [];
    const senderEmails: string[] = [];
    const subjects: string[] = [];
    const bodies: string[] = [];
    const delayUntils: number[] = [];

    for (const contact of contactsBatch.rows) {
      let senderEmail = '';
      if (campaign.type === 'normal') {
        senderEmail = campaign.sender_email || '';
      } else {
        const senders = campaign.sender_emails || [];
        if (senders.length > 0) {
          senderEmail = senders[globalIdx % senders.length];
        }
      }

      // Template substitution
      let personalizedBody = campaign.body_template || '';
      let personalizedSubject = campaign.subject || '';

      const performReplace = (key: string, value: string) => {
        const regex = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'gi');
        personalizedBody = personalizedBody.replace(regex, value);
        personalizedSubject = personalizedSubject.replace(regex, value);
      };

      performReplace('name', contact.name || 'Subscriber');
      performReplace('email', contact.email);
      performReplace('firstName', contact.first_name || (contact.name ? contact.name.split(' ')[0] : '') || 'Subscriber');
      performReplace('company', contact.company || 'your company');

      if (contact.variables && typeof contact.variables === 'object') {
        Object.entries(contact.variables).forEach(([k, v]) => {
          performReplace(k, String(v || ''));
        });
      }

      ids.push(Math.random().toString(36).substr(2, 9));
      userIds.push(userId);
      campaignIds.push(campaign.id);
      recipientEmails.push(contact.email);
      recipientNames.push(contact.name || '');
      senderEmails.push(senderEmail);
      subjects.push(personalizedSubject);
      bodies.push(personalizedBody);
      delayUntils.push(now + (globalIdx * intervalMs));

      globalIdx++;
    }

    // Batch insert using unnest for efficiency
    await query(
      `INSERT INTO email_queue (id, user_id, campaign_id, recipient_email, recipient_name, sender_email, status, subject, body, delay_until)
       SELECT unnest($1::text[]), unnest($2::int[]), unnest($3::text[]), unnest($4::text[]), unnest($5::text[]), unnest($6::text[]), 'pending', unnest($7::text[]), unnest($8::text[]), unnest($9::bigint[])`,
      [ids, userIds, campaignIds, recipientEmails, recipientNames, senderEmails, subjects, bodies, delayUntils]
    );

    offset += contactsBatch.rows.length;
  }

  // Update total contacts
  await query('UPDATE campaigns SET total_contacts = $1, sent_count = 0, success_count = 0, failed_count = 0 WHERE id = $2', [globalIdx, campaign.id]);
}

// Global token cache
const googleTokensCache: Record<string, { token: string; expiresAt: number }> = {};

async function sendGmailApi(userId: number, senderEmail: string, recipientEmail: string, recipientName: string, subject: string, htmlBody: string, senderName?: string, replyTo?: string) {
  // Find sender credentials (user-scoped)
  const accountResult = await query(
    'SELECT * FROM accounts WHERE user_id = $1 AND LOWER(email) = LOWER($2)',
    [userId, senderEmail]
  );

  if (accountResult.rows.length === 0) {
    throw new Error(`Gmail sender account ${senderEmail} is not authenticated.`);
  }

  const account = accountResult.rows[0];
  let accessToken = account.access_token;
  const isTokenExpired = !account.expires_at || account.expires_at <= Date.now() + 60 * 1000;

  if (isTokenExpired || !accessToken) {
    if (!account.refresh_token) {
      throw new Error(`Offline access required. Please reconnect Gmail ${senderEmail}.`);
    }

    const cacheKey = `${userId}:${account.email}`;
    const cached = googleTokensCache[cacheKey];
    if (cached && cached.expiresAt > Date.now() + 60 * 1000) {
      accessToken = cached.token;
    } else {
      const refreshResult = await refreshGoogleToken(account.refresh_token);
      accessToken = refreshResult.accessToken;
      const newExpiresAt = Date.now() + refreshResult.expiresIn * 1000;

      googleTokensCache[cacheKey] = { token: accessToken, expiresAt: newExpiresAt };
      await query(
        'UPDATE accounts SET access_token = $1, expires_at = $2, status = $3 WHERE id = $4',
        [accessToken, newExpiresAt, 'active', account.id]
      );
    }
  }

  const rawBase64 = constructRawEmail(recipientEmail, senderName || '', senderEmail, subject, htmlBody, replyTo);

  const sendRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw: rawBase64 })
  });

  if (!sendRes.ok) {
    const errorBody = await sendRes.text();
    throw new Error(`Gmail API failure [${sendRes.status}]: ${errorBody}`);
  }

  return await sendRes.json();
}

// Background queue dispatcher
async function executeEmailDispatchTick() {
  try {
    const activeCampaigns = await query("SELECT * FROM campaigns WHERE status = 'running'");

    if (activeCampaigns.rows.length === 0) return;

    for (const campaign of activeCampaigns.rows) {
      const pendingItems = await query(
        "SELECT * FROM email_queue WHERE campaign_id = $1 AND status = 'pending' AND delay_until <= $2 ORDER BY delay_until ASC LIMIT 3",
        [campaign.id, Date.now()]
      );

      if (pendingItems.rows.length === 0) {
        // Check if all items are processed (exclude paused — those are waiting for resume)
        const remaining = await query(
          "SELECT COUNT(*) as count FROM email_queue WHERE campaign_id = $1 AND status IN ('pending', 'paused')",
          [campaign.id]
        );
        if (parseInt(remaining.rows[0].count) === 0) {
          await query("UPDATE campaigns SET status = 'completed' WHERE id = $1", [campaign.id]);
        }
        continue;
      }

      for (const item of pendingItems.rows) {
        await query("UPDATE email_queue SET status = 'sending' WHERE id = $1", [item.id]);

        try {
          await sendGmailApi(campaign.user_id, item.sender_email, item.recipient_email, item.recipient_name, item.subject, item.body, campaign.sender_name || undefined, campaign.reply_to || undefined);

          await query("UPDATE email_queue SET status = 'success' WHERE id = $1", [item.id]);
          await query(
            'UPDATE campaigns SET sent_count = sent_count + 1, success_count = success_count + 1 WHERE id = $1',
            [campaign.id]
          );

          const logId = Math.random().toString(36).substr(2, 9);
          await query(
            `INSERT INTO campaign_logs (id, user_id, campaign_id, recipient, sender, status, subject) VALUES ($1, $2, $3, $4, $5, 'success', $6)`,
            [logId, campaign.user_id, campaign.id, item.recipient_email, item.sender_email, item.subject]
          );
        } catch (err: any) {
          await query("UPDATE email_queue SET status = 'failed' WHERE id = $1", [item.id]);
          await query(
            'UPDATE campaigns SET sent_count = sent_count + 1, failed_count = failed_count + 1 WHERE id = $1',
            [campaign.id]
          );

          const logId = Math.random().toString(36).substr(2, 9);
          await query(
            `INSERT INTO campaign_logs (id, user_id, campaign_id, recipient, sender, status, subject, error_message) VALUES ($1, $2, $3, $4, $5, 'failed', $6, $7)`,
            [logId, campaign.user_id, campaign.id, item.recipient_email, item.sender_email, item.subject, err.message]
          );

          console.error(`Send error (campaign ${campaign.id}):`, err.message);
        }
      }
    }
  } catch (err) {
    console.error('Queue Dispatch Tick Error:', err);
  }
}

// POST /api/dispatch (for cron triggers)
app.post('/api/dispatch', async (req, res) => {
  try {
    await executeEmailDispatchTick();
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dispatch', async (req, res) => {
  try {
    await executeEmailDispatchTick();
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Tick interval
if (!process.env.VERCEL) {
  setInterval(() => {
    executeEmailDispatchTick().catch(err => console.error('Tick error:', err));
  }, 1500);
}

/* ==========================================================================
   SERVER STARTUP
   ========================================================================== */

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    try {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    } catch (e) {
      // Vite not available, skip
    }
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    const indexHtml = path.join(distPath, 'index.html');
    if (fs.existsSync(indexHtml)) {
      app.use(express.static(distPath));
      app.get('*', (req, res, next) => {
        if (req.path.startsWith('/api/')) return next();
        res.sendFile(indexHtml);
      });
    }
  }

  if (!process.env.VERCEL) {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[Equinox Mail Server v2.0] Running on port ${PORT} with PostgreSQL`);
    });
  }
}

if (!process.env.VERCEL) {
  startServer();
}

export default app;
