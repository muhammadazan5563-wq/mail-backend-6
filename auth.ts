/**
 * Authentication middleware and helpers.
 * Uses JWT tokens for stateless auth.
 */
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { query } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'equinox-mail-secret-change-me-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

export interface AuthUser {
  id: number;
  email: string;
  name: string;
  role: string;
}

export interface AuthRequest extends Request {
  user?: AuthUser;
}

/**
 * Generate a JWT token for a user
 */
export function generateToken(user: AuthUser): string {
  const payload = { id: user.id, email: user.email, name: user.name, role: user.role };
  const secret = JWT_SECRET;
  // Use type assertion to handle strict StringValue typing in newer jsonwebtoken
  return (jwt.sign as any)(payload, secret, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * Hash a password
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

/**
 * Compare password with hash
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Extract client IP from request
 */
export function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  if (Array.isArray(forwarded)) {
    return forwarded[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

/**
 * Middleware: Require authentication
 * Attaches user object to req.user
 */
export function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUser;
    req.user = decoded;
    next();
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid authentication token.' });
  }
}

/**
 * Middleware: Require admin role
 * Must be used AFTER requireAuth
 */
export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

/**
 * In-memory cache for IP restriction checks to avoid hitting DB on every request.
 * Cache entries expire after 60 seconds.
 */
const ipRestrictionCache: Map<string, { restricted: boolean; expiresAt: number }> = new Map();
const IP_CACHE_TTL_MS = 60_000; // 60 seconds

/**
 * Middleware: Check if user IP is restricted
 * Skips OPTIONS (preflight) requests entirely for performance.
 * Uses in-memory cache to avoid DB round-trip on every request.
 */
export async function checkIpRestriction(req: AuthRequest, res: Response, next: NextFunction) {
  // Never block preflight requests — they must return fast for CORS to work
  if (req.method === 'OPTIONS') {
    return next();
  }

  const ip = getClientIp(req);
  
  // Check cache first
  const cached = ipRestrictionCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) {
    if (cached.restricted) {
      return res.status(403).json({ error: 'Access denied. Your IP has been restricted.' });
    }
    return next();
  }

  try {
    const result = await query(
      `SELECT id FROM admin_restrictions WHERE type = 'ip_ban' AND value = $1 AND is_active = true`,
      [ip]
    );
    
    const isRestricted = result.rows.length > 0;
    
    // Cache the result
    ipRestrictionCache.set(ip, { restricted: isRestricted, expiresAt: Date.now() + IP_CACHE_TTL_MS });
    
    if (isRestricted) {
      return res.status(403).json({ error: 'Access denied. Your IP has been restricted.' });
    }
    
    next();
  } catch (err) {
    // If DB check fails, allow access (fail open for availability)
    next();
  }
}

/**
 * Record login attempt in history
 */
export async function recordLogin(userId: number, ip: string, userAgent: string, success: boolean) {
  try {
    await query(
      `INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES ($1, $2, $3, $4)`,
      [userId, ip, userAgent, success]
    );
    
    if (success) {
      await query(
        `UPDATE users SET last_login_at = NOW(), last_login_ip = $1, updated_at = NOW() WHERE id = $2`,
        [ip, userId]
      );
    }
  } catch (err) {
    console.error('Failed to record login:', err);
  }
}
