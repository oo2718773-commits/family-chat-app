/**
 * Authentication Middleware and Security Functions
 * Handles JWT token validation, password hashing, and security protections
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getDb } = require('./database');

// Load environment variables
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;

/**
 * Hash a password using bcrypt
 * @param {string} password - Plain text password
 * @returns {string} - Hashed password
 */
function hashPassword(password) {
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

/**
 * Verify a password against a hash
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {boolean} - Whether password matches
 */
function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

/**
 * Generate a JWT token for a user
 * @param {object} user - User object from database
 * @returns {string} - JWT token
 */
function generateToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role
  };
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token
 * @returns {object|null} - Decoded payload or null if invalid
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

/**
 * Extract token from Authorization header
 * @param {object} req - Express request object
 * @returns {string|null} - Token or null
 */
function extractToken(req) {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Also check for token in cookies
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  
  return null;
}

/**
 * Authentication middleware - protects routes
 * Must be used after cookie-parser middleware
 */
function authMiddleware(req, res, next) {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please log in.'
      });
    }
    
    const decoded = verifyToken(token);
    
    if (!decoded) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired token. Please log in again.'
      });
    }
    
    // Verify user still exists in database
    const db = getDb();
    const user = db.prepare('SELECT id, role, is_online FROM users WHERE id = ?').get(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User no longer exists.'
      });
    }
    
    // Attach user info to request
    req.user = decoded;
    req.userDb = user;
    
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(500).json({
      success: false,
      error: 'Authentication error.'
    });
  }
}

/**
 * Role-based authorization middleware
 * @param {...string} allowedRoles - Roles that can access the route
 * @returns {function} - Middleware function
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required.'
      });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'You do not have permission to perform this action.'
      });
    }
    
    next();
  };
}

/**
 * Admin-only middleware
 */
function adminOnly(req, res, next) {
  return requireRole('admin')(req, res, next);
}

/**
 * Moderator or admin middleware
 */
function modOrAdmin(req, res, next) {
  return requireRole('admin', 'moderator')(req, res, next);
}

/**
 * XSS Protection - Sanitize user input
 * @param {string} str - Input string
 * @returns {string} - Sanitized string
 */
function sanitizeInput(str) {
  if (typeof str !== 'string') {
    return '';
  }
  
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Escape HTML for safe rendering
 * @param {string} str - Input string
 * @returns {string} - Escaped string
 */
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return '';
  }
  
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generate a random secure ID
 * @param {number} length - Length of ID
 * @returns {string} - Random ID
 */
function generateSecureId(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomArray = new Uint8Array(length);
  crypto.getRandomValues(randomArray);
  
  for (let i = 0; i < length; i++) {
    result += chars[randomArray[i] % chars.length];
  }
  
  return result;
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken,
  extractToken,
  authMiddleware,
  requireRole,
  adminOnly,
  modOrAdmin,
  sanitizeInput,
  escapeHtml,
  generateSecureId,
  JWT_SECRET,
  JWT_EXPIRES_IN
};
