/**
 * Database Module - SQLite setup and operations
 * Handles all database interactions for the Family Chat App
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Database file path
const DB_PATH = path.join(__dirname, '..', 'database.sqlite');

// Initialize database connection
let db;

// Create database connection with extended timeout for heavy operations
function initDatabase() {
  try {
    db = new Database(DB_PATH, {
      timeout: 10000,
      verbose: console.log
    });

    // Enable foreign keys
    db.pragma('foreign_keys = ON');

    // Set journal mode to WAL for better concurrency
    db.pragma('journal_mode = WAL');

    // Create tables
    createTables();

    console.log('✅ Database initialized successfully');
    return db;
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    throw error;
  }
}

/**
 * Create all necessary database tables
 */
function createTables() {
  // Users table - stores all family member accounts
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT DEFAULT 'member' CHECK(role IN ('admin', 'moderator', 'member')),
      avatar_url TEXT DEFAULT NULL,
      is_online INTEGER DEFAULT 0,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Messages table - stores all chat messages
  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('text', 'image', 'voice', 'file', 'sticker')),
      content TEXT NOT NULL,
      file_name TEXT DEFAULT NULL,
      file_size INTEGER DEFAULT NULL,
      file_mime_type TEXT DEFAULT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_edited INTEGER DEFAULT 0,
      is_deleted INTEGER DEFAULT 0,
      reply_to_id INTEGER DEFAULT NULL,
      is_pinned INTEGER DEFAULT 0,
      pinned_by INTEGER DEFAULT NULL,
      pinned_at DATETIME DEFAULT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (reply_to_id) REFERENCES messages(id) ON DELETE SET NULL,
      FOREIGN KEY (pinned_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  // Read receipts table - tracks message read status
  db.exec(`
    CREATE TABLE IF NOT EXISTS read_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(message_id, user_id)
    )
  `);

  // Pinned messages reference table (for easier querying)
  db.exec(`
    CREATE TABLE IF NOT EXISTS pinned_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id INTEGER NOT NULL UNIQUE,
      pinned_by INTEGER NOT NULL,
      pinned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
      FOREIGN KEY (pinned_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create indexes for performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
    CREATE INDEX IF NOT EXISTS idx_messages_pinned ON messages(is_pinned);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_read_receipts_message ON read_receipts(message_id);
  `);
}

/**
 * Get database instance
 */
function getDb() {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return db;
}

/**
 * Close database connection
 */
function closeDatabase() {
  if (db) {
    db.close();
    db = null;
    console.log('Database connection closed');
  }
}

/**
 * Create default admin user if not exists
 */
function ensureAdminUser(username, password) {
  const existingUser = db.prepare('SELECT id FROM users WHERE role = ?').get('admin');
  
  if (!existingUser) {
    const bcrypt = require('bcryptjs');
    const passwordHash = bcrypt.hashSync(password, 10);
    
    db.prepare(`
      INSERT INTO users (username, password_hash, display_name, role)
      VALUES (?, ?, ?, ?)
    `).run(username, passwordHash, 'Family Admin', 'admin');
    
    console.log(`✅ Default admin user created: ${username}`);
  }
}

/**
 * Clean old messages (optional maintenance)
 */
function cleanOldMessages(daysOld = 30) {
  const result = db.prepare(`
    DELETE FROM messages
    WHERE is_deleted = 1
    AND timestamp < datetime('now', '-${daysOld} days')
  `).run();
  
  console.log(`🧹 Cleaned ${result.changes} old deleted messages`);
}

module.exports = {
  initDatabase,
  getDb,
  closeDatabase,
  ensureAdminUser,
  cleanOldMessages
};
