/**
 * API Routes - All REST endpoints for the Family Chat App
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const { getPool, query } = require('./database-pg');
const {
  authMiddleware,
  adminOnly,
  modOrAdmin,
  hashPassword,
  verifyPassword,
  generateToken,
  escapeHtml,
  sanitizeInput
} = require('./auth');

// Load environment variables
require('dotenv').config();

const router = express.Router();
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB default
const MESSAGE_EDIT_WINDOW = parseInt(process.env.MESSAGE_EDIT_WINDOW) || 60; // 60 seconds

// ============================================
// FILE UPLOAD CONFIGURATION
// ============================================

// Ensure upload directories exist
const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
const avatarDir = path.join(uploadDir, 'avatars');
const messageDir = path.join(uploadDir, 'messages');

[uploadDir, avatarDir, messageDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isAvatar = req.query.type === 'avatar';
    cb(null, isAvatar ? avatarDir : messageDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const uniqueName = `${uuidv4()}${ext}`;
    cb(null, uniqueName);
  }
});

// File filter for security
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = {
    avatar: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    message: [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm',
      'application/pdf'
    ]
  };
  
  const isAvatar = req.query.type === 'avatar';
  const allowedTypes = isAvatar ? allowedMimeTypes.avatar : allowedMimeTypes.message;
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Allowed: ${allowedTypes.join(', ')}`), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Get relative file path for storage
 */
function getFilePath(filename, type = 'messages') {
  return `/uploads/${type}/${filename}`;
}

/**
 * Format message for API response
 */
function formatMessage(message) {
  return {
    id: message.id,
    userId: message.user_id,
    username: message.username,
    displayName: message.display_name,
    userAvatar: message.avatar_url,
    userRole: message.role,
    type: message.type,
    content: message.is_deleted ? null : escapeHtml(message.content),
    originalContent: message.is_deleted ? null : message.content,
    fileName: message.file_name,
    fileSize: message.file_size,
    fileMimeType: message.file_mime_type,
    timestamp: message.timestamp,
    isEdited: Boolean(message.is_edited),
    isDeleted: Boolean(message.is_deleted),
    replyToId: message.reply_to_id,
    replyTo: message.reply_to_content ? {
      id: message.reply_to_id,
      content: escapeHtml(message.reply_to_content.substring(0, 100)),
      displayName: message.reply_to_sender
    } : null,
    isPinned: Boolean(message.is_pinned),
    pinnedBy: message.pinned_by,
    pinnedByName: message.pinned_by_name
  };
}

// ============================================
// AUTH ROUTES
// ============================================

/**
 * POST /api/auth/register
 * Register a new user (Admin only or first user setup)
 */
router.post('/auth/register', authMiddleware, modOrAdmin, (req, res) => {
  try {
    const { username, displayName, password, role } = req.body;
    
    // Input validation
    if (!username || !displayName || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username, display name, and password are required.'
      });
    }
    
    // Username validation
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({
        success: false,
        error: 'Username can only contain letters, numbers, and underscores.'
      });
    }
    
    // Password strength
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters.'
      });
    }
    
    const db = getPool();
    
    // Check if username exists
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Username already exists.'
      });
    }
    
    // Determine role (only admin can create moderators)
    const userRole = (role && req.user.role === 'admin') ? role : 'member';
    
    // Create user
    const passwordHash = hashPassword(password);
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, display_name, role)
      VALUES (?, ?, ?, ?)
    `).run(username, passwordHash, sanitizeInput(displayName), userRole);
    
    const newUser = db.prepare('SELECT id, username, display_name, role FROM users WHERE id = ?').get(result.lastInsertRowid);
    
    res.status(201).json({
      success: true,
      message: 'User created successfully.',
      user: newUser
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create user.'
    });
  }
});

/**
 * POST /api/auth/login
 * User login
 */
router.post('/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required.'
      });
    }
    
    const db = getPool();
    const user = db.prepare(`
      SELECT id, username, password_hash, display_name, role, avatar_url, is_online, last_seen
      FROM users WHERE username = ?
    `).get(username);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }
    
    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }
    
    // Generate token
    const token = generateToken(user);
    
    // Update online status
    db.prepare('UPDATE users SET is_online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
    
    // Don't send password hash
    delete user.password_hash;
    
    res.json({
      success: true,
      message: 'Login successful.',
      token,
      user
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed.'
    });
  }
});

/**
 * POST /api/auth/logout
 * User logout
 */
router.post('/auth/logout', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    db.prepare('UPDATE users SET is_online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(req.user.id);
    
    res.json({
      success: true,
      message: 'Logged out successfully.'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed.'
    });
  }
});

/**
 * GET /api/auth/me
 * Get current user info
 */
router.get('/auth/me', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const user = db.prepare(`
      SELECT id, username, display_name, role, avatar_url, is_online, last_seen, created_at
      FROM users WHERE id = ?
    `).get(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found.'
      });
    }
    
    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user info.'
    });
  }
});

/**
 * PUT /api/auth/profile
 * Update user profile
 */
router.put('/auth/profile', authMiddleware, (req, res) => {
  try {
    const { displayName, currentPassword, newPassword } = req.body;
    const db = getPool();
    
    if (displayName) {
      db.prepare('UPDATE users SET display_name = ? WHERE id = ?')
        .run(sanitizeInput(displayName), req.user.id);
    }
    
    if (currentPassword && newPassword) {
      const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
      
      if (!verifyPassword(currentPassword, user.password_hash)) {
        return res.status(400).json({
          success: false,
          error: 'Current password is incorrect.'
        });
      }
      
      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          error: 'New password must be at least 6 characters.'
        });
      }
      
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .run(hashPassword(newPassword), req.user.id);
    }
    
    const updatedUser = db.prepare(`
      SELECT id, username, display_name, role, avatar_url FROM users WHERE id = ?
    `).get(req.user.id);
    
    res.json({
      success: true,
      message: 'Profile updated successfully.',
      user: updatedUser
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile.'
    });
  }
});

// ============================================
// USER MANAGEMENT ROUTES
// ============================================

/**
 * GET /api/users
 * Get all users
 */
router.get('/users', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const users = db.prepare(`
      SELECT id, username, display_name, role, avatar_url, is_online, last_seen, created_at
      FROM users ORDER BY display_name ASC
    `).all();
    
    res.json({
      success: true,
      users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get users.'
    });
  }
});

/**
 * GET /api/users/:id
 * Get specific user
 */
router.get('/users/:id', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const user = db.prepare(`
      SELECT id, username, display_name, role, avatar_url, is_online, last_seen, created_at
      FROM users WHERE id = ?
    `).get(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found.'
      });
    }
    
    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user.'
    });
  }
});

/**
 * PUT /api/users/:id/role
 * Update user role (Admin only)
 */
router.put('/users/:id/role', authMiddleware, adminOnly, (req, res) => {
  try {
    const { role } = req.body;
    
    if (!['admin', 'moderator', 'member'].includes(role)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid role.'
      });
    }
    
    const db = getPool();
    const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found.'
      });
    }
    
    // Prevent removing your own admin status
    if (user.id === req.user.id && user.role === 'admin' && role !== 'admin') {
      return res.status(400).json({
        success: false,
        error: 'You cannot demote yourself.'
      });
    }
    
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
    
    res.json({
      success: true,
      message: 'User role updated successfully.'
    });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update user role.'
    });
  }
});

/**
 * DELETE /api/users/:id
 * Delete user (Admin only)
 */
router.delete('/users/:id', authMiddleware, adminOnly, (req, res) => {
  try {
    const db = getPool();
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found.'
      });
    }
    
    // Prevent deleting yourself
    if (user.id === req.user.id) {
      return res.status(400).json({
        success: false,
        error: 'You cannot delete your own account.'
      });
    }
    
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    
    res.json({
      success: true,
      message: 'User deleted successfully.'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete user.'
    });
  }
});

// ============================================
// MESSAGE ROUTES
// ============================================

/**
 * GET /api/messages
 * Get messages with pagination
 */
router.get('/messages', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    const pinnedOnly = req.query.pinned === 'true';
    
    let query = `
      SELECT 
        m.*,
        u.username,
        u.display_name as display_name,
        u.avatar_url,
        u.role,
        r.username as reply_to_sender,
        mr.content as reply_to_content,
        pb.display_name as pinned_by_name
      FROM messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN messages mr ON m.reply_to_id = mr.id
      LEFT JOIN users r ON mr.user_id = r.id
      LEFT JOIN users pb ON m.pinned_by = pb.id
      WHERE m.is_deleted = 0
    `;
    
    if (pinnedOnly) {
      query += ' AND m.is_pinned = 1';
    }
    
    query += ' ORDER BY m.timestamp DESC LIMIT ? OFFSET ?';
    
    const messages = db.prepare(query).all(limit, offset);
    
    // Format messages (reverse for chronological order)
    const formattedMessages = messages.reverse().map(formatMessage);
    
    // Get total count
    const countQuery = pinnedOnly 
      ? 'SELECT COUNT(*) as total FROM messages WHERE is_deleted = 0 AND is_pinned = 1'
      : 'SELECT COUNT(*) as total FROM messages WHERE is_deleted = 0';
    const { total } = db.prepare(countQuery).get();
    
    res.json({
      success: true,
      messages: formattedMessages,
      total,
      hasMore: offset + messages.length < total
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get messages.'
    });
  }
});

/**
 * POST /api/messages
 * Send a new message
 */
router.post('/messages', authMiddleware, (req, res) => {
  try {
    const { type, content, replyTo, fileName, fileSize, fileMimeType } = req.body;
    
    // Input validation
    if (!type || !content) {
      return res.status(400).json({
        success: false,
        error: 'Message type and content are required.'
      });
    }
    
    const validTypes = ['text', 'image', 'voice', 'file', 'sticker'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message type.'
      });
    }
    
    // For text messages, sanitize content
    let messageContent = content;
    if (type === 'text') {
      messageContent = sanitizeInput(content);
    }
    
    const db = getPool();
    const result = db.prepare(`
      INSERT INTO messages (user_id, type, content, reply_to_id, file_name, file_size, file_mime_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      type,
      messageContent,
      replyTo || null,
      fileName || null,
      fileSize || null,
      fileMimeType || null
    );
    
    // Get the created message
    const message = db.prepare(`
      SELECT 
        m.*,
        u.username,
        u.display_name as display_name,
        u.avatar_url,
        u.role,
        r.username as reply_to_sender,
        mr.content as reply_to_content
      FROM messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN messages mr ON m.reply_to_id = mr.id
      LEFT JOIN users r ON mr.user_id = r.id
      WHERE m.id = ?
    `).get(result.lastInsertRowid);
    
    res.status(201).json({
      success: true,
      message: formatMessage(message)
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send message.'
    });
  }
});

/**
 * PUT /api/messages/:id
 * Edit a message (only within 1 minute window)
 */
router.put('/messages/:id', authMiddleware, (req, res) => {
  try {
    const { content } = req.body;
    const db = getPool();
    
    // Get message
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found.'
      });
    }
    
    // Check if user can edit (owner or admin/moderator)
    const canEdit = message.user_id === req.user.id || 
                    ['admin', 'moderator'].includes(req.user.role);
    
    if (!canEdit) {
      return res.status(403).json({
        success: false,
        error: 'You cannot edit this message.'
      });
    }
    
    // Check time window for non-moderators
    if (message.user_id === req.user.id && req.user.role === 'member') {
      const messageTime = new Date(message.timestamp).getTime();
      const now = Date.now();
      
      if (now - messageTime > MESSAGE_EDIT_WINDOW * 1000) {
        return res.status(403).json({
          success: false,
          error: `Edit window has expired. Messages can only be edited within ${MESSAGE_EDIT_WINDOW} seconds.`
        });
      }
    }
    
    // Update message
    db.prepare(`
      UPDATE messages SET content = ?, is_edited = 1, timestamp = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(sanitizeInput(content), req.params.id);
    
    res.json({
      success: true,
      message: 'Message updated successfully.'
    });
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to edit message.'
    });
  }
});

/**
 * DELETE /api/messages/:id
 * Delete a message (only within 1 minute window)
 */
router.delete('/messages/:id', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    
    // Get message
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found.'
      });
    }
    
    // Check if user can delete (owner or admin/moderator)
    const canDelete = message.user_id === req.user.id || 
                      ['admin', 'moderator'].includes(req.user.role);
    
    if (!canDelete) {
      return res.status(403).json({
        success: false,
        error: 'You cannot delete this message.'
      });
    }
    
    // Check time window for non-moderators (unless admin/moderator override)
    if (message.user_id === req.user.id && req.user.role === 'member') {
      const messageTime = new Date(message.timestamp).getTime();
      const now = Date.now();
      
      if (now - messageTime > MESSAGE_EDIT_WINDOW * 1000) {
        return res.status(403).json({
          success: false,
          error: `Delete window has expired. Messages can only be deleted within ${MESSAGE_EDIT_WINDOW} seconds.`
        });
      }
    }
    
    // Mark as deleted (soft delete)
    db.prepare(`
      UPDATE messages SET is_deleted = 1, content = '', timestamp = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.params.id);
    
    res.json({
      success: true,
      message: 'Message deleted successfully.'
    });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete message.'
    });
  }
});

/**
 * POST /api/messages/:id/pin
 * Pin a message
 */
router.post('/messages/:id/pin', authMiddleware, modOrAdmin, (req, res) => {
  try {
    const db = getPool();
    
    const message = db.prepare('SELECT is_pinned FROM messages WHERE id = ?').get(req.params.id);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found.'
      });
    }
    
    const newPinnedStatus = message.is_pinned ? 0 : 1;
    
    db.prepare(`
      UPDATE messages SET is_pinned = ?, pinned_by = ?, pinned_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(newPinnedStatus ? 1 : 0, newPinnedStatus ? req.user.id : null, req.params.id);
    
    res.json({
      success: true,
      message: newPinnedStatus ? 'Message pinned.' : 'Message unpinned.'
    });
  } catch (error) {
    console.error('Pin message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to pin message.'
    });
  }
});

// ============================================
// FILE UPLOAD ROUTES
// ============================================

/**
 * POST /api/upload
 * Upload a file (image, audio, PDF)
 */
router.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded.'
      });
    }
    
    const isAvatar = req.query.type === 'avatar';
    let fileUrl = getFilePath(req.file.filename, isAvatar ? 'avatars' : 'messages');
    let thumbnailUrl = null;
    
    // Compress images
    if (req.file.mimetype.startsWith('image/') && !isAvatar) {
      try {
        const inputPath = req.file.path;
        const outputFilename = `thumb_${req.file.filename}`;
        const outputPath = path.join(messageDir, outputFilename);
        
        await sharp(inputPath)
          .resize(300, 300, { fit: 'inside', withoutEnlargement: true })
          .jpeg({ quality: 70 })
          .toFile(outputPath);
        
        thumbnailUrl = getFilePath(outputFilename, 'messages');
      } catch (sharpError) {
        console.error('Image compression error:', sharpError);
      }
    }
    
    res.json({
      success: true,
      file: {
        url: fileUrl,
        thumbnailUrl,
        originalName: req.file.originalname,
        size: req.file.size,
        mimeType: req.file.mimetype
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      success: false,
      error: 'File upload failed.'
    });
  }
}, (error, req, res, next) => {
  res.status(400).json({
    success: false,
    error: error.message
  });
});

/**
 * POST /api/upload/avatar
 * Upload user avatar
 */
router.post('/upload/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded.'
      });
    }
    
    const fileUrl = getFilePath(req.file.filename, 'avatars');
    
    // Update user avatar
    const db = getPool();
    db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').run(fileUrl, req.user.id);
    
    res.json({
      success: true,
      avatar: fileUrl
    });
  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({
      success: false,
      error: 'Avatar upload failed.'
    });
  }
}, (error, req, res, next) => {
  res.status(400).json({
    success: false,
    error: error.message
  });
});

// ============================================
// STATUS ROUTES
// ============================================

/**
 * POST /api/status/online
 * Update user online status
 */
router.post('/status/online', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    db.prepare('UPDATE users SET is_online = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?')
      .run(req.body.isOnline ? 1 : 0, req.user.id);
    
    res.json({
      success: true
    });
  } catch (error) {
    console.error('Status update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update status.'
    });
  }
});

/**
 * GET /api/status/online
 * Get all online users
 */
router.get('/status/online', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const users = db.prepare(`
      SELECT id, username, display_name, avatar_url, last_seen
      FROM users WHERE is_online = 1
    `).all();
    
    res.json({
      success: true,
      users
    });
  } catch (error) {
    console.error('Get online users error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get online users.'
    });
  }
});

/**
 * GET /api/status/typing
 * Get typing indicators (simplified - in-memory store in production)
 */
router.get('/status/typing', authMiddleware, (req, res) => {
  // In a real app, this would use WebSockets or a Redis pub/sub
  // For this implementation, we return an empty response
  res.json({
    success: true,
    typing: []
  });
});

/**
 * POST /api/status/typing
 * Set typing indicator
 */
router.post('/status/typing', authMiddleware, (req, res) => {
  // In a real app, this would broadcast to other users
  res.json({
    success: true
  });
});

// ============================================
// READ RECEIPTS
// ============================================

/**
 * POST /api/messages/:id/read
 * Mark message as read
 */
router.post('/messages/:id/read', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    
    // Upsert read receipt
    const existing = db.prepare(`
      SELECT id FROM read_receipts WHERE message_id = ? AND user_id = ?
    `).get(req.params.id, req.user.id);
    
    if (!existing) {
      db.prepare(`
        INSERT INTO read_receipts (message_id, user_id) VALUES (?, ?)
      `).run(req.params.id, req.user.id);
    }
    
    res.json({
      success: true
    });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark message as read.'
    });
  }
});

/**
 * GET /api/messages/:id/read
 * Get read receipts for a message
 */
router.get('/messages/:id/read', authMiddleware, (req, res) => {
  try {
    const db = getPool();
    const receipts = db.prepare(`
      SELECT rr.*, u.display_name, u.avatar_url
      FROM read_receipts rr
      JOIN users u ON rr.user_id = u.id
      WHERE rr.message_id = ?
      ORDER BY rr.read_at ASC
    `).all(req.params.id);
    
    res.json({
      success: true,
      receipts
    });
  } catch (error) {
    console.error('Get receipts error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get read receipts.'
    });
  }
});

// ============================================
// SEARCH ROUTES
// ============================================

/**
 * GET /api/messages/search
 * Search messages
 */
router.get('/messages/search', authMiddleware, (req, res) => {
  try {
    const { q, limit } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Search query must be at least 2 characters.'
      });
    }
    
    const db = getPool();
    const searchLimit = Math.min(parseInt(limit) || 50, 100);
    const searchTerm = `%${sanitizeInput(q)}%`;
    
    const messages = db.prepare(`
      SELECT 
        m.*,
        u.username,
        u.display_name as display_name,
        u.avatar_url,
        u.role
      FROM messages m
      JOIN users u ON m.user_id = u.id
      WHERE m.is_deleted = 0
        AND m.type = 'text'
        AND m.content LIKE ?
      ORDER BY m.timestamp DESC
      LIMIT ?
    `).all(searchTerm, searchLimit);
    
    const formattedMessages = messages.reverse().map(formatMessage);
    
    res.json({
      success: true,
      messages: formattedMessages,
      query: q
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({
      success: false,
      error: 'Search failed.'
    });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

/**
 * GET /api/admin/stats
 * Get chat statistics
 */
router.get('/admin/stats', authMiddleware, modOrAdmin, (req, res) => {
  try {
    const db = getPool();
    
    const stats = {
      totalUsers: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
      totalMessages: db.prepare('SELECT COUNT(*) as count FROM messages').get().count,
      onlineUsers: db.prepare('SELECT COUNT(*) as count FROM users WHERE is_online = 1').get().count,
      pinnedMessages: db.prepare('SELECT COUNT(*) as count FROM messages WHERE is_pinned = 1').get().count,
      messagesToday: db.prepare(`
        SELECT COUNT(*) as count FROM messages 
        WHERE timestamp >= date('now', 'start of day')
      `).get().count,
      messagesThisWeek: db.prepare(`
        SELECT COUNT(*) as count FROM messages 
        WHERE timestamp >= date('now', '-7 days')
      `).get().count
    };
    
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics.'
    });
  }
});

/**
 * DELETE /api/admin/messages/:id
 * Admin can delete any message
 */
router.delete('/admin/messages/:id', authMiddleware, modOrAdmin, (req, res) => {
  try {
    const db = getPool();
    
    const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
    
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found.'
      });
    }
    
    db.prepare(`
      UPDATE messages SET is_deleted = 1, content = '', timestamp = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.params.id);
    
    res.json({
      success: true,
      message: 'Message deleted by admin.'
    });
  } catch (error) {
    console.error('Admin delete error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete message.'
    });
  }
});

module.exports = router;
