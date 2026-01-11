/**
 * Family Chat App - Main Server Entry Point
 * A secure, private family messaging application with PWA support
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import modules
const { initDatabase, ensureAdminUser, closeDatabase } = require('./database-pg');
const routes = require('./routes-pg');

// Create Express app
const app = express();

// ============================================
// CONFIGURATION
// ============================================

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Helmet - Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      mediaSrc: ["'self'", "blob:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS - Allow requests from any origin (for development and deployment)
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://z3209oq5lzt4.space.minimax.io'
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all origins in development
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle OPTIONS preflight requests
app.options('*', cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    success: false,
    error: 'Too many requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);

// ============================================
// BODY PARSING & COOKIES
// ============================================

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ============================================
// STATIC FILES
// ============================================

// Serve uploads directory
app.use('/uploads', express.static(path.join(__dirname, '..', 'public', 'uploads')));

// Serve PWA static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// ============================================
// API ROUTES
// ============================================

app.use('/api', routes);

// ============================================
// PWA ROUTES
// ============================================

// Serve manifest.json
app.get('/manifest.json', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'manifest.json'));
});

// Serve service worker
app.get('/sw.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'sw.js'));
});

// ============================================
// SPA ROUTE - Serve index.html for all non-API routes
// ============================================

app.get('*', (req, res, next) => {
  // Skip API routes and static files
  if (req.path.startsWith('/api') || 
      req.path.startsWith('/uploads') ||
      req.path === '/manifest.json' ||
      req.path === '/sw.js' ||
      req.path === '/favicon.ico') {
    return next();
  }
  
  // Serve the main HTML file
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  
  // Don't leak error details in production
  const message = NODE_ENV === 'production' 
    ? 'An error occurred. Please try again.' 
    : err.message;
  
  res.status(err.status || 500).json({
    success: false,
    error: message
  });
});

// ============================================
// SERVER STARTUP
// ============================================

function startServer() {
  try {
    // Initialize database
    initDatabase();
    
    // Create default admin if needed
    ensureAdminUser('admin', 'admin123');
    
    // Start server
    app.listen(PORT, () => {
      console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🏠 Family Connect - Private Family Chat                ║
║                                                          ║
║   Server running at:                                     ║
║   http://localhost:${PORT}                                   ║
║                                                          ║
║   Default Admin Credentials:                             ║
║   Username: admin                                        ║
║   Password: admin123                                     ║
║                                                          ║
║   ⚠️  Change the admin password after first login!       ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
      `);
    });
    
    // Graceful shutdown
    process.on('SIGINT', () => {
      console.log('\n🛑 Shutting down gracefully...');
      closeDatabase();
      process.exit(0);
    });
    
    process.on('SIGTERM', () => {
      console.log('\n🛑 Shutting down gracefully...');
      closeDatabase();
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();
