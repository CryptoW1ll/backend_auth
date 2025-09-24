const express = require('express');
const cors = require('cors');
const session = require('express-session');
// const RedisStore = require('connect-redis').default;
// const { createClient } = require('redis');
require('dotenv').config();

const authRoutes = require('./auth');

const app = express();
const PORT = process.env.PORT || 3001;

// Redis client for session storage (DISABLED)
// let redisClient;
// if (process.env.REDIS_URL) {
//   redisClient = createClient({ url: process.env.REDIS_URL });
//   redisClient.connect().catch(console.error);
// }

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'https://id.kick.com/oauth/authorize',
];

// Add additional origins from environment variable if set
if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

// app.use(cors({
//   origin: function (origin, callback) {
//     // Allow requests with no origin (like mobile apps or curl requests)
//     if (!origin) return callback(null, true);
    
//     if (allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
// }));

app.use(cors({
  origin: function (origin, callback) {
    callback(null, true); // allow all for testing, restrict in prod
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Session configuration
const sessionConfig = {
  name: 'kick.oauth.session',
  secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this',
  resave: false,
  saveUninitialized: true, // saveUninitialized: true (not recommended for all cases), or make sure you set something on req.session before responding.
  cookie: {
    secure: true, // Set to true if using HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24,
    sameSite: 'none' // Required for cross-site cookies (OAuth, third-party clients)
  }
};



// Always use in-memory session store
if (process.env.NODE_ENV === 'production') {
  console.warn('⚠️  WARNING: Using in-memory session store in production. This is NOT recommended. Sessions will be lost on server restart and do not scale.');
}

app.use(session(sessionConfig));

// Log when a session is created
app.use((req, res, next) => {
  // console.log('Origin:', req.headers.origin);
  // console.log('Cookies:', req.headers.cookie);
  if (req.session && req.session.id && req.session.isNew) 
  {
    console.log(`🆕 New session created: ${req.session.id}`);
  }
  // console.log('Session data:', req.session);
  // console.log('Session ID:', req.sessionID);
  // console.log('Is new session:', req.session.isNew);
  next();
});


// Add this right after your session middleware
// app.use((req, res, next) => {
//   console.log('=== SESSION DEBUG ===');
//   console.log('Session ID:', req.sessionID);
//   console.log('Session exists:', !!req.session);
//   console.log('Cookies received:', req.headers.cookie || 'None');
//   console.log('====================');
//   next();
// });

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    session: !!req.session,
    redis: !!redisClient
  });
});

// Auth routes
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({
    error: 'internal_error',
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : error.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'not_found',
    message: 'Endpoint not found'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Kick OAuth Backend running on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth endpoints: http://localhost:${PORT}/api/auth/*`);
  
  if (process.env.NODE_ENV === 'production') {
    console.log('🛡️  Running in PRODUCTION mode');
  } else {
    console.log('🔧 Running in DEVELOPMENT mode');
  }
});

