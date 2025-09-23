const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// In-memory storage for development (use Redis/Database in production)
const pkceStorage = new Map();

// Utility functions
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function isValidState(state) {
  return state && typeof state === 'string' && state.length >= 8;
}

function isValidCodeVerifier(verifier) {
  return verifier && typeof verifier === 'string' && verifier.length >= 43;
}

// POST /api/auth/kick/store-pkce
// Stores PKCE data securely for OAuth flow
router.post('/kick/store-pkce', (req, res) => {
  try {
    const { state, codeVerifier, timestamp } = req.body;

    // Validation
    if (!isValidState(state)) {
      return res.status(400).json({
        error: 'invalid_state',
        message: 'State parameter is required and must be at least 8 characters'
      });
    }

    if (!isValidCodeVerifier(codeVerifier)) {
      return res.status(400).json({
        error: 'invalid_code_verifier',
        message: 'Code verifier is required and must be at least 43 characters'
      });
    }

    // Generate or use existing session ID
    const sessionId = req.session.id || generateSessionId();
    const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes from now

    // Store PKCE data (expires in 10 minutes)
    const pkceData = {
      state,
      codeVerifier,
      timestamp: timestamp || Date.now(),
      expiresAt,
      sessionId
    };

    // Store in memory (use Redis/Database for production)
    pkceStorage.set(sessionId, pkceData);

    // Set session data
    req.session.oauthSessionId = sessionId;
    req.session.oauthState = state;

    console.log(`✅ Stored PKCE data for session: ${sessionId}`);

    res.json({ 
      success: true, 
      sessionId: sessionId,
      expiresIn: 600 // 10 minutes
    });

  } catch (error) {
    console.error('Error storing PKCE data:', error);
    res.status(500).json({
      error: 'storage_error',
      message: 'Failed to store PKCE data'
    });
  }
});

// POST /api/auth/kick/exchange
// Exchanges authorization code for access tokens
router.post('/kick/exchange', async (req, res) => {
  try {
    const { code, redirect_uri } = req.body;

    // Validation
    if (!code || !redirect_uri) {
      return res.status(400).json({
        error: 'missing_parameters',
        message: 'Code and redirect_uri are required'
      });
    }

    // Get session data
    const sessionId = req.session.oauthSessionId;
    if (!sessionId) {
      return res.status(400).json({
        error: 'no_session',
        message: 'No OAuth session found'
      });
    }

    // Retrieve stored PKCE data
    const pkceData = pkceStorage.get(sessionId);
    if (!pkceData) {
      return res.status(400).json({
        error: 'no_pkce_data',
        message: 'No PKCE data found for session'
      });
    }

    // Check expiration
    if (Date.now() > pkceData.expiresAt) {
      pkceStorage.delete(sessionId);
      return res.status(400).json({
        error: 'pkce_expired',
        message: 'PKCE data has expired'
      });
    }

    // Server-side OAuth credentials
    const CLIENT_ID = process.env.KICK_CLIENT_ID;
    const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;

    if (!CLIENT_ID || !CLIENT_SECRET) {
      console.error('❌ Missing Kick OAuth credentials in server environment');
      return res.status(500).json({
        error: 'server_configuration',
        message: 'OAuth not properly configured on server'
      });
    }

    console.log(`🔄 Exchanging code for tokens (session: ${sessionId})`);

    // Exchange code for tokens with Kick
    const tokenResponse = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET, // 🔐 Safe on server-side
        redirect_uri: redirect_uri,
        code_verifier: pkceData.codeVerifier,
        code: code,
      }),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      console.error('❌ Kick token exchange failed:', errorData);
      
      return res.status(400).json({
        error: errorData.error || 'token_exchange_failed',
        message: errorData.error_description || 'Failed to exchange code for tokens'
      });
    }

    const tokens = await tokenResponse.json();
    console.log(`✅ Successfully obtained tokens for session: ${sessionId}`);

    // Clean up PKCE data
    pkceStorage.delete(sessionId);

    // Store tokens in session (or database for persistence)
    req.session.kickTokens = {
      access_token: tokens.access_token,
      expires_at: Date.now() + (tokens.expires_in * 1000),
      scope: tokens.scope
      // Note: refresh_token stored securely server-side only
    };

    // Return success response (don't expose refresh token)
    res.json({
      success: true,
      access_token: tokens.access_token,
      expires_in: tokens.expires_in,
      scope: tokens.scope,
      token_type: tokens.token_type || 'Bearer'
    });

  } catch (error) {
    console.error('❌ Error in token exchange:', error);
    res.status(500).json({
      error: 'internal_error',
      message: 'Token exchange failed'
    });
  }
});

// GET /api/auth/kick/status
// Check current authentication status
router.get('/kick/status', (req, res) => {
  const tokens = req.session.kickTokens;
  
  if (!tokens || !tokens.access_token) {
    return res.json({ authenticated: false });
  }

  // Check if token is expired
  const isExpired = Date.now() > tokens.expires_at;
  
  res.json({
    authenticated: !isExpired,
    expires_at: tokens.expires_at,
    scope: tokens.scope,
    expired: isExpired
  });
});

// DELETE /api/auth/kick/logout
// Clear authentication tokens
router.delete('/kick/logout', (req, res) => {
  if (req.session.kickTokens) {
    delete req.session.kickTokens;
    console.log('🚪 User logged out');
  }

  res.json({ success: true, message: 'Logged out successfully' });
});

// Clean up expired PKCE data periodically (development only)
if (process.env.NODE_ENV !== 'production') {
  setInterval(() => {
    const now = Date.now();
    for (const [sessionId, data] of pkceStorage.entries()) {
      if (now > data.expiresAt) {
        pkceStorage.delete(sessionId);
        console.log(`🧹 Cleaned up expired PKCE data for session: ${sessionId}`);
      }
    }
  }, 60000); // Clean every minute
}

module.exports = router;