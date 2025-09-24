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

// Generate a random code_verifier (43-128 chars)
function generateCodeVerifier(length = 64) {
  return base64urlEncode(crypto.randomBytes(length));
}

// Generate a code_challenge from code_verifier
function generateCodeChallenge(codeVerifier) {
  return base64urlEncode(crypto.createHash('sha256').update(codeVerifier).digest());
}

// Base64url encode (RFC 7636)
function base64urlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// GET /api/auth/
// Initiates the OAuth flow by redirecting to Kick's authorization endpoint
router.get('/kick/auth', (req, res) => {
  try {
      req.session.touch(); // or set a value: req.session.initiated = true;

    // Use a fixed redirect_uri for Unity client (or get from config if needed)
    const redirect_uri = 'https://backend-auth-z6z0.onrender.com/api/auth/kick/callback';
    const CLIENT_ID = process.env.KICK_CLIENT_ID;
    const AUTH_URL = 'https://id.kick.com/oauth/authorize';

    console.log('--- /kick/auth DEBUG START ---');
    console.log('Session ID:', req.session.id);
    console.log('Session object:', req.session);
    console.log('CLIENT_ID:', CLIENT_ID);
    console.log('AUTH_URL:', AUTH_URL);
    console.log('redirect_uri:', redirect_uri);

    // Validation
    if (!CLIENT_ID) {
      console.error('❌ Missing Kick OAuth Client ID in server environment');
      return res.status(500).json({
        error: 'server_configuration',
        message: 'OAuth not properly configured on server'
      });
    }

    // Generate PKCE code_verifier and code_challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    console.log('Generated codeVerifier:', codeVerifier);
    console.log('Generated codeChallenge:', codeChallenge);

    // Generate and store a random state
    const state = crypto.randomBytes(12).toString('base64url'); // 16 chars, url-safe
    console.log('Generated state:', state);

    // Store PKCE and state in session and memory
    const sessionId = req.session.id || generateSessionId();
    const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes
    const pkceData = {
      state,
      codeVerifier,
      redirect_uri,
      expiresAt,
      sessionId
    };
    pkceStorage.set(sessionId, pkceData);
    req.session.oauthSessionId = sessionId;
    req.session.oauthState = state;
    console.log('Stored pkceData:', pkceData);
    console.log('Session after storing PKCE:', req.session);

    // Construct authorization URL
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: redirect_uri,
      scope: 'user:read', // Adjust scopes as needed
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });
    const authorizationUrl = `${AUTH_URL}?${params.toString()}`;
    console.log('Authorization URL:', authorizationUrl);
    console.log('--- /kick/auth DEBUG END ---');
    res.json({ authorizationUrl });
  } catch (error) {
    console.error('❌ Error in /kick/auth:', error);
    res.status(500).json({
      error: 'internal_error',
      message: 'Failed to initiate OAuth flow'
    });
  }
})

// GET /api/auth/kick/callback
// Handles the OAuth redirect, exchanges code for tokens
router.get('/kick/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const redirect_uri = req.protocol + '://' + req.get('host') + req.originalUrl.split('?')[0];

    // Validation
    if (!code || !state) {
      return res.status(400).json({
        error: 'missing_parameters',
        message: 'Code and state are required'
      });
    }

    // Find PKCE data by session (state is stored in session)
    const sessionId = req.session.oauthSessionId;
    if (!sessionId) {
      return res.status(400).json({
        error: 'no_session',
        message: 'No OAuth session found'
      });
    }
    const pkceData = pkceStorage.get(sessionId);
    if (!pkceData) {
      return res.status(400).json({
        error: 'no_pkce_data',
        message: 'No PKCE data found for session'
      });
    }
    if (pkceData.state !== state) {
      return res.status(400).json({
        error: 'state_mismatch',
        message: 'State does not match session'
      });
    }
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

    // Exchange code for tokens with Kick
    const tokenResponse = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: pkceData.redirect_uri || redirect_uri,
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
    };

    // Respond with success (or redirect to frontend)
    res.json({
      success: true,
      access_token: tokens.access_token,
      expires_in: tokens.expires_in,
      scope: tokens.scope,
      token_type: tokens.token_type || 'Bearer'
    });
  } catch (error) {
    console.error('❌ Error in /kick/callback:', error);
    res.status(500).json({
      error: 'internal_error',
      message: 'Token exchange failed'
    });
  }
});

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
// router.post('/kick/exchange', async (req, res) => {
//   try {
//     const { code, redirect_uri } = req.body;

//     // Validation
//     if (!code || !redirect_uri) {
//       return res.status(400).json({
//         error: 'missing_parameters',
//         message: 'Code and redirect_uri are required'
//       });
//     }

//     // Get session data
//     const sessionId = req.session.oauthSessionId;
//     if (!sessionId) {
//       return res.status(400).json({
//         error: 'no_session',
//         message: 'No OAuth session found'
//       });
//     }

//     // Retrieve stored PKCE data
//     const pkceData = pkceStorage.get(sessionId);
//     if (!pkceData) {
//       return res.status(400).json({
//         error: 'no_pkce_data',
//         message: 'No PKCE data found for session'
//       });
//     }

//     // Check expiration
//     if (Date.now() > pkceData.expiresAt) {
//       pkceStorage.delete(sessionId);
//       return res.status(400).json({
//         error: 'pkce_expired',
//         message: 'PKCE data has expired'
//       });
//     }

//     // Server-side OAuth credentials
//     const CLIENT_ID = process.env.KICK_CLIENT_ID;
//     const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;

//     if (!CLIENT_ID || !CLIENT_SECRET) {
//       console.error('❌ Missing Kick OAuth credentials in server environment');
//       return res.status(500).json({
//         error: 'server_configuration',
//         message: 'OAuth not properly configured on server'
//       });
//     }

//     console.log(`🔄 Exchanging code for tokens (session: ${sessionId})`);

//     // Exchange code for tokens with Kick
//     const tokenResponse = await fetch('https://id.kick.com/oauth/token', {
//       method: 'POST',
//       credentials: 'include', // ← CRITICAL
//       headers: {
//         'Content-Type': 'application/x-www-form-urlencoded',
//       },
//       body: new URLSearchParams({
//         grant_type: 'authorization_code',
//         client_id: CLIENT_ID,
//         client_secret: CLIENT_SECRET, // 🔐 Safe on server-side
//         redirect_uri: redirect_uri,
//         code_verifier: pkceData.codeVerifier,
//         code: code,
//       }),
//     });

//     if (!tokenResponse.ok) {
//       const errorData = await tokenResponse.json().catch(() => ({}));
//       console.error('❌ Kick token exchange failed:', errorData);
      
//       return res.status(400).json({
//         error: errorData.error || 'token_exchange_failed',
//         message: errorData.error_description || 'Failed to exchange code for tokens'
//       });
//     }

//     const tokens = await tokenResponse.json();
//     console.log(`✅ Successfully obtained tokens for session: ${sessionId}`);

//     // Clean up PKCE data
//     pkceStorage.delete(sessionId);

//     // Store tokens in session (or database for persistence)
//     req.session.kickTokens = {
//       access_token: tokens.access_token,
//       expires_at: Date.now() + (tokens.expires_in * 1000),
//       scope: tokens.scope
//       // Note: refresh_token stored securely server-side only
//     };

//     // Return success response (don't expose refresh token)
//     res.json({
//       success: true,
//       access_token: tokens.access_token,
//       expires_in: tokens.expires_in,
//       scope: tokens.scope,
//       token_type: tokens.token_type || 'Bearer'
//     });

//   } catch (error) {
//     console.error('❌ Error in token exchange:', error);
//     res.status(500).json({
//       error: 'internal_error',
//       message: 'Token exchange failed'
//     });
//   }
// });

// GET /api/auth/kick/status

// Check current authentication status
// router.get('/kick/status', (req, res) => {
//   const tokens = req.session.kickTokens;
  
//   if (!tokens || !tokens.access_token) {
//     return res.json({ authenticated: false });
//   }

//   // Check if token is expired
//   const isExpired = Date.now() > tokens.expires_at;
  
//   res.json({
//     authenticated: !isExpired,
//     expires_at: tokens.expires_at,
//     scope: tokens.scope,
//     expired: isExpired
//   });
// });

// DELETE /api/auth/kick/logout
// Clear authentication tokens
// router.delete('/kick/logout', (req, res) => {
//   if (req.session.kickTokens) {
//     delete req.session.kickTokens;
//     console.log('🚪 User logged out');
//   }

//   res.json({ success: true, message: 'Logged out successfully' });
// });

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