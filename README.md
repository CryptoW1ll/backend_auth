# Quick Start Guide for Kick OAuth Backend

## 🚀 Getting Started

### 1. Set Up Backend Server

```bash
# Navigate to the backend starter directory
cd backend-starter

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your actual Kick OAuth credentials
```

### 2. Get Kick OAuth Credentials

1. Go to [Kick Developer Portal](https://kick.com/developer/applications)
2. Create a new application
3. Set redirect URI to: `http://localhost:5173/auth` (development)
4. Copy Client ID and Client Secret to your `.env` file

## How to Run

This project no longer uses Firebase Functions. To run the backend server, use:

```bash
node server.js
```

Make sure to set up your environment variables in a `.env` file as needed.

All endpoints are served from `server.js`.


```bash
# Development mode (with auto-reload)
npm run dev

# Or production mode
npm start
```

### 4. Test the Endpoints

```bash
# Health check
curl http://localhost:3001/health

# Test PKCE storage
curl -X POST http://localhost:3001/api/auth/kick/store-pkce \
  -H "Content-Type: application/json" \
  -d '{"state":"test123","codeVerifier":"test_code_verifier_at_least_43_chars_long_12345","timestamp":1234567890}'
```

## 📁 Project Structure

```
backend-starter/
├── server.js              # Main Express server
├── routes/
│   └── auth.js            # OAuth authentication routes  
├── package.json           # Dependencies and scripts
├── .env.example           # Environment variables template
├── .env                   # Your actual environment variables (create this)
└── README.md             # This file
```

## 🔌 API Endpoints

- `GET /health` - Server health check
- `POST /api/auth/kick/store-pkce` - Store PKCE data securely
- `POST /api/auth/kick/exchange` - Exchange auth code for tokens
- `GET /api/auth/kick/status` - Check authentication status  
- `DELETE /api/auth/kick/logout` - Clear authentication

## 🛡️ Production Deployment

### Environment Variables
```bash
NODE_ENV=production
FRONTEND_URL=https://yourdomain.com
SESSION_SECRET=very-long-random-string
REDIS_URL=redis://your-redis-instance
KICK_CLIENT_ID=your_client_id
KICK_CLIENT_SECRET=your_client_secret
```

### Recommended Services
- **Hosting**: Railway, Render, DigitalOcean App Platform
- **Database**: Redis Cloud, AWS ElastiCache  
- **SSL**: Automatically handled by most platforms

### Security Checklist
- [ ] Use HTTPS in production
- [ ] Set strong SESSION_SECRET
- [ ] Use Redis for session storage
- [ ] Enable CORS for your domain only
- [ ] Keep client secret secure on server
- [ ] Set up monitoring and logging

## 🔧 Integration with Frontend

Update your frontend to use these endpoints:

```javascript
// In your React components
const backendURL = process.env.NODE_ENV === 'production' 
  ? 'https://your-backend-domain.com'
  : 'http://localhost:3001';

// Store PKCE data
await fetch(`${backendURL}/api/auth/kick/store-pkce`, {
  method: 'POST',
  credentials: 'include', // Important for cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ state, codeVerifier, timestamp })
});

// Exchange code for tokens
await fetch(`${backendURL}/api/auth/kick/exchange`, {
  method: 'POST', 
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code, redirect_uri })
});
```

## 🆘 Troubleshooting

### Common Issues

1. **CORS Errors**: Make sure FRONTEND_URL matches your React app URL
2. **Session Issues**: Check that credentials are included in fetch requests
3. **Token Exchange Fails**: Verify KICK_CLIENT_SECRET is correct
4. **Redis Connection**: Start Redis server or use memory storage for development

### Debug Mode
```bash
DEBUG=* npm run dev  # Enable all debug logs
```

## 📞 Next Steps

1. **Test locally**: Verify OAuth flow works end-to-end
2. **Deploy backend**: Choose a hosting platform and deploy
3. **Update frontend**: Point to your backend URL
4. **Production testing**: Test with real Kick OAuth flow
5. **Monitoring**: Set up error tracking and logs