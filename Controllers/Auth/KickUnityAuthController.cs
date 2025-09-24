
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Collections.Generic;
using KickLib.Auth;
using System.Text.Json;

namespace kickapi.Controllers.Auth
{
    [ApiController]
    [Route("api/auth/kick")]
    public class KickUnityAuthController : ControllerBase
    {
        // In-memory session store: sessionId -> session data
        private static ConcurrentDictionary<string, SessionData> sessionStore = new();
        private const string SessionCookieName = "kick_session_id";
        private const string ClientId = "01K5QJW9QDC6TJS4DB55KQ5CPP";
        private const string ClientSecret = ""; // Set this securely in production
        private const string RedirectUri = "https://backend-auth-z6z0.onrender.com/api/auth/kick/callback";
        private static readonly List<string> DefaultScopes = new() { "user:read", "chat:write" };

        private class SessionData
        {
            public string? CodeVerifier { get; set; }
            public string? State { get; set; }
            public string? AccessToken { get; set; }
            public string? RefreshToken { get; set; }
            public string? Scope { get; set; }
            public long? ExpiresAt { get; set; }
            public string? AuthCode { get; set; }
        }

        // 1. Unity requests the OAuth URL
        [HttpGet("auth")]
        public IActionResult GetAuthUrl()
        {
            string sessionId = Guid.NewGuid().ToString();
            string state = Guid.NewGuid().ToString("N");
            var authGenerator = new KickOAuthGenerator();
            var url = authGenerator.GetAuthorizationUri(
                RedirectUri,
                ClientId,
                DefaultScopes,
                out var codeVerifier,
                state
            );
            sessionStore[sessionId] = new SessionData { CodeVerifier = codeVerifier, State = state };
            Response.Cookies.Append(SessionCookieName, sessionId, new CookieOptions { HttpOnly = false, SameSite = SameSiteMode.Lax });
            return Ok(new { authorizationUrl = url.ToString(), state });
        }

        // 2. Kick redirects here after user authenticates
        [HttpGet("callback")]
        public async Task<IActionResult> OAuthCallback([FromQuery] string code, [FromQuery] string state)
        {
            if (!Request.Cookies.TryGetValue(SessionCookieName, out var sessionId))
                return BadRequest("Missing session cookie");
            if (!sessionStore.TryGetValue(sessionId, out var session) || session == null)
                return BadRequest("Session not found");
            if (session.State != state)
                return BadRequest("Invalid state");
            session.AuthCode = code;
            // Exchange code for tokens using PKCE
            var authGenerator = new KickOAuthGenerator();
            var result = await authGenerator.ExchangeCodeForTokenAsync(
                code,
                ClientId,
                ClientSecret,
                RedirectUri,
                state,
                session.CodeVerifier
            );
            if (result.IsSuccess && result.Value != null)
            {
                session.AccessToken = result.Value.AccessToken;
                session.RefreshToken = result.Value.RefreshToken;
                session.Scope = result.Value.Scope;
                session.ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (result.Value.ExpiresIn * 1000);
            }
            // Optionally, redirect to a success page
            return Content("<h2>Kick authentication complete. You may return to Unity.</h2>", "text/html");
        }

        // 3. Unity polls for result
        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            if (!Request.Cookies.TryGetValue(SessionCookieName, out var sessionId))
                return Unauthorized();
            if (!sessionStore.TryGetValue(sessionId, out var session) || session == null)
                return Unauthorized();
            if (!string.IsNullOrEmpty(session.AccessToken))
            {
                return Ok(new
                {
                    status = "complete",
                    access_token = session.AccessToken,
                    refresh_token = session.RefreshToken,
                    expires_at = session.ExpiresAt,
                    scope = session.Scope
                });
            }
            if (!string.IsNullOrEmpty(session.AuthCode))
            {
                return Ok(new { status = "auth_code", code = session.AuthCode });
            }
            return Ok(new { status = "pending" });
        }
    }
}
