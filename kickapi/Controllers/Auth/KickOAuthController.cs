using KickLib.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace kickapi.Controllers.Auth
{
    [ApiController]
    [Route("api/auth/kick")]
    public class KickOAuthController : ControllerBase
    {

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _redirectUri;

        public KickOAuthController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
            _clientId = Environment.GetEnvironmentVariable("KICK_CLIENT_ID") ?? "";
            _clientSecret = Environment.GetEnvironmentVariable("KICK_CLIENT_SECRET") ?? "";
            _redirectUri = Environment.GetEnvironmentVariable("KICK_REDIRECT_URI") ?? "";
        }


        /// <summary>
        /// Initiates the OAuth flow by generating the Kick authorization URL and PKCE verifier (POST version).
        /// Returns the URL and stores the verifier in session for later use in the callback.
        /// </summary>
        [HttpPost("auth")]
        public IActionResult Auth([FromBody] AuthRequest request)
        {
            try
            {
                var scopes = request?.Scopes ?? new List<string> { "user:read", "chat:write" };
                var redirectUri = string.IsNullOrEmpty(request?.RedirectUri) ? _redirectUri : request.RedirectUri;
                var state = string.IsNullOrEmpty(request?.State) ? null : request.State;
                var authGenerator = new KickOAuthGenerator();
                var url = authGenerator.GetAuthorizationUri(
                    redirectUri,
                    _clientId,
                    scopes,
                    out var verifier,
                    state
                );
                // Store verifier in session for later use in callback
                HttpContext.Session.SetString("kickVerifier", verifier);
                if (!string.IsNullOrEmpty(state))
                    HttpContext.Session.SetString("kickState", state);
                return Ok(new { authorizationUrl = url.ToString(), verifier, state });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "internal_error", message = ex.Message });
            }
        }

        public class AuthRequest
        {
            public List<string>? Scopes { get; set; }
            public string? RedirectUri { get; set; }
            public string? State { get; set; }
        }


        [HttpGet("login")]
        public IActionResult Login()
        {
            // Use KickLib to generate the correct authorization URL and PKCE verifier
            var scopes = new List<string> { "user:read", "chat:write" };
            var authGenerator = new KickOAuthGenerator();
            var url = authGenerator.GetAuthorizationUri(
                _redirectUri,
                _clientId,
                scopes,
                out var verifier
            );
            // Store verifier in session for later use in callback
            HttpContext.Session.SetString("kickVerifier", verifier);
            return Redirect(url.ToString());
        }

        [HttpGet("callback")]
        public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state)
        {
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                return BadRequest("Missing code or state");

            var verifier = HttpContext.Session.GetString("kickVerifier");
            if (string.IsNullOrEmpty(verifier))
                return BadRequest("Missing PKCE verifier in session");

            var authGenerator = new KickOAuthGenerator();
            var exchangeResults = await authGenerator.ExchangeCodeForTokenAsync(
                code,
                _clientId,
                _clientSecret,
                _redirectUri,
                state,
                verifier
            );

            if (!exchangeResults.IsSuccess || exchangeResults.Value == null || string.IsNullOrEmpty(exchangeResults.Value.AccessToken))
                return BadRequest("Failed to get tokens");

            // Store tokens in session
            var tokens = new
            {
                access_token = exchangeResults.Value.AccessToken,
                refresh_token = exchangeResults.Value.RefreshToken,
                expires_at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (exchangeResults.Value.ExpiresIn * 1000),
                scope = exchangeResults.Value.Scope
            };
            HttpContext.Session.SetString("kickTokens", System.Text.Json.JsonSerializer.Serialize(tokens));

            return Ok(new { authenticated = true });
        }
    }
}
