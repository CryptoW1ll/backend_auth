using Microsoft.AspNetCore.Mvc;

namespace kickapi.Controllers.Auth
{
    [ApiController]
    [Route("api/auth/kick")]
    public class KickStatusController : ControllerBase
    {
        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            // Try to get tokens from session
            var tokens = HttpContext.Session.GetString("kickTokens");
            if (string.IsNullOrEmpty(tokens))
            {
                return Ok(new { authenticated = false });
            }

            // Parse tokens JSON (assuming it is stored as JSON string)
            dynamic? tokenObj = null;
            try
            {
                tokenObj = System.Text.Json.JsonSerializer.Deserialize<dynamic>(tokens);
            }
            catch
            {
                return Ok(new { authenticated = false });
            }

            if (tokenObj == null || tokenObj["access_token"] == null)
            {
                return Ok(new { authenticated = false });
            }

            long expiresAt = 0;
            try
            {
                expiresAt = (long)tokenObj["expires_at"];
            }
            catch
            {
                return Ok(new { authenticated = false });
            }

            bool isExpired = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > expiresAt;

            return Ok(new
            {
                authenticated = !isExpired,
                expires_at = expiresAt,
                scope = tokenObj["scope"],
                expired = isExpired
            });
        }
    }
}
