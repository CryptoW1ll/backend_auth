using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;


namespace backend_auth.Controllers
{
    [ApiController]
    [Route("api/kick")]
    public class KickWebhookController : ControllerBase
    {

        private static readonly string ClientSecret = Environment.GetEnvironmentVariable("KICK_CLIENT_SECRET") ?? "";

        // Simple logger for demonstration (replace with ILogger in production)
        private void Log(string message)
        {
            Console.WriteLine($"[KickWebhookController] {DateTime.UtcNow:O} {message}");
        }

        [HttpPost("webhook")]
        public IActionResult Webhook([FromBody] JsonElement body)
        {
            var expectedSecret = ClientSecret;
            var authHeader = Request.Headers["Authorization"].FirstOrDefault();

            if (string.IsNullOrEmpty(expectedSecret) || authHeader != $"Bearer {expectedSecret}")
            {
                Log("[Webhook] Unauthorized webhook request.");
                return Unauthorized();
            }

            // Handle verification challenge
            if (body.TryGetProperty("challenge", out var challenge))
            {
                Log("[Webhook] Responding to verification challenge.");
                return Ok(new { challenge = challenge.GetString() });
            }

            // Handle the webhook event as before
            Log($"[Webhook] Received event: {body}");
            return Ok();
        }
    }


}