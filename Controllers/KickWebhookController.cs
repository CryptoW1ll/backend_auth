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

        // Simple logger for demonstration (replace with ILogger in production)
        private void Log(string message)
        {
            Console.WriteLine($"[KickUnityAuthController] {DateTime.UtcNow:O} {message}");
        }

        // webhook endpoint example
        [HttpPost("webhook")] //
        public IActionResult Webhook([FromBody] WebhookEvent webhookEvent)
        {
            // Handle the webhook event
            Log($"[Webhook] Received event: {JsonSerializer.Serialize(webhookEvent)}");
            return Ok();
        }

        // Minimal WebhookEvent class definition (customize as needed)
        public class WebhookEvent
        {
            public string? Type { get; set; }
            public JsonElement? Data { get; set; }
        }
    }


}