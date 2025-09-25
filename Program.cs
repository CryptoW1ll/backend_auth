var builder = WebApplication.CreateBuilder(args);

// Register IHttpClientFactory for controllers that need it
builder.Services.AddHttpClient();

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// CORS configuration
var allowedOrigins = new[]
{
    "http://localhost:5173",
    "https://echelonstudio.co.nz"
};
var frontendUrl = builder.Configuration["FRONTEND_URL"];
if (!string.IsNullOrEmpty(frontendUrl))
{
    allowedOrigins = allowedOrigins.Append(frontendUrl).ToArray();
}
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// Session configuration
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "kick.oauth.session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? Microsoft.AspNetCore.Http.CookieSecurePolicy.None
        : Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = builder.Environment.IsDevelopment()
        ? Microsoft.AspNetCore.Http.SameSiteMode.Lax
        : Microsoft.AspNetCore.Http.SameSiteMode.None;
    options.IdleTimeout = TimeSpan.FromDays(1);
});


var app = builder.Build();



// Enable Swagger UI in all environments
app.UseSwagger();
app.UseSwaggerUI();

app.UseCors();
app.UseSession();


app.MapControllers();

app.UseHttpsRedirection();

// Health check endpoint
app.MapGet("/health", (HttpContext context) =>
{
    // Force session to be created by writing a value
    context.Session.SetString("health_check", "ok");

    return Results.Json(new
    {
        status = "ok",
        timestamp = DateTime.UtcNow.ToString("o"),
        session = context.Session.IsAvailable
    });
});

// Error handling middleware
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
        var response = new
        {
            error = "internal_error",
            message = app.Environment.IsDevelopment() ? error?.Message : "Internal server error"
        };
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(response);
    });
});

// 404 handler
app.Use(async (context, next) =>
{
    await next();
    if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            error = "not_found",
            message = "Endpoint not found"
        });
    }
});

app.Run();
