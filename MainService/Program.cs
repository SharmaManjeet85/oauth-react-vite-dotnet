// main-service/Program.cs

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.IdentityModel.Logging;

IdentityModelEventSource.ShowPII = true;


var builder = WebApplication.CreateBuilder(args);

// ---------------- JWT ----------------
var jwtKey = builder.Configuration["Jwt:Key"]
             ?? "dev_secret_key_very_long_string_for_hs256_algorithm";

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer("Bearer", options =>
{
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine("❌ JWT AUTH FAILED");
            Console.WriteLine(ctx.Exception.ToString());
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            Console.WriteLine("✅ JWT VALIDATED");
            return Task.CompletedTask;
        }
    };

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "auth-service",

        ValidateAudience = true,
        ValidAudience = "api-clients",

        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
        ),

        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ---------------- PROTECTED API ----------------
app.MapGet("/data", () =>
{
    return Results.Ok(new { message = "Secure data accessed" });
})
.RequireAuthorization();

app.Run();
