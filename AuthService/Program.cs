// auth-service/Program.cs
using QRCoder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Serilog;
using System.Text;
using AuthService.Data;
var builder = WebApplication.CreateBuilder(args);

// ---------------- LOGGING ----------------
builder.Host.UseSerilog((ctx, lc) =>
    lc.WriteTo.Console());

// ---------------- DATABASE ----------------
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite("Data Source=auth.db"));

// ---------------- IDENTITY ----------------

builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// ---------------- JWT ----------------
var jwtKey = builder.Configuration["Jwt:Key"] 
             ?? "dev_secret_key_very_long_string_for_hs256_algorithm";


builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
            )
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.EnsureCreated();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

    var email = "user@email.com";
    var password = "Password@123";

    var user = await userManager.FindByEmailAsync(email);
    if (user == null)
    {
        user = new IdentityUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            Console.WriteLine("❌ Failed to create seed user");
            foreach (var e in result.Errors)
                Console.WriteLine(e.Description);
        }
        else
        {
            Console.WriteLine("✅ Seed user created");
        }
    }
}

app.UseAuthentication();
app.UseAuthorization();

// ---------------- AUTH ENDPOINT ----------------
app.MapPost("/auth/login", async (
    LoginRequest request,
    UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByEmailAsync(request.Email);
    
    Console.WriteLine(
    user == null
        ? "❌ User NOT found in DB"
        : $"✅ User found: {user.Email}");

    if (user is null)
        return Results.Unauthorized();
    
    
    if (!await userManager.CheckPasswordAsync(user, request.Password))
        return Results.Unauthorized();

    // MFA / OTP
    if (await userManager.GetTwoFactorEnabledAsync(user))
    {
        if (string.IsNullOrEmpty(request.Otp))
            return Results.BadRequest("OTP required");

        var validOtp =
            await userManager.VerifyTwoFactorTokenAsync(
                user,
                TokenOptions.DefaultAuthenticatorProvider,
                request.Otp);

        if (!validOtp)
            return Results.Unauthorized();
    }

    var token = JwtTokenGenerator.Generate(user.Email, jwtKey);
    return Results.Ok(new { token });
});

app.MapPost("/auth/mfa/setup", async (
    UserManager<IdentityUser> userManager,
    HttpContext http) =>
{
    // 🔐 Identify user from JWT
    var email = http.User.Claims
        .FirstOrDefault(c => c.Type.Contains("email"))?.Value;

    if (email is null)
        return Results.Unauthorized();

    var user = await userManager.FindByEmailAsync(email);
    if (user is null)
        return Results.Unauthorized();

    // Generate MFA secret
    var key = await userManager.GetAuthenticatorKeyAsync(user);
    if (string.IsNullOrEmpty(key))
        await userManager.ResetAuthenticatorKeyAsync(user);

    key = await userManager.GetAuthenticatorKeyAsync(user);

    var otpUri =
        $"otpauth://totp/ContainerizedApp:{email}" +
        $"?secret={key}&issuer=ContainerizedApp";

    // Generate QR code
    var qrGenerator = new QRCodeGenerator();
    var qrData = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
    var qrCode = new PngByteQRCode(qrData);
    var qrBytes = qrCode.GetGraphic(20);

    return Results.Ok(new
    {
        sharedKey = key,
        qrCode = Convert.ToBase64String(qrBytes)
    });
})
.RequireAuthorization();

app.MapPost("/auth/mfa/verify", async (
    VerifyMfaRequest request,
    UserManager<IdentityUser> userManager,
    HttpContext http) =>
{
    var email = http.User.Claims
        .FirstOrDefault(c => c.Type.Contains("email"))?.Value;

    if (email is null)
        return Results.Unauthorized();

    var user = await userManager.FindByEmailAsync(email);
    if (user is null)
        return Results.Unauthorized();

    var isValid = await userManager.VerifyTwoFactorTokenAsync(
        user,
        TokenOptions.DefaultAuthenticatorProvider,
        request.Code);

    if (!isValid)
        return Results.BadRequest("Invalid OTP");

    await userManager.SetTwoFactorEnabledAsync(user, true);

    return Results.Ok("MFA enabled");
})
.RequireAuthorization();

app.Run();

// ---------------- MODELS ----------------
record LoginRequest(string Email, string Password, string? Otp);
record VerifyMfaRequest(string Code);

