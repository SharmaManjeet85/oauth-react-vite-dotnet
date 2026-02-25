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
using System.Security.Claims;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
var builder = WebApplication.CreateBuilder(args);

// ---------------- LOGGING ----------------
builder.Host.UseSerilog((ctx, lc) =>
    lc.WriteTo.Console());

// ---------------- DATABASE ----------------
// builder.Services.AddDbContext<AuthDbContext>(options =>
//     options.UseSqlite("Data Source=/app/data/auth.db"));

// Program.cs
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(connectionString));
// ---------------- IDENTITY ----------------

// builder.Services
//     .AddIdentityCore<IdentityUser>()
//     .AddEntityFrameworkStores<AuthDbContext>()
//     .AddDefaultTokenProviders();
builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        options.SignIn.RequireConfirmedEmail = false;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// ---------------- JWT ----------------
var jwtKey = builder.Configuration["Jwt:Key"] 
             ?? "dev_secret_key_very_long_string_for_hs256_algorithm";


builder.Services
    .AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "auth-service",

            ValidateAudience = true,
            ValidAudience = "api-clients",

            ValidateIssuerSigningKey = true,
            IssuerSigningKey =
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(
                        builder.Configuration["Jwt:Key"]!
                    )),

            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    })
    .AddCookie(IdentityConstants.ExternalScheme)
    .AddGoogle("Google", options =>
    {
        options.ClientId = builder.Configuration["Google:ClientId"]!;
        options.ClientSecret = builder.Configuration["Google:ClientSecret"]!;

        // IMPORTANT
        options.CallbackPath = "/signin-google";

        options.SignInScheme = IdentityConstants.ExternalScheme;
    });
builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy
            .WithOrigins("http://localhost:5173")
            .AllowAnyHeader()
            .AllowAnyMethod();
            // .AllowCredentials();
    });
});

builder.Services.AddAuthorization();

var app = builder.Build();
// ... after builder.Build() ...
// Place this after var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<AuthDbContext>();
        
        // This is the critical part: 
        // RelationalDatabaseCreator can force the creation of the physical DB
        var dbCreator = context.GetService<IRelationalDatabaseCreator>();
        
        if (!dbCreator.Exists()) 
        {
            dbCreator.Create();
            Console.WriteLine("Physical Database 'AuthDb' created.");
        }
        
        if (!dbCreator.HasTables()) 
        {
            dbCreator.CreateTables();
            Console.WriteLine("Tables created successfully.");
        }
        
        // Alternative: context.Database.Migrate(); 
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Migration/Creation Error: {ex.Message}");
    }
}
// using (var scope = app.Services.CreateScope())
// {
//     var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
//     db.Database.EnsureCreated();

//     var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

//     var email = "user@email.com";
//     var password = "Password@123";

//     var user = await userManager.FindByEmailAsync(email);
//     if (user == null)
//     {
//         user = new IdentityUser
//         {
//             UserName = email,
//             Email = email,
//             EmailConfirmed = true
//         };

//         var result = await userManager.CreateAsync(user, password);
//         if (!result.Succeeded)
//         {
//             Console.WriteLine("❌ Failed to create seed user");
//             foreach (var e in result.Errors)
//                 Console.WriteLine(e.Description);
//         }
//         else
//         {
//             Console.WriteLine("✅ Seed user created");
//         }
//     }
// }
app.UseCors("Frontend");
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

    // 🔐 MFA ENFORCEMENT
    if (await userManager.GetTwoFactorEnabledAsync(user))
    {
        if (string.IsNullOrEmpty(request.Otp))
            return Results.BadRequest("OTP required");

        var isValidOtp =
            await userManager.VerifyTwoFactorTokenAsync(
                user,
                TokenOptions.DefaultAuthenticatorProvider,
                request.Otp
            );

        if (!isValidOtp)
            return Results.Unauthorized();
    }

    var token = JwtTokenGenerator.Generate(
    user.Id,
    user.Email!,
    builder.Configuration["Jwt:Key"]!
);
    return Results.Ok(new { token });
});

app.MapPost("/auth/mfa/setup", async (
    UserManager<IdentityUser> userManager,
    ClaimsPrincipal user) =>
{
    var identityUser = await userManager.GetUserAsync(user);
    if (identityUser == null)
        return Results.Unauthorized();

    // Reset old key (important)
    await userManager.ResetAuthenticatorKeyAsync(identityUser);

    var key = await userManager.GetAuthenticatorKeyAsync(identityUser);

    var otpUri =
        $"otpauth://totp/ContainerizedApp:{identityUser.Email}" +
        $"?secret={key}&issuer=ContainerizedApp&digits=6";

    return Results.Ok(new
    {
        sharedKey = key,
        otpAuthUri = otpUri
    });
})
.RequireAuthorization();
app.MapPost("/auth/register", async (
        RegisterRequest request,
        UserManager<IdentityUser> userManager
    ) =>
    {
    var existingUser = await userManager.FindByEmailAsync(request.Email);
    if (existingUser != null)
        return Results.BadRequest("User already exists");

    var user = new IdentityUser
    {
        UserName = request.Email,
        Email = request.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, request.Password);

    if (!result.Succeeded)
    {
        return Results.BadRequest(result.Errors.Select(e => e.Description));
    }

    return Results.Ok(new
    {
        message = "User registered successfully"
    });
});
app.MapPost("/auth/mfa/verify", async (
    MfaVerifyRequest request,
    UserManager<IdentityUser> userManager,
    ClaimsPrincipal userPrincipal) =>
{
    var email = userPrincipal.FindFirstValue(ClaimTypes.Email);

    if (email is null)
        return Results.Unauthorized();

    var user = await userManager.FindByEmailAsync(email);
    if (user is null)
        return Results.Unauthorized();

    var isValid = await userManager.VerifyTwoFactorTokenAsync(
        user,
        TokenOptions.DefaultAuthenticatorProvider,
        request.Code
    );

    if (!isValid)
        return Results.Unauthorized();

    await userManager.SetTwoFactorEnabledAsync(user, true);

    return Results.Ok(new { message = "MFA enabled successfully" });
})
.RequireAuthorization();
app.MapGet("/auth/google/login", (
    HttpContext httpContext
) =>
{
    var props = new AuthenticationProperties
    {
        RedirectUri = "/auth/google/callback"
    };

    return Results.Challenge(props, new[] { "Google" });
});
app.MapGet("/auth/google/callback", async (
    HttpContext httpContext,
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager
) =>
{
    var result = await httpContext.AuthenticateAsync(
        IdentityConstants.ExternalScheme
    );

    if (!result.Succeeded)
        return Results.Unauthorized();

    var email =
        result.Principal?.FindFirstValue(ClaimTypes.Email);

    if (email is null)
        return Results.BadRequest("Email not provided by Google");

    var user = await userManager.FindByEmailAsync(email);

    if (user == null)
    {
        user = new IdentityUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true
        };

        await userManager.CreateAsync(user);
    }

    // MFA CHECK
    if (await userManager.GetTwoFactorEnabledAsync(user))
    {
        // redirect UI to OTP screen
        return Results.Redirect(
            $"http://localhost:5173/mfa?email={email}"
        );
    }

    var token = JwtTokenGenerator.Generate(
        user.Id,
        user.Email!,
        builder.Configuration["Jwt:Key"]!
    );

    return Results.Redirect(
        $"http://localhost:5173/oauth-success?token={token}"
    );
});
app.Run();
// ---------------- MODELS ----------------
record LoginRequest(string Email, string Password, string? Otp);
record VerifyMfaRequest(string Otp);
public record MfaVerifyRequest(string Code);
record RegisterRequest(string Email, string Password);