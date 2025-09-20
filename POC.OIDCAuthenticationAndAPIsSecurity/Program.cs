#region namespaces

// These two references are manually added here and in the .csproj file. 

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Net.NetworkInformation;

#endregion namespaces

#region builder code. 
var builder = WebApplication.CreateBuilder(args);

// ---- Configure from appsettings or environment ----
var authority = builder.Configuration["Auth:Authority"]; // e.g., https://login.microsoftonline.com/{tenantId}/v2.0
var audience = builder.Configuration["Auth:Audience"];  // e.g., api://{app-client-id} or your API's Application ID URI
var requiredScope = builder.Configuration["Auth:RequiredScope"] ?? "api.read";

// ======= Read config =======
var tenant = builder.Configuration["Auth:Tenant"];                 // contoso
var tenantDomain = builder.Configuration["Auth:TenantWithDomain"];      // contoso.onmicrosoft.com
var signInPolicy = builder.Configuration["Auth:SignInPolicy"];          // B2C_1_signupsignin
var authorityBaseFormat = builder.Configuration["Auth:AuthorityBase"]
                          ?? "https://{0}.b2clogin.com/{1}";
var authorityWithSampleTenant = string.Format(authorityBaseFormat, tenant, $"{tenantDomain}/{signInPolicy}/v2.0");


// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ---- Bearer token validation against OIDC discovery ----
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = authority;   // OIDC discovery endpoint (/.well-known/openid-configuration)
        o.Audience = audience;    // API identifier registered in the IdP
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true
        };
        // Optional: if behind corporate proxies or custom certs, set BackchannelHttpHandler, etc.
    });


// ---- Require a scope (RFC 8693-style) ----
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("ApiScope", policy =>
        policy.RequireAssertion(ctx =>
            ctx.User?.Claims.Any(c => (c.Type == "scope" || c.Type == "scp") &&
                                      c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries) 
                                      
                                      .Contains(requiredScope)) == true));

    opts.AddPolicy("RequireAdminRole", p => p.RequireRole("admin"));
    
    opts.AddPolicy("RequireApiReadScope", p => p.RequireAssertion(ctx =>
        ctx.User.Claims.Any(c =>
            (c.Type == "scope" || c.Type == "scp") &&
            c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("api.read"))));
});


// ---- Swagger with OAuth2 (implicit Device/PKCE flow for testing) ----
// For pure API testing with bearer tokens, you can keep it simple with Bearer like sample #1.
// Below is the Bearer version for brevity; you can also wire full OAuth2 if desired.

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "OIDC Protected API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Paste an access token obtained from your IdP: Bearer {token}"
    });
    c.AddSecurityRequirement(new()
    {
        [new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } }] = Array.Empty<string>()
    });
});

#region AddSwaggerGen() method with B2C, OAuth2 - Authorization Code + PKCE... 
// ---------------------------------------
// ======= Swagger (OAuth2 – Authorization Code + PKCE) =======

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "B2C OIDC PRotected API", Version = "v1" });

    // OAuth2 definition for Swagger UI (Auth Code + PKCE) 
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri(
                    $"https://{tenant}.b2clogin.com/{tenantDomain}/{signInPolicy}/oauth2/v2.0/authorize"),
                TokenUrl = new Uri(
                    $"https://{tenant}.b2clogin.com/{tenantDomain}/{signInPolicy}/oauth2/v2.0/token"),
                Scopes = new Dictionary<string, string>
                {
                    { requiredScope, "API read access" }
                }
            }
        }
    });
});

// ---------------------------------------

#endregion

#endregion builder code.
#region app. 
var app = builder.Build();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


// Unprotected
app.MapGet("/", () => new { service = "OIDC Protected API", timeUtc = DateTime.UtcNow });


// Protected by Bearer token + required scope
app.MapGet("/profile", (HttpContext http) =>
{
    var user = http.User;
    var sub = user.FindFirst("sub")?.Value ?? user.Identity?.Name ?? "unknown";
    var scopes = string.Join(' ', user.FindAll("scope").Select(c => c.Value));
    if (string.IsNullOrWhiteSpace(scopes))
        scopes = string.Join(' ', user.FindAll("scp").Select(c => c.Value));

    return new
    {
        subject = sub,
        scopes,
        claims = user.Claims.Select(c => new { c.Type, c.Value })
    };
})

.RequireAuthorization("ApiScope");

// Protected with role based authorization. 
app.MapGet("/admin/metrics", () => "ok").RequireAuthorization("RequireAdminRole");
app.MapGet("/reports", () => "ok").RequireAuthorization("RequireApiReadScope");

// ----------------------------------

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "OIDC Protected API", Version = "v1" });

// Lets you sign in in Swagger UI and call protected endpoints with the acquired access token.
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri($"{authority}/oauth2/v2.0/authorize"), // adjust per IdP
                TokenUrl = new Uri($"{authority}/oauth2/v2.0/token"),             // adjust per IdP
                Scopes = new Dictionary<string, string> { { requiredScope, "API read access" } }
            }
        }
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            { Type = ReferenceType.SecurityScheme, Id = "oauth2" }
        }] = new[] { requiredScope }
    });
});

app.UseSwaggerUI(o =>
{
    o.OAuthClientId(builder.Configuration["SwaggerOAuth:ClientId"]);   // public SPA/PKCE client
    o.OAuthUsePkce();
    o.OAuthScopeSeparator(" ");
});

// ----------------------------------

app.UseHttpsRedirection();
app.MapControllers();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

#endregion app. 




