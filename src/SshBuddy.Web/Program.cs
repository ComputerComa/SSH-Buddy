using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using SshBuddy.Web.Components;
using SshBuddy.Web.Endpoints;
using SshBuddy.Web.Services;

if (Cli.IsCommand(args))
    return await Cli.RunAsync(args);

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var requireHttps = config.GetValue("Security:RequireHttps", !builder.Environment.IsDevelopment());

builder.Services.AddSshBuddyCore(config, builder.Environment);
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();

// Everything is private unless an endpoint or page opts out with [AllowAnonymous].
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

// Only trust X-Forwarded-* from the reverse proxy configured in ReverseProxy:KnownProxies / KnownNetworks.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    foreach (var p in config.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [])
        o.KnownProxies.Add(IPAddress.Parse(p));
    foreach (var n in config.GetSection("ReverseProxy:KnownNetworks").Get<string[]>() ?? [])
    {
        var parts = n.Split('/');
        o.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse(parts[0]), int.Parse(parts[1])));
    }
});

builder.Services.AddHttpsRedirection(o => o.HttpsPort = 443);

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    RateLimitPartition<string> ByIp(HttpContext ctx, int limit) =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
    // Backstop for /api/machines/*: random bearer values each get their own per-credential bucket below, so an
    // unauthenticated flood needs a per-address ceiling too. Generous, because many machines can share one NAT address.
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        ctx.Request.Path.StartsWithSegments("/api/machines")
            ? RateLimitPartition.GetFixedWindowLimiter("machines-ip:" + ctx.Connection.RemoteIpAddress,
                _ => new FixedWindowRateLimiterOptions { PermitLimit = config.GetValue("RateLimits:MachineApiPerIpPerMinute", 600), Window = TimeSpan.FromMinutes(1), QueueLimit = 0 })
            : RateLimitPartition.GetNoLimiter("none"));
    o.AddPolicy("login", ctx => ByIp(ctx, config.GetValue("RateLimits:LoginPerMinute", 5)));
    o.AddPolicy("enroll", ctx => ByIp(ctx, config.GetValue("RateLimits:EnrollPerMinute", 10)));
    o.AddPolicy("machine-enroll", ctx => ByIp(ctx, config.GetValue("RateLimits:MachineEnrollPerMinute", 60)));
    // Check-ins are limited per credential, not per IP: a proxy that hides client addresses would otherwise
    // put the whole fleet in one bucket and make healthy machines look stale.
    o.AddPolicy("checkin", ctx =>
    {
        var bearer = ctx.Request.Headers.Authorization.ToString();
        var key = bearer.Length > 0 ? "c:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(bearer))) : "ip:" + ctx.Connection.RemoteIpAddress;
        return RateLimitPartition.GetFixedWindowLimiter(key,
            _ => new FixedWindowRateLimiterOptions { PermitLimit = config.GetValue("RateLimits:CheckInPerMinute", 20), Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
    });
});

var app = builder.Build();

app.UseForwardedHeaders();

// Browser navigations get the branded pages; everything else (API calls, form posts) gets problem+json.
// Re-executing a POST into a Razor page would fail antiforgery, and API clients must never receive HTML.
static bool IsBrowserNavigation(HttpContext ctx) =>
    HttpMethods.IsGet(ctx.Request.Method) && !ctx.Request.Path.StartsWithSegments("/api");

if (!app.Environment.IsDevelopment())
{
    app.UseWhen(IsBrowserNavigation, b => b.UseExceptionHandler("/Error", createScopeForErrors: true));
    app.UseWhen(ctx => !IsBrowserNavigation(ctx), b => b.UseExceptionHandler(e => e.Run(ctx =>
    {
        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        return Results.Problem(statusCode: StatusCodes.Status500InternalServerError).ExecuteAsync(ctx);
    })));
    app.UseHsts();
}

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

if (requireHttps)
{
    // Never redirect API calls: a redirected POST would already have sent the token in clear text.
    app.Use(async (ctx, next) =>
    {
        if (!ctx.Request.IsHttps && ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { title = "HTTPS is required." });
            return;
        }
        await next();
    });
    app.UseHttpsRedirection();
}

// Same split for bare status codes: a 429 on a login POST must stay a 429, not a re-executed Razor POST.
app.UseWhen(IsBrowserNavigation,
    branch => branch.UseStatusCodePagesWithReExecute("/status/{0}", createScopeForStatusCodePages: true));

app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets().AllowAnonymous();
app.MapSshBuddyEndpoints();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
return 0;

public partial class Program;
