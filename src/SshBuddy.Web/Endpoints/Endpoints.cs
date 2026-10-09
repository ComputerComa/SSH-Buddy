using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using SshBuddy.Web.Services;

namespace SshBuddy.Web.Endpoints;

public static class Endpoints
{
    public static void MapSshBuddyEndpoints(this WebApplication app)
    {
        // Public keys are not secrets: anonymous read, so unattended hosts need no credentials.
        app.MapMethods("/api/authorized-keys", ["GET", "HEAD"], async (HttpContext ctx, AuthorizedKeysService svc, CancellationToken ct) =>
        {
            var doc = await svc.GetAsync(ct);
            ctx.Response.Headers.ETag = doc.ETag;
            ctx.Response.Headers.CacheControl = "no-cache";
            if (MatchesIfNoneMatch(ctx.Request, doc.ETag))
                return Results.StatusCode(StatusCodes.Status304NotModified);
            return Results.Text(doc.Body, "text/plain; charset=utf-8");
        }).AllowAnonymous();

        // Authorised by the single-use token, not by a cookie, so antiforgery does not apply.
        app.MapPost("/api/keys/enroll", async (HttpContext ctx, EnrollmentService svc, ILogger<EnrollmentService> log, CancellationToken ct) =>
        {
            const int MaxBody = 16 * 1024;
            if (!ctx.Request.HasFormContentType)
                return Results.Problem(statusCode: StatusCodes.Status415UnsupportedMediaType, detail: "Send application/x-www-form-urlencoded or multipart form data.");
            if (ctx.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } f)
                f.MaxRequestBodySize = MaxBody;

            IFormCollection form;
            try { form = await ctx.Request.ReadFormAsync(ct); }
            catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException or IOException)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: "Malformed or oversized form.");
            }

            var result = await svc.EnrollAsync(BearerToken(ctx.Request), form["label"], form["publicKey"], ct);
            switch (result.Status)
            {
                case EnrollStatus.Enrolled:
                    return Results.Json(
                        new { id = result.Key!.Id, algorithm = result.Key.Algorithm, fingerprint = result.Key.Fingerprint },
                        statusCode: StatusCodes.Status201Created);
                case EnrollStatus.InvalidToken:
                    log.LogWarning("Enrollment rejected: invalid, expired or used token.");
                    ctx.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, detail: "Invalid, expired or already used enrollment token.");
                case EnrollStatus.Duplicate:
                    return Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: result.Error);
                default:
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: result.Error);
            }
        }).AllowAnonymous().DisableAntiforgery().RequireRateLimiting("enroll");

        MapMachineEndpoints(app);

        // Login/logout are plain form posts; minimal-API form binding validates the antiforgery token.
        app.MapPost("/account/login", async (
            [FromForm] LoginForm form,
            SignInManager<IdentityUser> signIn) =>
        {
            var result = await signIn.PasswordSignInAsync(form.Email ?? "", form.Password ?? "", isPersistent: false, lockoutOnFailure: true);
            if (result.Succeeded)
                return Results.LocalRedirect(IsLocal(form.ReturnUrl) ? form.ReturnUrl! : "/");
            var error = result.IsLockedOut ? "locked" : "invalid";
            return Results.Redirect($"/login?error={error}");
        }).AllowAnonymous().RequireRateLimiting("login");

        app.MapPost("/account/logout", async (SignInManager<IdentityUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.Redirect("/login");
        });
    }

    private static void MapMachineEndpoints(WebApplication app)
    {
        // Authorised by a template credential, which can enroll machines and do nothing else.
        app.MapPost("/api/machines/enroll", async (
            HttpContext ctx, MachineService svc, ILogger<MachineService> log, CancellationToken ct) =>
        {
            var body = await ReadJsonAsync<MachineEnrollRequest>(ctx, ct);
            if (body is null) return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: "A small JSON body is required.");

            var r = await svc.EnrollAsync(BearerToken(ctx.Request), body.Fqdn, body.Nonce, body.AgentVersion, ClientIp(ctx), ct);
            switch (r.Status)
            {
                case EnrollMachineStatus.Issued:
                    return Results.Json(new { fqdn = r.Fqdn, machineCredential = r.MachineCredential }, statusCode: StatusCodes.Status201Created);
                case EnrollMachineStatus.InvalidCredential:
                    log.LogWarning("Machine enrollment rejected: invalid or revoked template credential.");
                    ctx.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, detail: "Invalid or revoked enrollment credential.");
                case EnrollMachineStatus.Conflict:
                    log.LogWarning("Machine enrollment refused for an existing hostname.");
                    return Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: r.Error);
                default:
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: r.Error);
            }
        }).AllowAnonymous().RequireRateLimiting("machine-enroll");

        // Authorised by the per-machine credential issued at enrollment. Idempotent: it only records the latest state.
        app.MapPost("/api/machines/checkin", async (HttpContext ctx, MachineService svc, CancellationToken ct) =>
        {
            var body = await ReadJsonAsync<MachineCheckInRequest>(ctx, ct);
            if (body is null) return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: "A small JSON body is required.");

            var r = await svc.CheckInAsync(BearerToken(ctx.Request),
                new CheckInReport(body.AgentVersion, body.Result, body.Error, body.AppliedEtag), ClientIp(ctx), ct);
            switch (r.Status)
            {
                case CheckInStatus.Ok:
                    return Results.NoContent();
                case CheckInStatus.Unauthorized:
                    ctx.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, detail: "Unknown or revoked machine credential.");
                default:
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, detail: r.Error);
            }
        }).AllowAnonymous().RequireRateLimiting("checkin");

        // The agent binaries and their manifest are public, like the key list: they contain no secrets.
        app.MapGet("/api/agent/manifest", (AgentReleaseService releases) =>
            releases.GetManifest() is { } m
                ? Results.Json(new
                {
                    version = m.Version,
                    binaries = m.Binaries.Select(b => new { os = "linux", arch = b.Platform.Split('-')[1], platform = b.Platform, size = b.Size, sha256 = b.Sha256, path = b.Path }),
                })
                : Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "No complete agent release is published."))
            .AllowAnonymous();

        app.MapGet("/api/agent/manifest.txt", (AgentReleaseService releases) =>
            releases.GetManifest() is { } m
                ? Results.Text(m.ToText(), "text/plain; charset=utf-8")
                : Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "No complete agent release is published."))
            .AllowAnonymous();

        app.MapGet("/api/agent/download/{version}/{platform}", (string version, string platform, AgentReleaseService releases) =>
            releases.Find(version, platform) is { } f
                ? Results.File(f.FilePath, "application/octet-stream", fileDownloadName: $"ssh-buddy-agent-{platform}")
                : Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "Unknown release."))
            .AllowAnonymous();
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpContext ctx, CancellationToken ct) where T : class
    {
        if (ctx.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } f) f.MaxRequestBodySize = 8 * 1024;
        try { return await ctx.Request.ReadFromJsonAsync<T>(ct); }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or BadHttpRequestException or InvalidOperationException) { return null; }
    }

    private static string? ClientIp(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString();

    private static string? BearerToken(HttpRequest req)
    {
        var header = req.Headers.Authorization.ToString();
        const string Prefix = "Bearer ";
        return header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) ? header[Prefix.Length..].Trim() : null;
    }

    private static bool MatchesIfNoneMatch(HttpRequest req, string etag)
    {
        var values = req.GetTypedHeaders().IfNoneMatch;
        return values.Any(v => v.Equals(EntityTagHeaderValue.Any) || v.Compare(new EntityTagHeaderValue(etag), useStrongComparison: false));
    }

    private static bool IsLocal(string? url) =>
        !string.IsNullOrEmpty(url) && url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));
}

public class LoginForm
{
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string? ReturnUrl { get; set; }
}

public record MachineEnrollRequest(string? Fqdn, string? Nonce, string? AgentVersion);

public record MachineCheckInRequest(string? AgentVersion, string? Result, string? Error, string? AppliedEtag);
