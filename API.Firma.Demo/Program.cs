using System.Globalization;
using System.Diagnostics;
using Microsoft.AspNetCore.Localization;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = true;
    options.SingleLine = true;
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
});
builder.Logging.AddDebug();

if (builder.Environment.IsDevelopment())
{
    var apiDevelopmentSettings = Path.GetFullPath(
        Path.Combine(
            builder.Environment.ContentRootPath,
            "..",
            "appsettings.Development.json"));
    builder.Configuration.AddJsonFile(
        apiDevelopmentSettings,
        optional: false,
        reloadOnChange: true);
    builder.Configuration.AddUserSecrets(
        "API-Firma-Numerica-Software-2026");
    builder.Configuration.AddEnvironmentVariables();
}

builder.Services.AddRazorPages();
builder.Services.AddHttpClient("FirmaApi", client =>
{
    var baseUrl = builder.Configuration["ApiFirma:BaseUrl"]
        ?? throw new InvalidOperationException("Configure ApiFirma:BaseUrl.");

    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromMinutes(2);
});

var app = builder.Build();
var formCulture = CultureInfo.GetCultureInfo("en-US");

app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new RequestCulture(formCulture),
    SupportedCultures = [formCulture],
    SupportedUICultures = [formCulture]
});

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/css")
        || context.Request.Path.StartsWithSegments("/js")
        || context.Request.Path.StartsWithSegments("/lib")
        || context.Request.Path.StartsWithSegments("/favicon.ico")
        || context.Request.Path.Value?.EndsWith(".css", StringComparison.OrdinalIgnoreCase) == true)
    {
        await next();
        return;
    }

    var logger = context.RequestServices
        .GetRequiredService<ILoggerFactory>()
        .CreateLogger("API.Firma.Demo.Requests");
    var stopwatch = Stopwatch.StartNew();
    context.Response.Headers["X-Request-ID"] = context.TraceIdentifier;
    using var scope = logger.BeginScope(new Dictionary<string, object?>
    {
        ["RequestId"] = context.TraceIdentifier,
        ["Method"] = context.Request.Method,
        ["Path"] = context.Request.Path.Value
    });
    logger.LogInformation(
        "Solicitud Demo iniciada: {Method} {Path}{QueryString}; IP remota {RemoteIp}; Content-Type {ContentType}; Content-Length {ContentLength}; User-Agent {UserAgent}",
        context.Request.Method,
        context.Request.Path,
        context.Request.QueryString,
        context.Connection.RemoteIpAddress,
        context.Request.ContentType ?? "sin tipo",
        context.Request.ContentLength,
        context.Request.Headers.UserAgent.ToString());

    try
    {
        await next();
    }
    catch (Exception exception)
    {
        logger.LogError(
            exception,
            "Solicitud Demo falló tras {ElapsedMs} ms: {ExceptionType}; HResult 0x{HResult:X8}; mensaje {ExceptionMessage}; interna {InnerExceptionType}: {InnerExceptionMessage}",
            stopwatch.ElapsedMilliseconds,
            exception.GetType().FullName,
            exception.HResult,
            exception.Message,
            exception.InnerException?.GetType().FullName ?? "ninguna",
            exception.InnerException?.Message ?? "ninguno");
        throw;
    }
    finally
    {
        logger.LogInformation(
            "Solicitud Demo finalizada: HTTP {StatusCode}; Content-Type {ContentType}; Content-Length {ContentLength}; duración {ElapsedMs} ms",
            context.Response.StatusCode,
            context.Response.ContentType ?? "sin tipo",
            context.Response.ContentLength,
            stopwatch.ElapsedMilliseconds);
    }
});

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
