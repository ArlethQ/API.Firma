using System.Globalization;
using System.Diagnostics;
using System.Threading.RateLimiting;
using System.Net;
using API.Firma.Models;
using API.Firma.Security;
using API.Firma.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Localization;
using Microsoft.OpenApi;

namespace API.Firma;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        const long maxRequestBytes = 15 * 1024 * 1024;

        builder.Logging.ClearProviders();
        builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
        builder.Logging.AddSimpleConsole(options =>
        {
            options.IncludeScopes = true;
            options.SingleLine = true;
            options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
        });
        builder.Logging.AddDebug();

        builder.Services
            .AddOptions<ApiSecurityOptions>()
            .Bind(builder.Configuration.GetSection(ApiSecurityOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.ApiKey)
                && options.ApiKey.Length >= 32,
                "Configure ApiSecurity:ApiKey con al menos 32 caracteres.")
            .Validate(options => options.AllowedIpAddresses.Count > 0
                && options.AllowedIpAddresses.All(value => IPAddress.TryParse(value, out _)),
                "Configure ApiSecurity:AllowedIpAddresses con al menos una IP válida.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<QrSecurityOptions>()
            .Bind(builder.Configuration.GetSection(QrSecurityOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.SigningKey)
                && options.SigningKey.Length >= 32,
                "Configure QrSecurity:SigningKey con al menos 32 caracteres.")
            .Validate(options => Uri.TryCreate(
                    options.VerificationBaseUrl,
                    UriKind.Absolute,
                    out var uri)
                && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
                "Configure QrSecurity:VerificationBaseUrl con una URL HTTP o HTTPS válida.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<TimestampAuthorityOptions>()
            .Bind(builder.Configuration.GetSection(TimestampAuthorityOptions.SectionName))
            .Validate(options => !options.Enabled
                || (Uri.TryCreate(options.Url, UriKind.Absolute, out var uri)
                    && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)),
                "Configure TimestampAuthority:Url con una URL HTTPS válida.")
            .Validate(options => !options.Enabled
                || options.TimeoutSeconds is >= 5 and <= 120,
                "Configure TimestampAuthority:TimeoutSeconds entre 5 y 120 segundos.")
            .Validate(options => !options.Enabled
                || (!string.IsNullOrWhiteSpace(options.Username)
                    && !string.IsNullOrWhiteSpace(options.Password)),
                "Configure TimestampAuthority:Username y TimestampAuthority:Password para activar TSA.")
            .ValidateOnStart();

        builder.Services.Configure<FormOptions>(options =>
        {
            options.MultipartBodyLengthLimit = maxRequestBytes;
            options.ValueLengthLimit = 16 * 1024;
        });
        builder.WebHost.ConfigureKestrel(options =>
            options.Limits.MaxRequestBodySize = maxRequestBytes);

        builder.Services
            .AddControllers()
            .ConfigureApiBehaviorOptions(options =>
            {
                options.InvalidModelStateResponseFactory = context =>
                    ApiValidationProblemFactory.Create(
                        context.HttpContext,
                        context.ModelState);
            });
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            var xmlDocumentation = Path.Combine(
                AppContext.BaseDirectory,
                $"{typeof(Program).Assembly.GetName().Name}.xml");
            options.IncludeXmlComments(xmlDocumentation);
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "API Firma - Numérica Software",
                Version = "v1",
                Description = "Estampa un código QR y firma digitalmente un PDF en una sola operación."
            });
            options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.ApiKey,
                Name = ApiKeyMiddleware.HeaderName,
                In = ParameterLocation.Header,
                Description = "Ingrese la API key configurada para el entorno."
            });
            options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference("ApiKey", document, null)] = []
            });
        });
        builder.Services.AddProblemDetails();
        builder.Services.AddSingleton<PdfStampService>();
        builder.Services.AddHttpClient<Rfc3161TimestampService>();
        builder.Services.AddSingleton<UanatacaTrustStore>();
        builder.Services.AddSingleton<PdfSignatureValidationService>();
        builder.Services.AddSingleton<QrTokenService>();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, cancellationToken) =>
                await Results.Problem(
                        statusCode: StatusCodes.Status429TooManyRequests,
                        title: "Demasiadas solicitudes",
                        detail: "Se superó el límite de solicitudes permitido. Intente nuevamente más tarde.")
                    .ExecuteAsync(context.HttpContext);
            options.AddPolicy("firma", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Request.Headers[ApiKeyMiddleware.HeaderName].ToString().Trim(),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 20,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    }));
            options.AddPolicy("verificacion", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "desconocida",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 60,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    }));
        });

        var app = builder.Build();
        var formCulture = CultureInfo.GetCultureInfo("en-US");
        var qrConfiguration = app.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<QrSecurityOptions>>()
            .Value;

        if (Uri.TryCreate(
                qrConfiguration.VerificationBaseUrl,
                UriKind.Absolute,
                out var qrVerificationUri)
            && (string.Equals(
                    qrVerificationUri.Host,
                    "localhost",
                    StringComparison.OrdinalIgnoreCase)
                || qrVerificationUri.Host == "127.0.0.1"
                || qrVerificationUri.Host == "::1"))
        {
            app.Logger.LogWarning(
                "QrSecurity:VerificationBaseUrl usa localhost. El QR se podrá leer, "
                + "pero la validación no abrirá desde un teléfono. Configure una IP de red o dominio accesible.");
        }

        app.UseRequestLocalization(new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture(formCulture),
            SupportedCultures = [formCulture],
            SupportedUICultures = [formCulture]
        });

        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/swagger"))
            {
                await next();
                return;
            }

            var logger = context.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("API.Firma.Requests");
            var stopwatch = Stopwatch.StartNew();
            context.Response.Headers["X-Request-ID"] = context.TraceIdentifier;
            using var scope = logger.BeginScope(new Dictionary<string, object?>
            {
                ["RequestId"] = context.TraceIdentifier,
                ["Method"] = context.Request.Method,
                ["Path"] = context.Request.Path.Value
            });
            logger.LogInformation(
                "Solicitud iniciada: {Method} {Path}{QueryString}; protocolo {Protocol}; IP remota {RemoteIp}; Content-Type {ContentType}; Content-Length {ContentLength}; User-Agent {UserAgent}; X-Correlation-ID {CorrelationId}",
                context.Request.Method,
                context.Request.Path,
                context.Request.QueryString,
                context.Request.Protocol,
                context.Connection.RemoteIpAddress,
                context.Request.ContentType ?? "sin tipo",
                context.Request.ContentLength,
                context.Request.Headers.UserAgent.ToString(),
                context.Request.Headers["X-Correlation-ID"].ToString());

            try
            {
                await next();
            }
            catch (Exception exception)
            {
                logger.LogError(
                    exception,
                    "Solicitud falló tras {ElapsedMs} ms. Excepción {ExceptionType}; HResult 0x{HResult:X8}; mensaje {ExceptionMessage}; excepción interna {InnerExceptionType}: {InnerExceptionMessage}",
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
                    "Solicitud finalizada: HTTP {StatusCode}; Content-Type {ResponseContentType}; Content-Length {ResponseContentLength}; duración {ElapsedMs} ms",
                    context.Response.StatusCode,
                    context.Response.ContentType ?? "sin tipo",
                    context.Response.ContentLength,
                    stopwatch.ElapsedMilliseconds);
            }
        });

        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
            app.UseHttpsRedirection();
        }

        app.UseExceptionHandler();
        app.UseMiddleware<IpAllowlistMiddleware>();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(options =>
            {
                options.RoutePrefix = string.Empty;
                options.SwaggerEndpoint("/swagger/v1/swagger.json", "API Firma v1");
                options.DocumentTitle = "API Firma - Numérica Software";
            });
        }

        app.UseMiddleware<ApiKeyMiddleware>();
        app.UseRateLimiter();
        app.MapControllers();
        app.Run();
    }
}
