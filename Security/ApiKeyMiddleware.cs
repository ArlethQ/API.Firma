using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace API.Firma.Security;

public sealed class ApiKeyMiddleware(
    RequestDelegate next,
    IOptionsMonitor<ApiSecurityOptions> securityOptions)
{
    public const string HeaderName = "X-API-Key";

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/openapi")
            || context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var suppliedKey = context.Request.Headers[HeaderName].ToString().Trim();
        var expectedKey = securityOptions.CurrentValue.ApiKey.Trim();

        if (!KeysMatch(suppliedKey, expectedKey))
        {
            await Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "No autorizado",
                    detail: $"Envíe una API key válida en el encabezado {HeaderName}.")
                .ExecuteAsync(context);
            return;
        }

        await next(context);
    }

    private static bool KeysMatch(string supplied, string expected)
    {
        if (string.IsNullOrEmpty(supplied) || string.IsNullOrEmpty(expected))
        {
            return false;
        }

        var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        var expectedBytes = Encoding.UTF8.GetBytes(expected);

        return suppliedBytes.Length == expectedBytes.Length
            && CryptographicOperations.FixedTimeEquals(suppliedBytes, expectedBytes);
    }
}
