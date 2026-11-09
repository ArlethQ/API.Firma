using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace API.Firma.Security;

public sealed class IpAllowlistMiddleware
{
    private readonly RequestDelegate next;
    private readonly HashSet<IPAddress> allowedAddresses;

    public IpAllowlistMiddleware(
        RequestDelegate next,
        IOptions<ApiSecurityOptions> securityOptions)
    {
        this.next = next;
        allowedAddresses = securityOptions.Value.AllowedIpAddresses
            .Select(IPAddress.Parse)
            .Select(Normalize)
            .ToHashSet();
    }

    public async Task InvokeAsync(HttpContext context, IHostEnvironment environment)
    {
        var isDevelopmentSwagger = environment.IsDevelopment()
            && (context.Request.Path == "/"
                || context.Request.Path.StartsWithSegments("/swagger"));
        if (isDevelopmentSwagger
            || context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var remoteAddress = context.Connection.RemoteIpAddress;
        var isAllowed = remoteAddress is not null
            ? allowedAddresses.Contains(Normalize(remoteAddress))
            : environment.IsEnvironment("Testing");

        if (!isAllowed)
        {
            await Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Acceso bloqueado",
                    detail: "La dirección IP no está autorizada para utilizar esta API.")
                .ExecuteAsync(context);
            return;
        }

        await next(context);
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
