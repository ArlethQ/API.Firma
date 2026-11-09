using System.Net;
using API.Firma.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace API.Firma.Tests;

public sealed class IpAllowlistMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_AllowsConfiguredIp()
    {
        var nextWasCalled = false;
        var middleware = CreateMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback;

        await middleware.InvokeAsync(context, new TestEnvironment());

        Assert.True(nextWasCalled);
    }

    [Fact]
    public async Task InvokeAsync_BlocksUnknownIp()
    {
        var nextWasCalled = false;
        var middleware = CreateMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
        context.Response.Body = new MemoryStream();
        using var services = new ServiceCollection()
            .AddLogging()
            .AddProblemDetails()
            .BuildServiceProvider();
        context.RequestServices = services;

        await middleware.InvokeAsync(context, new TestEnvironment());

        Assert.False(nextWasCalled);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    private static IpAllowlistMiddleware CreateMiddleware(RequestDelegate next) =>
        new(
            next,
            Options.Create(new ApiSecurityOptions
            {
                ApiKey = "12345678901234567890123456789012",
                AllowedIpAddresses = ["127.0.0.1", "::1"]
            }));

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "API.Firma.Tests";
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
