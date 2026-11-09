using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using API.Firma.Security;
using API.Firma.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace API.Firma.Tests;

public sealed class ApiEndpointsTests : IDisposable
{
    private const string ApiKey = "12345678901234567890123456789012";
    private const string CertificatePassword = "Clave-segura-de-prueba";
    private readonly WebApplicationFactory<global::API.Firma.Program> factory;

    public ApiEndpointsTests()
    {
        factory = new WebApplicationFactory<global::API.Firma.Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Testing");
                builder.ConfigureLogging(logging => logging.ClearProviders());
                builder.ConfigureAppConfiguration((_, configuration) =>
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["ApiSecurity:ApiKey"] = ApiKey,
                        ["ApiSecurity:AllowedIpAddresses:0"] = "127.0.0.1",
                        ["ApiSecurity:AllowedIpAddresses:1"] = "::1",
                        ["QrSecurity:SigningKey"] = "Clave-QR-integracion-con-mas-de-32-caracteres",
                        ["QrSecurity:VerificationBaseUrl"] =
                            "https://localhost/api/verificaciones/qr"
                    }));
            });
    }

    [Fact]
    public async Task Stamp_WithoutApiKey_ReturnsUnauthorized()
    {
        using var client = CreateClient();
        using var content = new MultipartFormDataContent();

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Stamp_WithMultipleInvalidFields_ReturnsEveryValidationError()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var content = new MultipartFormDataContent
        {
            { new StringContent("-1"), "xMm" },
            { new StringContent("200"), "anchoMm" }
        };

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType?.MediaType);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        var root = body.RootElement;
        var errors = root.GetProperty("errors");

        Assert.Equal("La solicitud contiene errores de validación.", root.GetProperty("title").GetString());
        Assert.Equal(5, root.GetProperty("errorCount").GetInt32());
        Assert.True(errors.TryGetProperty("pdf", out _));
        Assert.True(errors.TryGetProperty("certificado", out _));
        Assert.True(errors.TryGetProperty("clave", out _));
        Assert.True(errors.TryGetProperty("xMm", out _));
        Assert.True(errors.TryGetProperty("anchoMm", out _));

        var detail = root.GetProperty("detail").GetString();
        foreach (var field in new[] { "pdf", "certificado", "clave", "xMm", "anchoMm" })
        {
            Assert.Contains($"{field}:", detail);
        }
    }

    [Fact]
    public async Task Health_DoesNotRequireApiKey()
    {
        using var client = CreateClient();

        using var response = await client.GetAsync("/api/salud");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Stamp_WithValidRequest_ReturnsStampedPdfAndHashes()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", $"  {ApiKey}  ");
        using var content = CreateValidRequest();

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.Contains("X-Documento-Original-SHA256"));
        Assert.True(response.Headers.Contains("X-Documento-Salida-SHA256"));

        var result = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("%PDF-"u8.ToArray(), result[..5]);

        using var stream = new MemoryStream(result);
        using var document = PdfReader.Open(stream, PdfDocumentOpenMode.Import);
        Assert.Single(document.Pages);
    }

    [Fact]
    public async Task Stamp_WithPdfContentTypeOctetStream_AcceptsPdfByContent()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var content = CreateValidRequest(pdfContentType: "application/octet-stream");

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Stamp_WithTwoPositions_ReturnsOneSignedPdf()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var content = CreateValidRequest(
            posiciones: "[{\"pagina\":1,\"xMm\":20,\"yMm\":30,\"anchoMm\":80},{\"pagina\":1,\"xMm\":110,\"yMm\":160,\"anchoMm\":80}]");

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("%PDF-"u8.ToArray(), result[..5]);
    }

    [Fact]
    public async Task Stamp_WithWrongCertificatePassword_ReturnsSafeDiagnostic()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var content = CreateValidRequest("clave-incorrecta");

        using var response = await client.PostAsync(
            "/api/documentos/estampar",
            content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        Assert.Equal(
            "PFX_PASSWORD_REJECTED",
            body.RootElement.GetProperty("diagnosticCode").GetString());
        Assert.Matches(
            "^0x[0-9A-F]{8}$",
            body.RootElement.GetProperty("cryptographicErrorCode").GetString());
    }

    [Fact]
    public async Task ValidateSignature_WithUnsignedPdf_ReturnsInvalidResult()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var content = new MultipartFormDataContent();
        var pdf = new ByteArrayContent(CreatePdf());
        pdf.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        content.Add(pdf, "pdf", "documento.pdf");

        using var response = await client.PostAsync(
            "/api/documentos/validar-firma",
            content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        Assert.False(body.RootElement.GetProperty("valido").GetBoolean());
        Assert.Equal(0, body.RootElement.GetProperty("cantidadFirmas").GetInt32());
    }

    [Fact]
    public async Task Stamp_WithValidP12_ReturnsPdfWithValidIntegrity()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
        using var signContent = CreateValidRequest();

        using var signResponse = await client.PostAsync(
            "/api/documentos/estampar",
            signContent);

        Assert.Equal(HttpStatusCode.OK, signResponse.StatusCode);
        Assert.Equal(
            "application/pdf",
            signResponse.Content.Headers.ContentType?.MediaType);
        var signedPdf = await signResponse.Content.ReadAsByteArrayAsync();

        using var validationContent = new MultipartFormDataContent();
        var signedPdfContent = new ByteArrayContent(signedPdf);
        signedPdfContent.Headers.ContentType =
            new MediaTypeHeaderValue("application/pdf");
        validationContent.Add(
            signedPdfContent,
            "pdf",
            "documento-firmado.pdf");

        using var validationResponse = await client.PostAsync(
            "/api/documentos/validar-firma",
            validationContent);

        Assert.Equal(HttpStatusCode.OK, validationResponse.StatusCode);
        using var body = JsonDocument.Parse(
            await validationResponse.Content.ReadAsStreamAsync());
        var signature = Assert.Single(
            body.RootElement.GetProperty("firmas").EnumerateArray());
        Assert.True(signature.GetProperty("integridadValida").GetBoolean());
        Assert.True(signature.GetProperty("cubreDocumentoCompleto").GetBoolean());
        Assert.Equal(
            "NO_VERIFICABLE",
            body.RootElement.GetProperty("estado").GetString());
        Assert.Contains(
            body.RootElement.GetProperty("errores").EnumerateArray(),
            issue => issue.GetProperty("codigo").GetString()
                == "CADENA_NO_CONFIABLE");
    }

    [Fact]
    public async Task Stamp_WithPreviouslySignedPdf_PreservesPreviousSignature()
    {
        using var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);

        using var firstRequest = CreateValidRequest();
        using var firstResponse = await client.PostAsync(
            "/api/documentos/estampar",
            firstRequest);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var firstSignedPdf = await firstResponse.Content.ReadAsByteArrayAsync();

        using var secondRequest = CreateValidRequest(pdfBytes: firstSignedPdf);
        using var secondResponse = await client.PostAsync(
            "/api/documentos/estampar",
            secondRequest);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        var secondSignedPdf = await secondResponse.Content.ReadAsByteArrayAsync();

        using var validationContent = new MultipartFormDataContent();
        var pdfContent = new ByteArrayContent(secondSignedPdf);
        pdfContent.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        validationContent.Add(pdfContent, "pdf", "documento-firmado.pdf");
        using var validationResponse = await client.PostAsync(
            "/api/documentos/validar-firma",
            validationContent);

        Assert.Equal(HttpStatusCode.OK, validationResponse.StatusCode);
        using var body = JsonDocument.Parse(await validationResponse.Content.ReadAsStreamAsync());
        Assert.Equal(2, body.RootElement.GetProperty("cantidadFirmas").GetInt32());
        Assert.All(
            body.RootElement.GetProperty("firmas").EnumerateArray(),
            signature => Assert.True(signature.GetProperty("integridadValida").GetBoolean()));
    }

    [Fact]
    public async Task Swagger_DocumentsSignatureValidationResponses()
    {
        using var developmentFactory = factory.WithWebHostBuilder(
            builder => builder.UseEnvironment("Development"));
        using var client = developmentFactory.CreateClient();

        using var response = await client.GetAsync("/swagger/v1/swagger.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var swagger = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        var operation = swagger.RootElement
            .GetProperty("paths")
            .GetProperty("/api/documentos/validar-firma")
            .GetProperty("post");
        Assert.Contains("OCSP/CRL", operation.GetProperty("description").GetString());
        var responses = operation.GetProperty("responses");
        foreach (var status in new[] { "200", "400", "401", "403", "413", "429" })
        {
            Assert.True(responses.TryGetProperty(status, out _), $"Falta documentar HTTP {status}.");
        }
    }

    [Fact]
    public async Task VerifyQr_DoesNotRequireApiKeyAndRejectsAlteredToken()
    {
        using var data = JsonDocument.Parse("""{"NombreTitular":"PRUEBA"}""");
        var tokenService = new QrTokenService(Options.Create(new QrSecurityOptions
        {
            SigningKey = "Clave-QR-integracion-con-mas-de-32-caracteres",
            VerificationBaseUrl = "https://localhost/api/verificaciones/qr"
        }));
        var verificationUrl = tokenService.CreateVerificationUrl(
            data.RootElement,
            new string('A', 64),
            DateTimeOffset.UtcNow);
        using var client = CreateClient();

        using var validResponse = await client.GetAsync(new Uri(verificationUrl).PathAndQuery);
        using var invalidResponse = await client.GetAsync("/api/verificaciones/qr?token=alterado");

        Assert.Equal(HttpStatusCode.OK, validResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidResponse.StatusCode);
    }

    public void Dispose() => factory.Dispose();

    private HttpClient CreateClient() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost")
        });

    private static MultipartFormDataContent CreateValidRequest(
        string password = CertificatePassword,
        string? posiciones = null,
        string pdfContentType = "application/pdf",
        byte[]? pdfBytes = null)
    {
        var content = new MultipartFormDataContent();
        var pdf = new ByteArrayContent(pdfBytes ?? CreatePdf());
        pdf.Headers.ContentType = new MediaTypeHeaderValue(pdfContentType);
        var certificate = new ByteArrayContent(CreateP12());
        certificate.Headers.ContentType =
            new MediaTypeHeaderValue("application/x-pkcs12");

        content.Add(pdf, "pdf", "documento.pdf");
        content.Add(certificate, "certificado", "certificado.p12");
        content.Add(new StringContent(password), "clave");
        content.Add(new StringContent("1"), "pagina");
        content.Add(new StringContent("100"), "xMm");
        content.Add(new StringContent("224.78"), "yMm");
        content.Add(new StringContent("100"), "anchoMm");
        if (posiciones is not null)
            content.Add(new StringContent(posiciones), "posiciones");
        return content;
    }

    private static byte[] CreatePdf()
    {
        using var document = new PdfDocument();
        document.AddPage();
        using var stream = new MemoryStream();
        document.Save(stream, false);
        return stream.ToArray();
    }

    private static byte[] CreateP12()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=FIRMANTE DE INTEGRACION",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return certificate.Export(
            X509ContentType.Pkcs12,
            CertificatePassword);
    }

}
