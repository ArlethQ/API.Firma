using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using API.Firma.Models;
using API.Firma.Security;
using API.Firma.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace API.Firma.Tests;

public sealed class PdfStampServiceTests
{
    private const string CertificatePassword = "Clave-segura-de-prueba";

    [Fact]
    public async Task StampAsync_StampsAndSignsInOneFlow()
    {
        var request = CreateRequest(CreatePdf());

        var result = await CreateService().StampAsync(request, CancellationToken.None);

        Assert.NotEmpty(result.Pdf);
        Assert.Equal("%PDF-"u8.ToArray(), result.Pdf[..5]);
        Assert.NotEqual(result.OriginalSha256, result.OutputSha256);

        using var output = new MemoryStream(result.Pdf);
        using var document = PdfReader.Open(output, PdfDocumentOpenMode.Import);
        Assert.Single(document.Pages);

        var validationService = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            new UanatacaTrustStore(
                NullLogger<UanatacaTrustStore>.Instance));
        var validation = await validationService.ValidateAsync(
            CreateFormFile(
                result.Pdf,
                "pdf",
                "documento-firmado-estampado.pdf",
                "application/pdf"),
            CancellationToken.None);
        Assert.True(validation.DocumentoCompletoCubierto);
        Assert.True(Assert.Single(validation.Firmas).IntegridadValida);
    }

    [Fact]
    public async Task StampAsync_AcceptsPdfWithUtf8Bom()
    {
        var pdfWithBom = new byte[] { 0xEF, 0xBB, 0xBF }
            .Concat(CreatePdf())
            .ToArray();

        var result = await CreateService().StampAsync(
            CreateRequest(pdfWithBom),
            CancellationToken.None);

        Assert.Equal("%PDF-"u8.ToArray(), result.Pdf[..5]);
    }

    [Fact]
    public async Task StampAsync_RejectsWrongCertificatePassword()
    {
        var exception = await Assert.ThrowsAsync<StampValidationException>(
            () => CreateService().StampAsync(
                CreateRequest(CreatePdf(), password: "clave-incorrecta"),
                CancellationToken.None));

        Assert.Equal("certificado", exception.Field);
        Assert.Equal("PFX_PASSWORD_REJECTED", exception.DiagnosticCode);
        Assert.Matches("^0x[0-9A-F]{8}$", exception.CryptographicErrorCode);
    }

    [Fact]
    public void RequiresMachineKeySetRetry_OnlyAcceptsFileNotFoundError()
    {
        Assert.True(PdfStampService.RequiresMachineKeySetRetry(
            unchecked((int)0x80070002)));
        Assert.False(PdfStampService.RequiresMachineKeySetRetry(
            unchecked((int)0x80070056)));
    }

    [Fact]
    public async Task StampAsync_RejectsNonPkcs12ContentWithSpecificMessage()
    {
        var request = CreateRequest(
            CreatePdf(),
            certificate: "contenido-base64"u8.ToArray());

        var exception = await Assert.ThrowsAsync<StampValidationException>(
            () => CreateService().StampAsync(request, CancellationToken.None));

        Assert.Equal("certificado", exception.Field);
        Assert.Contains("archivo binario original", exception.Message);
        Assert.Equal("PFX_FORMAT_INVALID", exception.DiagnosticCode);
    }

    [Fact]
    public async Task StampAsync_RejectsEmptyCertificate()
    {
        var exception = await Assert.ThrowsAsync<StampValidationException>(
            () => CreateService().StampAsync(
                CreateRequest(CreatePdf(), certificate: []),
                CancellationToken.None));

        Assert.Equal("certificado", exception.Field);
        Assert.Contains("Debe enviar", exception.Message);
    }

    [Fact]
    public async Task StampAsync_RejectsPkcs12WithoutPrivateKey()
    {
        var exception = await Assert.ThrowsAsync<StampValidationException>(
            () => CreateService().StampAsync(
                CreateRequest(CreatePdf(), certificate: CreateP12(includePrivateKey: false)),
                CancellationToken.None));

        Assert.Equal("certificado", exception.Field);
        Assert.Contains("clave privada", exception.Message);
    }

    [Fact]
    public async Task StampAsync_DoesNotUseClientFileNameAsServerPath()
    {
        var request = CreateRequest(
            CreatePdf(),
            fileName: "../../ruta/inexistente/certificado.p12");

        var result = await CreateService().StampAsync(
            request,
            CancellationToken.None);

        Assert.NotEmpty(result.Pdf);
    }

    [Fact]
    public async Task StampAsync_LeavesNoTemporaryCertificateFile()
    {
        var clientSuppliedPath = Path.Combine(
            Path.GetTempPath(),
            $"api-firma-test-{Guid.NewGuid():N}.p12");

        try
        {
            var result = await CreateService().StampAsync(
                CreateRequest(CreatePdf(), fileName: clientSuppliedPath),
                CancellationToken.None);

            Assert.NotEmpty(result.Pdf);
            Assert.False(File.Exists(clientSuppliedPath));
        }
        finally
        {
            if (File.Exists(clientSuppliedPath))
            {
                File.Delete(clientSuppliedPath);
            }
        }
    }

    [Fact]
    public async Task StampAsync_HandlesTwoConcurrentRequestsInMemory()
    {
        var p12 = CreateP12();

        var results = await Task.WhenAll(
            Enumerable.Range(0, 2).Select(_ =>
                CreateService().StampAsync(
                    CreateRequest(CreatePdf(), certificate: p12),
                    CancellationToken.None)));

        Assert.All(results, result => Assert.NotEmpty(result.Pdf));
    }

    [Fact]
    public async Task StampAsync_LogsReceivedCertificateLengthAndSha256()
    {
        var p12 = CreateP12();
        var logger = new RecordingLogger<PdfStampService>();

        await CreateService(logger).StampAsync(
            CreateRequest(CreatePdf(), certificate: p12),
            CancellationToken.None);

        var expectedHash = Convert.ToHexString(SHA256.HashData(p12));
        Assert.Contains(
            logger.Messages,
            message => message.Contains(expectedHash, StringComparison.Ordinal)
                && message.Contains($"longitud {p12.Length} bytes", StringComparison.Ordinal)
                && message.Contains("almacenamiento memory", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StampAsync_IncludesCertificatesBundledInPkcs12()
    {
        var p12 = CreateP12WithChain();

        var result = await CreateService().StampAsync(
            CreateRequest(CreatePdf(), certificate: p12),
            CancellationToken.None);

        var text = Encoding.Latin1.GetString(result.Pdf);
        var contents = Regex.Match(
            text,
            @"/Contents\s*<([\da-fA-F\s]+)>",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2));
        Assert.True(contents.Success);
        var cmsBytes = Convert.FromHexString(
            Regex.Replace(contents.Groups[1].Value, @"\s", string.Empty));
        var cms = new SignedCms();
        cms.Decode(cmsBytes);

        Assert.Equal(3, cms.Certificates.Count);
        Assert.Contains(
            cms.Certificates.Cast<X509Certificate2>(),
            certificate => certificate.Subject.Contains(
                "INTERMEDIA DE PRUEBA",
                StringComparison.Ordinal));
    }

    [Fact]
    public void QrToken_RoundTripReturnsAuthenticJsonData()
    {
        using var document = JsonDocument.Parse(
            """{"EsValida":true,"NombreTitular":"ANA","DiasRestantes":141}""");
        var service = CreateQrTokenService();
        var url = service.CreateVerificationUrl(
            document.RootElement,
            new string('A', 64),
            DateTimeOffset.UtcNow);
        var token = QueryHelpers.ParseQuery(new Uri(url).Query)["token"].ToString();

        var result = service.Verify(token);

        Assert.True(result.Valido);
        Assert.Equal(
            """{"EsValida":true,"NombreTitular":"ANA","DiasRestantes":141}""",
            JsonSerializer.Serialize(result.Datos));
    }

    [Fact]
    public void QrToken_RejectsAlteredSignature()
    {
        using var document = JsonDocument.Parse("""{"EsValida":true}""");
        var service = CreateQrTokenService();
        var url = service.CreateVerificationUrl(
            document.RootElement,
            new string('A', 64),
            DateTimeOffset.UtcNow);
        var token = QueryHelpers.ParseQuery(new Uri(url).Query)["token"].ToString();
        var altered = token[..^1] + (token[^1] == 'A' ? "B" : "A");

        var exception = Assert.Throws<StampValidationException>(() => service.Verify(altered));

        Assert.Equal("token", exception.Field);
    }

    [Theory]
    [InlineData("")]
    [InlineData("v1")]
    [InlineData("v1...")]
    [InlineData("v2.YQ.c2lnbmF0dXJl")]
    [InlineData("v1.***.***")]
    public void QrToken_RejectsMalformedTokensWithoutUnhandledErrors(string token)
    {
        var service = CreateQrTokenService();

        var exception = Assert.Throws<StampValidationException>(() => service.Verify(token));

        Assert.Equal("token", exception.Field);
    }

    private static PdfStampService CreateService(
        ILogger<PdfStampService>? logger = null) =>
        new(logger ?? NullLogger<PdfStampService>.Instance, CreateQrTokenService());

    private static QrTokenService CreateQrTokenService() =>
        new(Options.Create(new QrSecurityOptions
        {
            SigningKey = "Clave-de-prueba-QR-con-mas-de-32-caracteres",
            VerificationBaseUrl = "https://firma.test/api/verificaciones/qr"
        }));

    private static StampPdfRequest CreateRequest(
        byte[] pdf,
        string password = CertificatePassword,
        byte[]? certificate = null,
        string fileName = "certificado.p12")
    {
        var stream = new MemoryStream(pdf);
        var file = new FormFile(stream, 0, stream.Length, "pdf", "documento.pdf")
        {
            Headers = new HeaderDictionary(),
            ContentType = "application/pdf"
        };

        return new StampPdfRequest
        {
            Pdf = file,
            Certificado = CreateFormFile(
                certificate ?? CreateP12(),
                "certificado",
                fileName,
                "application/x-pkcs12"),
            Clave = password,
            Razon = "Prueba integrada",
            Pagina = 1,
            XMm = 10,
            YMm = 10,
            AnchoMm = 100
        };
    }

    private static byte[] CreateP12(bool includePrivateKey = true)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=FIRMANTE DE PRUEBA",
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
        using var certificateToExport = includePrivateKey
            ? null
            : X509CertificateLoader.LoadCertificate(
                certificate.Export(X509ContentType.Cert));
        return (certificateToExport ?? certificate).Export(
            X509ContentType.Pkcs12,
            CertificatePassword);
    }

    private static byte[] CreateP12WithChain()
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=RAIZ DE PRUEBA",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 1, true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(60));

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest(
            "CN=INTERMEDIA DE PRUEBA",
            intermediateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
        using var intermediatePublic = intermediateRequest.Create(
            root,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(45),
            RandomNumberGenerator.GetBytes(16));
        using var intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

        using var signerKey = RSA.Create(2048);
        var signerRequest = new CertificateRequest(
            "CN=FIRMANTE CON CADENA",
            signerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        signerRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        signerRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var signerPublic = signerRequest.Create(
            intermediate,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(16));
        using var signer = signerPublic.CopyWithPrivateKey(signerKey);

        var collection = new X509Certificate2Collection
        {
            signer,
            intermediate,
            root
        };
        return collection.Export(X509ContentType.Pkcs12, CertificatePassword)!;
    }

    private static byte[] CreatePdf()
    {
        using var document = new PdfDocument();
        document.AddPage();
        using var stream = new MemoryStream();
        document.Save(stream, false);
        return stream.ToArray();
    }

    private static IFormFile CreateFormFile(
        byte[] bytes,
        string fieldName,
        string fileName,
        string contentType)
    {
        var stream = new MemoryStream(bytes);
        return new FormFile(stream, 0, stream.Length, fieldName, fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType
        };
    }

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

}
