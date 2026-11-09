using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using API.Firma.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace API.Firma.Tests;

public sealed class PdfSignatureValidationServiceTests
{
    [Fact]
    public async Task ValidateAsync_WithValidCmsSignature_ReturnsValidIntegrity()
    {
        var pdf = CreateSignedPdf();
        var file = CreatePdfFile(pdf);
        var service = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            CreateTrustStore());

        var result = await service.ValidateAsync(file, CancellationToken.None);

        Assert.False(result.Valido);
        Assert.Equal("NO_VERIFICABLE", result.Estado);
        Assert.Contains(
            result.Errores,
            issue => issue.Codigo == "CADENA_NO_CONFIABLE");
        Assert.True(result.DocumentoCompletoCubierto);
        var signature = Assert.Single(result.Firmas);
        Assert.True(signature.IntegridadValida);
        Assert.True(signature.CertificadoVigente);
        Assert.False(signature.CadenaConfiable);
        Assert.False(signature.Valida);
        Assert.True(signature.RevocacionValida);
        Assert.Equal("SinProblemasDetectados", signature.EstadoRevocacion);
        Assert.Null(signature.SelloTiempoValido);
        Assert.Equal("FIRMANTE DE PRUEBA", signature.Firmante);
    }

    [Fact]
    public async Task ValidateAsync_WithSignatureFromAnotherProviderField_ReturnsValidIntegrity()
    {
        var pdf = CreateSignedPdf(signatureFieldName: "Firma-Otro-Proveedor");
        var service = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            CreateTrustStore());

        var result = await service.ValidateAsync(
            CreatePdfFile(pdf),
            CancellationToken.None);

        Assert.Single(result.Firmas);
        Assert.True(result.DocumentoCompletoCubierto);
        Assert.True(result.Firmas[0].IntegridadValida);
    }

    [Fact]
    public async Task ValidateAsync_WithUnsignedPdf_ReturnsNoSignatures()
    {
        var service = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            CreateTrustStore());

        var result = await service.ValidateAsync(
            CreatePdfFile("%PDF-1.7\n%%EOF"u8.ToArray()),
            CancellationToken.None);

        Assert.False(result.Valido);
        Assert.Equal("SIN_FIRMAS", result.Estado);
        Assert.Equal("SIN_FIRMAS", Assert.Single(result.Errores).Codigo);
        Assert.Empty(result.Firmas);
    }

    [Fact]
    public async Task ValidateAsync_WithAlteredSignedContent_ReturnsInvalid()
    {
        var pdf = CreateSignedPdf();
        pdf[12] ^= 1;
        var service = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            CreateTrustStore());

        var result = await service.ValidateAsync(
            CreatePdfFile(pdf),
            CancellationToken.None);

        Assert.False(result.Valido);
        Assert.Equal("INVALIDA", result.Estado);
        var signature = Assert.Single(result.Firmas);
        Assert.False(signature.IntegridadValida);
        Assert.Equal("INTEGRIDAD_INVALIDA", signature.CodigoError);
        Assert.Contains("modificado", signature.Error, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(signature.DetalleTecnico));
    }

    [Fact]
    public async Task ValidateAsync_ExpiredCertificateDoesNotTrustClaimedSigningTime()
    {
        var pdf = CreateSignedPdf(
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(-10));
        var service = new PdfSignatureValidationService(
            NullLogger<PdfSignatureValidationService>.Instance,
            CreateTrustStore());

        var result = await service.ValidateAsync(
            CreatePdfFile(pdf),
            CancellationToken.None);

        var signature = Assert.Single(result.Firmas);
        Assert.True(signature.IntegridadValida);
        Assert.False(signature.CertificadoVigente);
        Assert.Equal("INVALIDA", result.Estado);
        Assert.Equal("CERTIFICADO_NO_VIGENTE", signature.CodigoError);
        Assert.Null(signature.SelloTiempoValido);
        Assert.Contains("sello de tiempo", signature.Error);
    }

    private static byte[] CreateSignedPdf(
        DateTimeOffset? certificateFrom = null,
        DateTimeOffset? certificateUntil = null,
        DateTime? claimedSigningTime = null,
        string signatureFieldName = "API.Firma-test")
    {
        const int reservedCmsHexLength = 16_384;
        var contentsPlaceholder = new string('0', reservedCmsHexLength);
        var template = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "%PDF-1.7\n2 0 obj\n<< /FT /Sig /T ({4}) /V 1 0 R >>\nendobj\n1 0 obj\n<< /Type /Sig /ByteRange [0 {0:D10} {1:D10} {2:D10}] /Contents <{3}> >>\nendobj\n%%EOF",
            0,
            0,
            0,
            contentsPlaceholder,
            signatureFieldName);
        var contentsStart = template.IndexOf('<', template.IndexOf("/Contents", StringComparison.Ordinal));
        var secondRangeStart = contentsStart + reservedCmsHexLength + 2;
        var secondRangeLength = template.Length - secondRangeStart;
        template = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "%PDF-1.7\n2 0 obj\n<< /FT /Sig /T ({4}) /V 1 0 R >>\nendobj\n1 0 obj\n<< /Type /Sig /ByteRange [0 {0:D10} {1:D10} {2:D10}] /Contents <{3}> >>\nendobj\n%%EOF",
            contentsStart,
            secondRangeStart,
            secondRangeLength,
            contentsPlaceholder,
            signatureFieldName);

        var unsignedPdf = System.Text.Encoding.ASCII.GetBytes(template);
        var signedContent = new byte[contentsStart + secondRangeLength];
        Buffer.BlockCopy(unsignedPdf, 0, signedContent, 0, contentsStart);
        Buffer.BlockCopy(
            unsignedPdf,
            secondRangeStart,
            signedContent,
            contentsStart,
            secondRangeLength);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=FIRMANTE DE PRUEBA",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            certificateFrom ?? DateTimeOffset.UtcNow.AddDays(-1),
            certificateUntil ?? DateTimeOffset.UtcNow.AddDays(30));
        var cms = new SignedCms(new ContentInfo(signedContent), detached: true);
        var signer = new CmsSigner(certificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(
            claimedSigningTime ?? DateTime.UtcNow));
        cms.ComputeSignature(signer);
        var cmsHex = Convert.ToHexString(cms.Encode());
        Assert.True(cmsHex.Length <= reservedCmsHexLength);

        var paddedCmsHex = cmsHex.PadRight(reservedCmsHexLength, '0');
        return System.Text.Encoding.ASCII.GetBytes(
            template.Replace(contentsPlaceholder, paddedCmsHex, StringComparison.Ordinal));
    }

    private static IFormFile CreatePdfFile(byte[] bytes)
    {
        var stream = new MemoryStream(bytes);
        return new FormFile(stream, 0, stream.Length, "pdf", "firmado.pdf")
        {
            Headers = new HeaderDictionary(),
            ContentType = "application/pdf"
        };
    }

    private static UanatacaTrustStore CreateTrustStore() =>
        new(NullLogger<UanatacaTrustStore>.Instance);
}
