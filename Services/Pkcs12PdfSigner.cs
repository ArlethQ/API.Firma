using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PdfSharp.Pdf.Signatures;

namespace API.Firma.Services;

internal sealed class Pkcs12PdfSigner(
    X509Certificate2 signingCertificate,
    X509Certificate2Collection certificates,
    ILogger logger) : IDigitalSigner
{
    private static readonly Oid Sha256Oid = new("2.16.840.1.101.3.4.2.1");

    public string CertificateName => signingCertificate.GetNameInfo(
        X509NameType.SimpleName,
        forIssuer: false);

    public Task<int> GetSignatureSizeAsync()
    {
        var size = CreateSignature([0]).Length;
        logger.LogDebug(
            "Tamaño CMS reservado calculado: {SignatureSize} bytes; firmante {Thumbprint}; certificados PKCS#12 {CertificateCount}",
            size,
            signingCertificate.Thumbprint,
            certificates.Count);
        return Task.FromResult(size);
    }

    public Task<byte[]> GetSignatureAsync(Stream stream)
    {
        var stopwatch = Stopwatch.StartNew();
        using var content = new MemoryStream();
        stream.Position = 0;
        var buffer = new byte[81920];
        int bytesRead;
        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            content.Write(buffer, 0, bytesRead);
        }

        var contentBytes = content.ToArray();
        logger.LogDebug(
            "Contenido ByteRange preparado para firma: {ContentBytes} bytes en {ElapsedMs} ms",
            contentBytes.Length,
            stopwatch.ElapsedMilliseconds);
        var signature = CreateSignature(contentBytes);
        logger.LogInformation(
            "Firma CMS generada: {SignatureBytes} bytes para {ContentBytes} bytes; firmante {Thumbprint}; certificados incluidos {IncludedCertificateCount}; duración {ElapsedMs} ms",
            signature.Length,
            contentBytes.Length,
            signingCertificate.Thumbprint,
            certificates.Count,
            stopwatch.ElapsedMilliseconds);
        return Task.FromResult(signature);
    }

    private byte[] CreateSignature(byte[] content)
    {
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var signer = new CmsSigner(
            SubjectIdentifierType.IssuerAndSerialNumber,
            signingCertificate)
        {
            DigestAlgorithm = Sha256Oid,
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));

        foreach (var certificate in certificates)
        {
            if (!string.Equals(
                    certificate.Thumbprint,
                    signingCertificate.Thumbprint,
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(
                    certificate.Subject,
                    certificate.Issuer,
                    StringComparison.OrdinalIgnoreCase))
            {
                signer.Certificates.Add(certificate);
            }
        }

        cms.ComputeSignature(signer, silent: true);
        return cms.Encode();
    }
}
