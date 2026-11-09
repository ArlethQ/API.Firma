using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using API.Firma.Models;

namespace API.Firma.Services;

public sealed class PdfSignatureValidationService(
    ILogger<PdfSignatureValidationService> logger,
    UanatacaTrustStore trustStore)
{
    private const long MaxPdfBytes = 10 * 1024 * 1024;
    private const string SignatureTimestampOid = "1.2.840.113549.1.9.16.2.14";
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private static readonly TimeSpan RevocationTimeout = TimeSpan.FromSeconds(5);
    private static readonly Regex ByteRangeRegex = new(
        @"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex ContentsRegex = new(
        @"/Contents\s*<([\da-fA-F\s]+)>",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    public async Task<PdfSignatureValidationResult> ValidateAsync(
        IFormFile pdf,
        CancellationToken cancellationToken)
    {
        ValidateFile(pdf);

        await using var input = new MemoryStream();
        await pdf.CopyToAsync(input, cancellationToken);
        var bytes = input.ToArray();
        ValidatePdfHeader(bytes);

        var text = Encoding.Latin1.GetString(bytes);
        var signatures = new List<PdfSignatureDetail>();

        var signatureMatches = ByteRangeRegex
            .Matches(text)
            .ToArray();

        foreach (var byteRangeMatch in signatureMatches)
        {
            signatures.AddRange(ValidateSignatures(bytes, text, byteRangeMatch));
        }

        var latestRevisionEnd = signatureMatches.Length == 0
            ? 0
            : signatureMatches.Max(GetRevisionEnd);
        var documentCovered = latestRevisionEnd == bytes.Length;
        var valid = signatures.Count > 0
            && documentCovered
            && signatures.All(signature => signature.Valida);

        var result = new PdfSignatureValidationResult(
            valid,
            signatures.Count,
            documentCovered,
            signatures);
        if (result.Valido)
        {
            logger.LogInformation(
                "Validación de PDF completada: {SignatureCount} firma(s), estado {Status}",
                signatures.Count,
                result.Estado);
        }
        else
        {
            logger.LogWarning(
                "Validación de PDF completada: {SignatureCount} firma(s), estado {Status}. Motivos: {Issues}",
                signatures.Count,
                result.Estado,
                string.Join(
                    " | ",
                    result.Errores.Select(issue =>
                        issue.NumeroFirma is null
                            ? $"{issue.Codigo}: {issue.Mensaje}"
                            : $"{issue.Codigo} (firma {issue.NumeroFirma}): {issue.Mensaje}")));
        }

        return result;
    }

    private static long GetRevisionEnd(Match match) =>
        long.Parse(match.Groups[3].Value) + long.Parse(match.Groups[4].Value);

    private IReadOnlyList<PdfSignatureDetail> ValidateSignatures(
        byte[] pdf,
        string text,
        Match byteRangeMatch)
    {
        try
        {
            var ranges = byteRangeMatch.Groups
                .Cast<Group>()
                .Skip(1)
                .Select(group => long.Parse(group.Value))
                .ToArray();
            ValidateByteRange(ranges, pdf.Length);

            var objectStart = text.LastIndexOf(" obj", byteRangeMatch.Index, StringComparison.Ordinal);
            objectStart = objectStart < 0
                ? 0
                : text.LastIndexOfAny(['\r', '\n'], objectStart) + 1;
            var objectEnd = text.IndexOf("endobj", byteRangeMatch.Index, StringComparison.Ordinal);
            if (objectEnd < 0)
            {
                throw new CryptographicException("No se encontró el final del objeto de firma.");
            }

            var signatureObject = text[objectStart..objectEnd];
            var contentsMatch = ContentsRegex.Match(signatureObject);
            if (!contentsMatch.Success)
            {
                throw new CryptographicException(
                    "La firma no contiene un bloque CMS hexadecimal compatible.");
            }

            var cmsBytes = Convert.FromHexString(
                Regex.Replace(contentsMatch.Groups[1].Value, @"\s", string.Empty));
            cmsBytes = TrimDerPadding(cmsBytes);

            using var signedContent = new MemoryStream();
            signedContent.Write(pdf, checked((int)ranges[0]), checked((int)ranges[1]));
            signedContent.Write(pdf, checked((int)ranges[2]), checked((int)ranges[3]));

            var cms = new SignedCms(
                new ContentInfo(signedContent.ToArray()),
                detached: true);
            cms.Decode(cmsBytes);
            cms.CheckSignature(verifySignatureOnly: true);

            var signers = cms.SignerInfos
                .Cast<SignerInfo>()
                .ToArray();
            var revisionEnd = ranges[2] + ranges[3];
            if (signers.Length == 0)
            {
                throw new CryptographicException("El bloque CMS no contiene firmantes.");
            }

            return signers
                .Select(signer =>
                {
                    var certificate = signer.Certificate
                        ?? throw new CryptographicException(
                            "La firma no incluye el certificado del firmante.");
                    var signedAt = GetSigningTime(signer);
                    var timestamp = ValidateTimestamp(signer);
                    var validationTime = timestamp.Valid == true
                        ? timestamp.Timestamp!.Value.UtcDateTime
                        : DateTime.UtcNow;
                    var certificateCurrent = validationTime >= certificate.NotBefore.ToUniversalTime()
                        && validationTime <= certificate.NotAfter.ToUniversalTime();
                    var chain = ValidateChain(
                        certificate,
                        cms.Certificates,
                        validationTime,
                        requireTimestampingEku: false);
                    var signatureValid = certificateCurrent
                        && chain.Trusted
                        && !chain.Revoked
                        && (!timestamp.Present || timestamp.Valid != false);

                    return new PdfSignatureDetail(
                        signatureValid,
                        true,
                        certificateCurrent,
                        chain.Trusted,
                        chain.RevocationValid,
                        chain.RevocationStatus,
                        revisionEnd == pdf.Length,
                        certificate.GetNameInfo(X509NameType.SimpleName, false),
                        certificate.GetNameInfo(X509NameType.SimpleName, true),
                        certificate.SerialNumber,
                        certificate.Thumbprint,
                        signedAt,
                        certificate.NotBefore,
                        certificate.NotAfter,
                        signer.DigestAlgorithm.FriendlyName ?? signer.DigestAlgorithm.Value,
                        timestamp.Present ? timestamp.Valid : null,
                        timestamp.Timestamp,
                        timestamp.Authority,
                        signatureValid
                            ? null
                            : GetValidationError(
                                certificateCurrent,
                                chain,
                                timestamp));
                })
                .ToArray();
        }
        catch (Exception exception) when (
            exception is CryptographicException
            or FormatException
            or OverflowException
            or ArgumentOutOfRangeException)
        {
            return [new PdfSignatureDetail(
                false,
                false,
                false,
                false,
                false,
                "NoComprobada",
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                GetReadableSignatureError(exception),
                exception.Message)];
        }
    }

    private static string GetReadableSignatureError(Exception exception)
    {
        var message = exception.Message.Trim();
        if (message.StartsWith("El ", StringComparison.Ordinal)
            || message.StartsWith("La ", StringComparison.Ordinal)
            || message.StartsWith("No se ", StringComparison.Ordinal))
        {
            return message;
        }

        return exception switch
        {
            CryptographicException =>
                "La integridad criptográfica no es válida. El contenido del PDF o el bloque de firma pudo ser modificado.",
            FormatException =>
                "El bloque de firma tiene un formato hexadecimal o CMS inválido.",
            OverflowException or ArgumentOutOfRangeException =>
                "La estructura interna de la firma contiene posiciones o tamaños inválidos.",
            _ => "No fue posible interpretar la firma digital incluida en el PDF."
        };
    }

    private static string GetValidationError(
        bool certificateCurrent,
        ChainValidation chain,
        TimestampValidation timestamp)
    {
        if (!certificateCurrent)
        {
            return timestamp.Present && timestamp.Valid == false
                ? $"El certificado no está vigente y el sello de tiempo no es válido: {timestamp.Error}"
                : "El certificado no está vigente y no tiene un sello de tiempo RFC 3161 válido.";
        }

        if (!chain.Trusted || chain.Revoked)
        {
            return chain.Error
                ?? "No fue posible validar completamente la cadena del certificado.";
        }

        if (timestamp.Present && timestamp.Valid == false)
        {
            return $"El sello de tiempo RFC 3161 no es válido: {timestamp.Error}";
        }

        return "La firma no superó todas las validaciones.";
    }

    private static void ValidateByteRange(long[] ranges, int fileLength)
    {
        if (ranges.Length != 4
            || ranges[0] != 0
            || ranges.Any(value => value < 0)
            || ranges[0] + ranges[1] > fileLength
            || ranges[2] + ranges[3] > fileLength
            || ranges[0] + ranges[1] >= ranges[2])
        {
            throw new CryptographicException("El ByteRange de la firma es inválido.");
        }
    }

    private static byte[] TrimDerPadding(byte[] value)
    {
        if (value.Length < 2 || value[0] != 0x30)
        {
            throw new CryptographicException("El contenido de la firma no es CMS/DER.");
        }

        var lengthByte = value[1];
        int headerLength;
        int contentLength;
        if ((lengthByte & 0x80) == 0)
        {
            headerLength = 2;
            contentLength = lengthByte;
        }
        else
        {
            var lengthBytes = lengthByte & 0x7F;
            if (lengthBytes is 0 or > 4 || value.Length < 2 + lengthBytes)
            {
                throw new CryptographicException("La longitud del bloque CMS es inválida.");
            }

            headerLength = 2 + lengthBytes;
            contentLength = 0;
            for (var index = 0; index < lengthBytes; index++)
            {
                contentLength = checked((contentLength << 8) | value[2 + index]);
            }
        }

        var totalLength = checked(headerLength + contentLength);
        if (totalLength > value.Length)
        {
            throw new CryptographicException("El bloque CMS está incompleto.");
        }

        return value[..totalLength];
    }

    private static DateTimeOffset? GetSigningTime(SignerInfo signer)
    {
        var attribute = signer.SignedAttributes
            .Cast<CryptographicAttributeObject>()
            .FirstOrDefault(item => item.Oid?.Value == "1.2.840.113549.1.9.5");
        return attribute?.Values.Count > 0
            ? new DateTimeOffset(new Pkcs9SigningTime(attribute.Values[0].RawData).SigningTime)
            : null;
    }

    private TimestampValidation ValidateTimestamp(SignerInfo signer)
    {
        var attribute = signer.UnsignedAttributes
            .Cast<CryptographicAttributeObject>()
            .FirstOrDefault(item => item.Oid?.Value == SignatureTimestampOid);
        if (attribute is null)
        {
            return TimestampValidation.NotPresent;
        }

        foreach (var value in attribute.Values.Cast<AsnEncodedData>())
        {
            if (!Rfc3161TimestampToken.TryDecode(
                    value.RawData,
                    out var token,
                    out var bytesConsumed)
                || token is null
                || bytesConsumed != value.RawData.Length)
            {
                continue;
            }

            var timestampCms = token.AsSignedCms();
            if (!token.VerifySignatureForSignerInfo(
                    signer,
                    out var authorityCertificate,
                    timestampCms.Certificates)
                || authorityCertificate is null)
            {
                continue;
            }

            var timestamp = token.TokenInfo.Timestamp;
            var authorityChain = ValidateChain(
                authorityCertificate,
                timestampCms.Certificates,
                timestamp.UtcDateTime,
                requireTimestampingEku: true);
            if (authorityChain.Revoked)
            {
                return new TimestampValidation(
                    true,
                    false,
                    timestamp,
                    authorityCertificate.GetNameInfo(X509NameType.SimpleName, false),
                    authorityChain.Error);
            }

            if (!authorityChain.RevocationValid)
            {
                return new TimestampValidation(
                    true,
                    null,
                    timestamp,
                    authorityCertificate.GetNameInfo(X509NameType.SimpleName, false),
                    authorityChain.Error);
            }

            if (!authorityChain.Trusted)
            {
                return new TimestampValidation(
                    true,
                    false,
                    timestamp,
                    authorityCertificate.GetNameInfo(X509NameType.SimpleName, false),
                    authorityChain.Error);
            }

            return new TimestampValidation(
                true,
                true,
                timestamp,
                authorityCertificate.GetNameInfo(X509NameType.SimpleName, false),
                null);
        }

        return new TimestampValidation(
            true,
            false,
            null,
            null,
            "El token no corresponde a la firma o su firma criptográfica es inválida.");
    }

    private ChainValidation ValidateChain(
        X509Certificate2 certificate,
        X509Certificate2Collection certificates,
        DateTime verificationTime,
        bool requireTimestampingEku)
    {
        using var systemTrustChain = CreateChain(
            certificates,
            verificationTime,
            X509RevocationMode.NoCheck,
            requireTimestampingEku,
            useCustomTrust: false);
        var trusted = systemTrustChain.Build(certificate);
        var useCustomTrust = false;

        if (!trusted)
        {
            using var customTrustChain = CreateChain(
                certificates,
                verificationTime,
                X509RevocationMode.NoCheck,
                requireTimestampingEku,
                useCustomTrust: true);
            trusted = customTrustChain.Build(certificate);
            useCustomTrust = trusted;
        }

        using var onlineChain = CreateChain(
            certificates,
            verificationTime,
            X509RevocationMode.Online,
            requireTimestampingEku,
            useCustomTrust);
        var onlineValid = onlineChain.Build(certificate);
        var flags = onlineChain.ChainStatus
            .Select(status => status.Status)
            .Aggregate(X509ChainStatusFlags.NoError, (current, status) => current | status);
        var revoked = flags.HasFlag(X509ChainStatusFlags.Revoked);
        var revocationUnavailable =
            flags.HasFlag(X509ChainStatusFlags.OfflineRevocation)
            || flags.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown);
        var revocationValid = !revoked && !revocationUnavailable;
        var revocationStatus = revoked
            ? "Revocado"
            : revocationUnavailable
                ? "NoDisponible"
                : "SinProblemasDetectados";
        var error = revoked
            ? "El certificado fue revocado por su autoridad certificadora."
            : revocationUnavailable
                ? "No fue posible comprobar la revocación mediante OCSP o CRL."
                : !trusted
                    ? "La cadena del certificado no pertenece a una autoridad de confianza."
                    : !onlineValid
                        ? string.Join(
                            " ",
                            onlineChain.ChainStatus
                                .Select(status => status.StatusInformation.Trim())
                                .Where(message => message.Length > 0))
                        : null;

        return new ChainValidation(
            trusted,
            onlineValid,
            revoked,
            revocationValid,
            revocationStatus,
            error);
    }

    private X509Chain CreateChain(
        X509Certificate2Collection certificates,
        DateTime verificationTime,
        X509RevocationMode revocationMode,
        bool requireTimestampingEku,
        bool useCustomTrust)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = revocationMode;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = RevocationTimeout;
        chain.ChainPolicy.VerificationTime = verificationTime;
        chain.ChainPolicy.DisableCertificateDownloads = false;
        chain.ChainPolicy.ExtraStore.AddRange(certificates);
        if (useCustomTrust)
        {
            trustStore.ApplyCustomTrust(chain.ChainPolicy);
        }
        else
        {
            trustStore.AddIntermediates(chain.ChainPolicy.ExtraStore);
        }

        if (requireTimestampingEku)
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimestampingEkuOid));
        }

        return chain;
    }

    private static void ValidateFile(IFormFile pdf)
    {
        if (pdf.Length == 0)
        {
            throw new StampValidationException("pdf", "Debe enviar un archivo PDF.");
        }

        if (pdf.Length > MaxPdfBytes)
        {
            throw new StampValidationException("pdf", "El PDF no puede superar 10 MB.");
        }

        if (!string.Equals(pdf.ContentType, "application/pdf", StringComparison.OrdinalIgnoreCase))
        {
            throw new StampValidationException("pdf", "El tipo de archivo debe ser application/pdf.");
        }
    }

    private static void ValidatePdfHeader(byte[] bytes)
    {
        if (bytes.Length < 5 || !bytes.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
        {
            throw new StampValidationException("pdf", "El contenido enviado no tiene formato PDF.");
        }
    }

    private sealed record ChainValidation(
        bool Trusted,
        bool OnlineValid,
        bool Revoked,
        bool RevocationValid,
        string RevocationStatus,
        string? Error);

    private sealed record TimestampValidation(
        bool Present,
        bool? Valid,
        DateTimeOffset? Timestamp,
        string? Authority,
        string? Error)
    {
        public static TimestampValidation NotPresent { get; } =
            new(false, false, null, null, null);
    }
}
