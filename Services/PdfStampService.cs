using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using API.Firma.Models;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;
using QRCoder;
using SkiaSharp;

namespace API.Firma.Services;

public sealed class PdfStampService(
    ILogger<PdfStampService> logger,
    QrTokenService qrTokenService,
    Rfc3161TimestampService? timestampService = null)
{
    private static readonly SemaphoreSlim PdfErrorLogLock = new(1, 1);
    private const long MaxPdfBytes = 10 * 1024 * 1024;
    private const long MaxCertificateBytes = 1024 * 1024;
    private const int MaxQrPayloadBytes = 2000;
    private const double StampHeightRatio = 0.39;
    private const double MinimumVisualStampWidthMm = 50.3;
    private const double QrPhysicalWidthMm = 14.5;
    private const double StampLeftPaddingRatio = 0.014;
    private const double StampTextGapPoints = 4;
    private const double StampFontSizePoints = 8;
    private const double StampRasterDpi = 600;
    private const int MaxPlacements = 2;

    public async Task<StampResult> StampAsync(
        StampPdfRequest request,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var placements = ParsePlacements(request);
        logger.LogInformation(
            "Iniciando firma y estampación: PDF {PdfFileName}, tipo {PdfContentType}, {PdfBytes} bytes; certificado {CertificateFileName}, tipo {CertificateContentType}, {CertificateBytes} bytes; clave presente {PasswordPresent}, longitud {PasswordLength}; ubicaciones {PlacementCount}; razón presente {ReasonPresent}; ubicación presente {LocationPresent}",
            Path.GetFileName(request.Pdf.FileName),
            request.Pdf.ContentType,
            request.Pdf.Length,
            Path.GetFileName(request.Certificado.FileName),
            request.Certificado.ContentType,
            request.Certificado.Length,
            !string.IsNullOrEmpty(request.Clave),
            request.Clave.Length,
            placements.Count,
            !string.IsNullOrWhiteSpace(request.Razon),
            !string.IsNullOrWhiteSpace(request.Ubicacion));
        ValidateFile(request.Pdf);
        ValidateCertificateFile(request);
        logger.LogDebug(
            "Etapa validación inicial completada en {ElapsedMs} ms.",
            stopwatch.ElapsedMilliseconds);

        await using var input = new MemoryStream();
        await request.Pdf.CopyToAsync(input, cancellationToken);
        var originalBytes = input.ToArray();
        var bomLength = GetUtf8BomLength(originalBytes);
        if (bomLength > 0)
        {
            logger.LogWarning(
                "El PDF recibido contiene {BomCount} BOM UTF-8; se retirarán antes de validarlo.",
                bomLength / 3);
            originalBytes = originalBytes[bomLength..];
        }

        ValidatePdfHeader(originalBytes);
        var originalHash = Convert.ToHexString(SHA256.HashData(originalBytes));
        var pdfBytesForStamp = originalBytes;
        var pdfWasNormalized = false;
        var usePdfSharpIncrementalFallback = false;
        logger.LogInformation(
            "PDF leído y validado en memoria: {PdfBytes} bytes; SHA-256 {PdfSha256}; cabecera {PdfHeader}; etapa {ElapsedMs} ms",
            originalBytes.Length,
            originalHash,
            Encoding.ASCII.GetString(originalBytes, 0, Math.Min(8, originalBytes.Length)),
            stopwatch.ElapsedMilliseconds);

        if (ContainsPdfEncryption(originalBytes))
        {
            throw new StampValidationException(
                "pdf",
                "El PDF está cifrado o protegido y no puede modificarse de forma segura.",
                diagnosticCode: "PDF_ENCRYPTED");
        }

        try
        {
            IncrementalPdfSignatureAppender.ValidateInput(originalBytes, request.Pagina);
        }
        catch (Exception exception)
        {
            if (ContainsDigitalSignature(originalBytes, inspectPdfStructure: true))
            {
                try
                {
                    IncrementalPdfSignatureAppender.ValidatePdfSharpInput(
                        originalBytes,
                        request.Pagina);
                    usePdfSharpIncrementalFallback = true;
                    logger.LogWarning(
                        exception,
                        "El PDF firmado usa xref/object streams u otra estructura no textual; se conservarán sus bytes y se agregará una revisión incremental compatible.");
                }
                catch (Exception parsedStructureException)
                {
                    var validationException = new StampValidationException(
                        "pdf",
                        "El PDF firmado usa una estructura que no puede modificarse conservando sus firmas.",
                        parsedStructureException,
                        diagnosticCode: "PDF_SIGNED_STRUCTURE_UNSUPPORTED");
                    await PersistPdfErrorAsync(
                        request,
                        originalBytes,
                        "validar estructura firmada",
                        validationException);
                    throw validationException;
                }
            }

            try
            {
                pdfBytesForStamp = NormalizePdf(originalBytes);
                IncrementalPdfSignatureAppender.ValidateInput(
                    pdfBytesForStamp,
                    request.Pagina);
                pdfWasNormalized = true;
                logger.LogWarning(
                    exception,
                    "El PDF original requiere normalización antes de la estampación: {OriginalBytes} bytes; PDF normalizado {NormalizedBytes} bytes",
                    originalBytes.Length,
                    pdfBytesForStamp.Length);
            }
            catch (Exception normalizationException)
            {
                var validationException = new StampValidationException(
                    "pdf",
                    "El PDF no tiene una estructura compatible para ser modificado.",
                    normalizationException,
                    diagnosticCode: "PDF_STRUCTURE_UNSUPPORTED");
                await PersistPdfErrorAsync(
                    request,
                    originalBytes,
                    "normalizar PDF",
                    validationException);
                throw validationException;
            }
        }

        await using var certificateStream = request.Certificado.OpenReadStream();
        using var certificateInput = new MemoryStream();
        await certificateStream.CopyToAsync(certificateInput, cancellationToken);
        var certificateBytes = certificateInput.ToArray();
        var certificateSha256 = Convert.ToHexString(
            SHA256.HashData(certificateBytes));
        logger.LogInformation(
            "Certificado PKCS#12 recibido: nombre original {OriginalFileName}, longitud {CertificateBytes} bytes, SHA-256 {CertificateSha256}; almacenamiento {CertificateStorage}",
            request.Certificado.FileName,
            certificateBytes.Length,
            certificateSha256,
            "memory");
        if (certificateBytes.Length == 0)
        {
            throw new StampValidationException(
                "certificado",
                "Debe enviar un certificado P12 o PFX.");
        }

        using var certificateBundle = LoadCertificates(
            certificateBytes,
            request.Clave);
        var certificate = certificateBundle.SigningCertificate;
        ValidateCertificate(certificate);
        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault()?.KeyUsages.ToString() ?? "sin extensión KeyUsage";
        logger.LogInformation(
            "PKCS#12 abierto correctamente en {ElapsedMs} ms: {CertificateCount} certificado(s); seleccionado sujeto {Subject}; emisor {Issuer}; serie {SerialNumber}; huella {Thumbprint}; válido UTC {NotBefore:o} a {NotAfter:o}; algoritmo de clave {PublicKeyAlgorithm}; algoritmo de firma {SignatureAlgorithm}; clave privada {HasPrivateKey}; KeyUsage {KeyUsage}",
            stopwatch.ElapsedMilliseconds,
            certificateBundle.Certificates.Count,
            certificate.Subject,
            certificate.Issuer,
            certificate.SerialNumber,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            certificate.PublicKey.Oid.Value,
            certificate.SignatureAlgorithm.Value,
            certificate.HasPrivateKey,
            keyUsage);
        foreach (var bundledCertificate in certificateBundle.Certificates)
        {
            logger.LogDebug(
                "Certificado incluido en PKCS#12: sujeto {Subject}; emisor {Issuer}; serie {SerialNumber}; huella {Thumbprint}; clave privada {HasPrivateKey}; vigencia UTC {NotBefore:o} a {NotAfter:o}",
                bundledCertificate.Subject,
                bundledCertificate.Issuer,
                bundledCertificate.SerialNumber,
                bundledCertificate.Thumbprint,
                bundledCertificate.HasPrivateKey,
                bundledCertificate.NotBefore.ToUniversalTime(),
                bundledCertificate.NotAfter.ToUniversalTime());
        }

        var signatureData = CreateSignatureData(certificate);

        var signedAt = DateTimeOffset.Now;
        var qrPayload = qrTokenService.CreatePlainText(
            signatureData,
            signedAt.ToUniversalTime());
        ValidateQrPayloadSize(qrPayload);
        var qr = CreateQr(qrPayload);
        var requestedStampWidthMm = placements[0].AnchoMm;
        var stampWidthMm = Math.Max(
            requestedStampWidthMm,
            MinimumVisualStampWidthMm);
        var placement = placements[0] with { AnchoMm = stampWidthMm };
        var qrModuleSizeMm = QrPhysicalWidthMm / qr.ModuleCount;
        logger.LogInformation(
            "QR calculado: contenido {PayloadBytes} bytes, {QrModules} módulos, módulo físico estimado {ModuleSizeMm:0.000} mm",
            Encoding.UTF8.GetByteCount(qrPayload),
            qr.ModuleCount,
            qrModuleSizeMm);
        var stampPng = CreateStampImage(
            qr.Png,
            signatureData,
            stampWidthMm);
        logger.LogInformation(
            "QR y sello generados: QR {QrBytes} bytes, {QrModules} módulos, sello {StampBytes} bytes",
            qr.Png.Length,
            qr.ModuleCount,
            stampPng.Length);

        var processingStage = "preparar firma";
        try
        {
            processingStage = ContainsDigitalSignature(pdfBytesForStamp)
                ? "agregar firma incremental"
                : "crear primera firma incremental";
            var outputBytes = await IncrementalPdfSignatureAppender.AppendAsync(
                pdfBytesForStamp,
                certificate,
                certificateBundle.Certificates,
                stampPng,
                placement,
                request.Razon,
                request.Ubicacion,
                timestampService,
                cancellationToken,
                usePdfSharpIncrementalFallback);
            var outputHash = Convert.ToHexString(SHA256.HashData(outputBytes));
            logger.LogInformation(
                "PDF estampado y firmado incrementalmente en {ElapsedMs} ms: entrada {InputBytes} bytes; normalizado {PdfWasNormalized}; salida {OutputBytes} bytes; diferencia {SizeDelta} bytes; SHA-256 salida {OutputSha256}; certificado {Thumbprint}; contiene ByteRange {HasByteRange}; contiene filtro Adobe.PPKLite {HasAdobeFilter}",
                stopwatch.ElapsedMilliseconds,
                pdfBytesForStamp.Length,
                pdfWasNormalized,
                outputBytes.Length,
                outputBytes.Length - pdfBytesForStamp.Length,
                outputHash,
                certificate.Thumbprint,
                outputBytes.AsSpan().IndexOf("/ByteRange"u8) >= 0,
                outputBytes.AsSpan().IndexOf("/Adobe.PPKLite"u8) >= 0);

            return new StampResult(
                outputBytes,
                originalHash,
                outputHash);
        }
        catch (StampValidationException exception)
        {
            await PersistPdfErrorAsync(
                request,
                originalBytes,
                processingStage,
                exception);
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Falló la etapa {ProcessingStage} tras {ElapsedMs} ms. Excepción {ExceptionType}; HResult 0x{HResult:X8}; mensaje {ExceptionMessage}; interna {InnerExceptionType}: {InnerExceptionMessage}",
                processingStage,
                stopwatch.ElapsedMilliseconds,
                exception.GetType().FullName,
                exception.HResult,
                exception.Message,
                exception.InnerException?.GetType().FullName ?? "ninguna",
                exception.InnerException?.Message ?? "ninguno");
            await PersistPdfErrorAsync(
                request,
                originalBytes,
                processingStage,
                exception);
            throw new StampValidationException(
                "pdf",
                "El archivo no es un PDF válido, está protegido o no puede modificarse.",
                exception);
        }
    }

    private async Task PersistPdfErrorAsync(
        StampPdfRequest request,
        byte[]? pdfBytes,
        string processingStage,
        Exception exception)
    {
        try
        {
            var localAppData = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData))
            {
                localAppData = AppContext.BaseDirectory;
            }

            var logDirectory = Path.Combine(localAppData, "API.Firma", "Logs");
            var failedPdfDirectory = Path.Combine(logDirectory, "FailedPdfs");
            Directory.CreateDirectory(logDirectory);
            Directory.CreateDirectory(failedPdfDirectory);
            var logPath = Path.Combine(logDirectory, "pdf-errors.log");
            var diagnosticCode = exception is StampValidationException validationException
                ? validationException.DiagnosticCode ?? "no disponible"
                : "no disponible";
            var pdfHash = pdfBytes is null
                ? "no disponible"
                : Convert.ToHexString(SHA256.HashData(pdfBytes));
            var failedPdfPath = pdfBytes is null
                ? "no disponible"
                : Path.Combine(
                    failedPdfDirectory,
                    $"pdf-error-{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.pdf");
            var entry = string.Join(
                Environment.NewLine,
                $"[{DateTimeOffset.UtcNow:O}]",
                $"Etapa: {processingStage}",
                $"PDF: {Path.GetFileName(request.Pdf.FileName)}",
                $"Bytes: {request.Pdf.Length}",
                $"Página: {request.Pagina}",
                $"SHA-256: {pdfHash}",
                $"Código: {diagnosticCode}",
                $"PDF guardado: {failedPdfPath}",
                $"Excepción: {exception}",
                new string('-', 100),
                string.Empty);

            await PdfErrorLogLock.WaitAsync();
            try
            {
                if (pdfBytes is not null && failedPdfPath != "no disponible")
                {
                    await File.WriteAllBytesAsync(failedPdfPath, pdfBytes);
                }

                await File.AppendAllTextAsync(logPath, entry, Encoding.UTF8);
            }
            finally
            {
                PdfErrorLogLock.Release();
            }

            logger.LogInformation(
                "Diagnóstico PDF guardado en {PdfErrorLogPath}.",
                logPath);
        }
        catch (Exception logException)
        {
            logger.LogError(
                logException,
                "No se pudo guardar el diagnóstico del PDF en AppData.");
        }
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

    }

    private static void ValidatePdfHeader(byte[] bytes)
    {
        ReadOnlySpan<byte> pdfMagic = "%PDF-"u8;
        if (bytes.Length < pdfMagic.Length
            || !bytes.AsSpan(0, pdfMagic.Length).SequenceEqual(pdfMagic))
        {
            throw new StampValidationException("pdf", "El contenido enviado no tiene formato PDF.");
        }
    }

    private static int GetUtf8BomLength(byte[] bytes)
    {
        var length = 0;
        while (bytes.Length - length >= 3
            && bytes[length] == 0xEF
            && bytes[length + 1] == 0xBB
            && bytes[length + 2] == 0xBF)
        {
            length += 3;
        }

        return length;
    }

    private static bool ContainsDigitalSignature(
        byte[] bytes,
        bool inspectPdfStructure = false)
    {
        if (bytes.AsSpan().IndexOf("/ByteRange"u8) >= 0
            || bytes.AsSpan().IndexOf("/Type /Sig"u8) >= 0
            || bytes.AsSpan().IndexOf("/FT /Sig"u8) >= 0)
        {
            return true;
        }

        if (!inspectPdfStructure)
        {
            return false;
        }

        try
        {
            using var input = new MemoryStream(bytes, writable: false);
            using var document = PdfReader.Open(input, PdfDocumentOpenMode.Import);
            return document.Internals.GetAllObjects().Any(pdfObject =>
            {
                var text = pdfObject?.ToString() ?? string.Empty;
                return text.Contains("/ByteRange", StringComparison.Ordinal)
                    || text.Contains("/Type /Sig", StringComparison.Ordinal)
                    || text.Contains("/FT /Sig", StringComparison.Ordinal);
            });
        }
        catch
        {
            return true;
        }
    }

    private static bool ContainsPdfEncryption(byte[] bytes) =>
        Regex.IsMatch(
            Encoding.Latin1.GetString(bytes),
            @"(?m)/Encrypt\s+\d+\s+\d+\s+R\b",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2));

    private static byte[] NormalizePdf(byte[] originalPdf)
    {
        using var input = new MemoryStream(originalPdf, writable: false);
        using var document = PdfReader.Open(input, PdfDocumentOpenMode.Modify);
        using var output = new MemoryStream();
        document.Save(output, closeStream: false);
        return output.ToArray();
    }

    private static void ValidateCertificateFile(StampPdfRequest request)
    {
        if (request.Certificado.Length == 0)
        {
            throw new StampValidationException(
                "certificado",
                "Debe enviar un certificado P12 o PFX.");
        }

        if (request.Certificado.Length > MaxCertificateBytes)
        {
            throw new StampValidationException(
                "certificado",
                "El certificado no puede superar 1 MB.");
        }

        var extension = Path.GetExtension(request.Certificado.FileName);
        if (!string.Equals(extension, ".p12", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(extension, ".pfx", StringComparison.OrdinalIgnoreCase))
        {
            throw new StampValidationException(
                "certificado",
                "El certificado debe tener extensión .p12 o .pfx.");
        }

        if (string.IsNullOrEmpty(request.Clave))
        {
            throw new StampValidationException(
                "clave",
                "Debe enviar la clave del certificado.");
        }
    }

    private CertificateBundle LoadCertificates(
        byte[] certificateBytes,
        string password)
    {
        try
        {
            if (X509Certificate2.GetCertContentType(certificateBytes)
                != X509ContentType.Pkcs12)
            {
                throw new StampValidationException(
                    "certificado",
                    "El contenido enviado no es un certificado P12/PFX. Envíe el archivo binario original, no su texto Base64.",
                    diagnosticCode: "PFX_FORMAT_INVALID");
            }
        }
        catch (CryptographicException exception)
        {
            logger.LogWarning(
                exception,
                "El archivo de certificado recibido ({CertificateBytes} bytes) no tiene formato PKCS#12.",
                certificateBytes.Length);
            throw new StampValidationException(
                "certificado",
                "El contenido enviado no es un certificado P12/PFX. Envíe el archivo binario original, no su texto Base64.",
                exception,
                "PFX_FORMAT_INVALID",
                FormatCryptographicErrorCode(exception));
        }

        try
        {
            return LoadCertificateBundle(
                certificateBytes,
                password,
                X509KeyStorageFlags.EphemeralKeySet
                    | X509KeyStorageFlags.Exportable);
        }
        catch (Pkcs12LoadLimitExceededException exception)
        {
            logger.LogWarning(
                exception,
                "El certificado PKCS#12 excede los límites seguros del cargador.");
            throw new StampValidationException(
                "certificado",
                "El certificado P12/PFX excede los límites de seguridad permitidos. Vuelva a exportarlo e intente nuevamente.",
                exception,
                "PFX_LOAD_LIMIT_EXCEEDED");
        }
        catch (CryptographicException exception)
            when (RequiresMachineKeySetRetry(exception.HResult))
        {
            logger.LogWarning(
                exception,
                "El proveedor criptográfico no pudo abrir la clave efímera. Se reintentará con almacenamiento temporal del equipo.");

            try
            {
                return LoadCertificateBundle(
                    certificateBytes,
                    password,
                    X509KeyStorageFlags.MachineKeySet
                        | X509KeyStorageFlags.Exportable);
            }
            catch (Pkcs12LoadLimitExceededException retryException)
            {
                logger.LogWarning(
                    retryException,
                    "El certificado PKCS#12 excede los límites seguros del cargador.");
                throw new StampValidationException(
                    "certificado",
                    "El certificado P12/PFX excede los límites de seguridad permitidos. Vuelva a exportarlo e intente nuevamente.",
                    retryException,
                    "PFX_LOAD_LIMIT_EXCEEDED");
            }
            catch (CryptographicException retryException)
            {
                throw CreatePkcs12LoadException(retryException);
            }
        }
        catch (CryptographicException exception)
        {
            throw CreatePkcs12LoadException(exception);
        }

        StampValidationException CreatePkcs12LoadException(
            CryptographicException exception)
        {
            logger.LogWarning(
                exception,
                "No se pudo abrir el certificado PKCS#12 ({CertificateBytes} bytes). Excepción {ExceptionType}, HResult 0x{ErrorCode:X8}, mensaje {ExceptionMessage}",
                certificateBytes.Length,
                exception.GetType().FullName,
                exception.HResult,
                exception.Message);
            return new StampValidationException(
                "certificado",
                "No se pudo abrir el certificado P12/PFX. Verifique que la clave sea exacta, sin comillas ni codificación URL.",
                exception,
                ClassifyPkcs12LoadError(exception),
                FormatCryptographicErrorCode(exception));
        }
    }

    private static CertificateBundle LoadCertificateBundle(
        byte[] certificateBytes,
        string password,
        X509KeyStorageFlags keyStorageFlags)
    {
        var certificates = X509CertificateLoader.LoadPkcs12Collection(
            certificateBytes,
            password,
            keyStorageFlags);
        var signingCertificate = certificates
            .Cast<X509Certificate2>()
            .Where(item => item.HasPrivateKey)
            .OrderByDescending(IsUsableForDigitalSignature)
            .ThenByDescending(item => item.NotAfter)
            .FirstOrDefault()
            ?? certificates.Cast<X509Certificate2>().FirstOrDefault()
            ?? throw new CryptographicException(
                "El archivo PKCS#12 no contiene certificados.");
        return new CertificateBundle(certificates, signingCertificate);
    }

    internal static bool RequiresMachineKeySetRetry(int hResult) =>
        hResult == unchecked((int)0x80070002);

    private static string ClassifyPkcs12LoadError(CryptographicException exception)
    {
        const int invalidPassword = unchecked((int)0x80070056);
        const int badAlgorithm = unchecked((int)0x80090008);

        if (exception.HResult == invalidPassword
            || exception.Message.Contains("password", StringComparison.OrdinalIgnoreCase)
            || exception.Message.Contains("contraseña", StringComparison.OrdinalIgnoreCase))
        {
            return "PFX_PASSWORD_REJECTED";
        }

        if (exception.HResult == badAlgorithm
            || exception.Message.Contains("unsupported", StringComparison.OrdinalIgnoreCase)
            || exception.Message.Contains("not supported", StringComparison.OrdinalIgnoreCase)
            || exception.Message.Contains("algorithm", StringComparison.OrdinalIgnoreCase)
            || exception.Message.Contains("algoritmo", StringComparison.OrdinalIgnoreCase))
        {
            return "PFX_ALGORITHM_NOT_SUPPORTED";
        }

        return "PFX_LOAD_FAILED";
    }

    private static string FormatCryptographicErrorCode(CryptographicException exception) =>
        $"0x{unchecked((uint)exception.HResult):X8}";

    private static void ValidateCertificate(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new StampValidationException(
                "certificado",
                "El certificado no contiene una clave privada.");
        }

        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime()
            || now > certificate.NotAfter.ToUniversalTime())
        {
            throw new StampValidationException(
                "certificado",
                "El certificado no está vigente.");
        }

        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();
        if (keyUsage is not null
            && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)
            && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            throw new StampValidationException(
                "certificado",
                "El certificado no permite realizar firmas digitales.");
        }
    }

    private static bool IsUsableForDigitalSignature(X509Certificate2 certificate)
    {
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime()
            || now > certificate.NotAfter.ToUniversalTime())
        {
            return false;
        }

        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();
        return keyUsage is null
            || keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)
            || keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation);
    }

    private static JsonElement CreateSignatureData(X509Certificate2 certificate)
    {
        var identification = GetSubjectValue(
            certificate.SubjectName,
            "SERIALNUMBER");
        return JsonSerializer.SerializeToElement(new
        {
            n = certificate.GetNameInfo(
                X509NameType.SimpleName,
                forIssuer: false),
            i = identification
        });
    }

    private static string? GetSubjectValue(
        X500DistinguishedName subject,
        string attributeName)
    {
        var decoded = subject.Decode(
            X500DistinguishedNameFlags.UseNewLines
            | X500DistinguishedNameFlags.DoNotUseQuotes);
        foreach (var line in decoded.Split(
                     ['\r', '\n'],
                     StringSplitOptions.RemoveEmptyEntries
                     | StringSplitOptions.TrimEntries))
        {
            var separator = line.IndexOf('=');
            if (separator > 0
                && string.Equals(
                    line[..separator].Trim(),
                    attributeName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return line[(separator + 1)..].Trim();
            }
        }

        return null;
    }

    private static void ValidateQrPayloadSize(string payload)
    {
        if (Encoding.UTF8.GetByteCount(payload) > MaxQrPayloadBytes)
        {
            throw new StampValidationException(
                "certificado",
                "Los datos del certificado exceden la capacidad legible del QR.");
        }
    }

    private static GeneratedQr CreateQr(string payload)
    {
        using var data = QRCodeGenerator.GenerateQrCode(
            payload,
            QRCodeGenerator.ECCLevel.L,
            forceUtf8: true,
            utf8BOM: false);
        using var pngQr = new PngByteQRCode(data);
        return new GeneratedQr(
            pngQr.GetGraphic(40, drawQuietZones: true),
            data.ModuleMatrix.Count);
    }

    private static byte[] CreateStampImage(
        byte[] qrPng,
        JsonElement data,
        double stampWidthMm)
    {
        using var qr = SKBitmap.Decode(qrPng)
            ?? throw new InvalidOperationException("No fue posible componer el sello.");

        var stampWidthPoints = stampWidthMm * 72d / 25.4d;
        var qrWidthPoints = QrPhysicalWidthMm * 72d / 25.4d;
        var naturalStampWidth =
            qr.Width * stampWidthPoints / qrWidthPoints;
        var maxStampWidth = stampWidthPoints * StampRasterDpi / 72d;
        var stampWidth = (int)Math.Ceiling(
            Math.Min(naturalStampWidth, maxStampWidth));
        var imageScale = stampWidth / naturalStampWidth;
        var stampHeight = (int)Math.Ceiling(stampWidth * StampHeightRatio);
        var stampHeightPoints = stampWidthMm * 72d / 25.4d * StampHeightRatio;
        var stampFontSize = (float)(StampFontSizePoints * stampHeight / stampHeightPoints);
        var leftPadding = Math.Max(
            2,
            (int)Math.Ceiling(stampWidth * StampLeftPaddingRatio));
        var textGap = Math.Max(
            4,
            (int)Math.Ceiling(
                StampTextGapPoints * stampWidth / stampWidthPoints));
        using var stamp = new SKBitmap(stampWidth, stampHeight);
        using var canvas = new SKCanvas(stamp);
        canvas.Clear(SKColors.White);

        var qrLeft = leftPadding;
        var qrDisplayWidth = Math.Max(1, (int)Math.Round(qr.Width * imageScale));
        var qrDisplayHeight = Math.Max(1, (int)Math.Round(qr.Height * imageScale));
        var qrTop = (stampHeight - qrDisplayHeight) / 2f;
        canvas.DrawBitmap(
            qr,
            new SKRect(
                qrLeft,
                qrTop,
                qrLeft + qrDisplayWidth,
                qrTop + qrDisplayHeight),
            new SKSamplingOptions(SKFilterMode.Nearest, SKMipmapMode.None),
            null);

        var contentLeft = qrLeft + qrDisplayWidth + textGap;
        var contentRight = stampWidth * 0.93f;
        var availableWidth = contentRight - contentLeft;
        var holderName = GetText(data, "n");
        if (!string.IsNullOrWhiteSpace(holderName))
        {
            using var labelTypeface = SKTypeface.FromFamilyName("Arial", SKFontStyle.Normal);
            const string labelText = "Firmado electrónicamente por:";
            using var labelBaseFont = new SKFont(labelTypeface, stampFontSize);
            var labelWidth = labelBaseFont.MeasureText(labelText);
            var labelFontSize = labelWidth > availableWidth
                ? stampFontSize * (availableWidth / labelWidth)
                : stampFontSize;
            using var labelFont = new SKFont(
                labelTypeface,
                labelFontSize);
            using var labelPaint = new SKPaint
            {
                Color = SKColors.Black,
                IsAntialias = true
            };
            canvas.DrawText(
                labelText,
                contentLeft,
                stampHeight * 0.30f,
                SKTextAlign.Left,
                labelFont,
                labelPaint);

            using var typeface = SKTypeface.FromFamilyName("Arial", SKFontStyle.Normal);
            using var initialFont = new SKFont(
                typeface,
                stampFontSize);
            var nameLines = SplitNameIntoLines(
                holderName,
                initialFont,
                availableWidth);
            var widestLine = nameLines.Max(
                line => initialFont.MeasureText(line));
            var nameFontSize = widestLine > availableWidth
                ? initialFont.Size * (availableWidth / widestLine)
                : initialFont.Size;
            using var nameFont = new SKFont(typeface, nameFontSize);
            using var namePaint = new SKPaint
            {
                Color = SKColors.Black,
                IsAntialias = true
            };

            var firstBaseline = nameLines.Length == 1 ? 0.54f : 0.46f;
            var lineSpacing = nameLines.Length == 1 ? 0 : 0.16f;
            for (var index = 0; index < nameLines.Length; index++)
            {
                canvas.DrawText(
                    nameLines[index],
                    contentLeft,
                    stampHeight * (firstBaseline + (lineSpacing * index)),
                    SKTextAlign.Left,
                    nameFont,
                    namePaint);
            }
        }

        using var image = SKImage.FromBitmap(stamp);
        using var encoded = image.Encode(SKEncodedImageFormat.Png, 100);
        return encoded.ToArray();
    }

    private static IReadOnlyList<StampPlacement> ParsePlacements(StampPdfRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Posiciones))
        {
            return
            [
                new StampPlacement(request.Pagina, request.XMm, request.YMm, request.AnchoMm)
            ];
        }

        List<StampPlacement>? placements;
        try
        {
            placements = JsonSerializer.Deserialize<List<StampPlacement>>(
                request.Posiciones,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException exception)
        {
            throw new StampValidationException(
                "posiciones",
                "La lista de posiciones no tiene un formato válido.",
                exception);
        }

        if (placements is null || placements.Count is < 1 or > MaxPlacements)
        {
            throw new StampValidationException(
                "posiciones",
                $"Debe enviar entre 1 y {MaxPlacements} posiciones de firma.");
        }

        return placements.ToArray();
    }

    private static void ValidatePlacements(
        IReadOnlyList<StampPlacement> placements,
        PdfDocument document)
    {
        for (var index = 0; index < placements.Count; index++)
        {
            var placement = placements[index];
            if (placement.Pagina < 1 || placement.Pagina > document.PageCount)
            {
                throw new StampValidationException(
                    $"posiciones[{index}].pagina",
                    $"El PDF tiene {document.PageCount} página(s); la página solicitada no existe.");
            }

            if (placement.XMm < 0 || placement.XMm > 2000
                || placement.YMm < 0 || placement.YMm > 2000)
            {
                throw new StampValidationException(
                    $"posiciones[{index}]",
                    "X e Y deben estar entre 0 y 2000 mm.");
            }

            if (placement.AnchoMm is < 40 or > 160)
            {
                throw new StampValidationException(
                    $"posiciones[{index}].anchoMm",
                    "El ancho debe estar entre 40 y 160 mm.");
            }

            if (placement.Rotacion is not (0 or 90 or 180 or 270))
            {
                throw new StampValidationException(
                    $"posiciones[{index}].rotacion",
                    "La rotación debe ser 0, 90, 180 o 270 grados.");
            }

            var page = document.Pages[placement.Pagina - 1];
            var rotation = ResolveRotation(placement, page.Width.Point, page.Height.Point);
            var width = XUnit.FromMillimeter(placement.AnchoMm);
            var height = width * StampHeightRatio;
            var boundsWidth = rotation is 90 or 270 ? height : width;
            var boundsHeight = rotation is 90 or 270 ? width : height;
            var x = XUnit.FromMillimeter(placement.XMm);
            var y = XUnit.FromMillimeter(placement.YMm);
            if (x.Point + boundsWidth.Point > page.Width.Point
                || y.Point + boundsHeight.Point > page.Height.Point)
            {
                throw new StampValidationException(
                    $"posiciones[{index}]",
                    "El sello no cabe en la página con las coordenadas y el ancho indicados.");
            }
        }
    }

    private static int ResolveRotation(
        StampPlacement placement,
        double pageWidthPoints,
        double pageHeightPoints) =>
        placement.Rotacion == 0 && pageWidthPoints > pageHeightPoints
            ? 90
            : placement.Rotacion;

    private static void DrawStamp(
        XGraphics graphics,
        XImage image,
        double x,
        double y,
        double width,
        double height,
        double boundsWidth,
        double boundsHeight,
        int rotation)
    {
        if (rotation == 0)
        {
            graphics.DrawImage(image, x, y, width, height);
            return;
        }

        var state = graphics.Save();
        graphics.TranslateTransform(x + (boundsWidth / 2), y + (boundsHeight / 2));
        graphics.RotateTransform(rotation);
        graphics.DrawImage(image, -(width / 2), -(height / 2), width, height);
        graphics.Restore(state);
    }

    private static string? GetText(JsonElement data, string propertyName)
    {
        foreach (var property in data.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                return property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString()
                    : property.Value.ToString();
            }
        }

        return null;
    }

    private static string[] SplitNameIntoLines(
        string value,
        SKFont font,
        float maxWidth)
    {
        var normalized = string.Join(
            ' ',
            value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries));
        if (font.MeasureText(normalized) <= maxWidth)
        {
            return [normalized];
        }

        var words = normalized.Split(' ');
        if (words.Length < 2)
        {
            return [normalized];
        }

        if (words.Length >= 3)
        {
            return
            [
                string.Join(' ', words[..^1]),
                words[^1]
            ];
        }

        var bestSplit = 1;
        var bestScore = float.MaxValue;
        for (var index = 1; index < words.Length; index++)
        {
            var firstLine = string.Join(' ', words[..index]);
            var secondLine = string.Join(' ', words[index..]);
            var firstWidth = font.MeasureText(firstLine);
            var secondWidth = font.MeasureText(secondLine);
            var score = Math.Max(firstWidth, secondWidth)
                + (Math.Abs(firstWidth - secondWidth) * 0.15f);
            if (score < bestScore)
            {
                bestScore = score;
                bestSplit = index;
            }
        }

        return
        [
            string.Join(' ', words[..bestSplit]),
            string.Join(' ', words[bestSplit..])
        ];
    }

    private sealed record GeneratedQr(byte[] Png, int ModuleCount);

    private sealed class CertificateBundle(
        X509Certificate2Collection certificates,
        X509Certificate2 signingCertificate) : IDisposable
    {
        public X509Certificate2Collection Certificates { get; } = certificates;

        public X509Certificate2 SigningCertificate { get; } = signingCertificate;

        public void Dispose()
        {
            foreach (var certificate in Certificates)
            {
                certificate.Dispose();
            }
        }
    }

}
