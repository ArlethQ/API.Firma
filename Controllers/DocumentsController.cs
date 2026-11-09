using API.Firma.Models;
using API.Firma.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace API.Firma.Controllers;

[ApiController]
[Route("api/documentos")]
[EnableRateLimiting("firma")]
public sealed class DocumentsController(
    PdfStampService pdfStampService,
    PdfSignatureValidationService signatureValidationService,
    ILogger<DocumentsController> logger) : ControllerBase
{
    /// <summary>
    /// Valida las firmas digitales CMS/PAdES contenidas en un PDF.
    /// </summary>
    /// <remarks>
    /// Comprueba la integridad de cada firma, la cobertura del documento, la cadena
    /// del certificado, su revocación mediante OCSP/CRL y los sellos de tiempo RFC 3161.
    /// Envíe el archivo como multipart/form-data en el campo <c>pdf</c>.
    /// Un HTTP 200 puede contener <c>valido: false</c>; esto representa una validación
    /// ejecutada correctamente sobre un documento sin firma o con una firma inválida.
    /// </remarks>
    /// <response code="200">Resultado detallado de todas las firmas encontradas.</response>
    /// <response code="400">El archivo falta, está vacío, excede 10 MB o no es un PDF.</response>
    /// <response code="401">La API key falta o es inválida.</response>
    /// <response code="403">La dirección IP no está autorizada.</response>
    /// <response code="413">La solicitud excede el límite permitido.</response>
    /// <response code="429">Se superó el límite de solicitudes.</response>
    [HttpPost("validar-firma")]
    [Consumes("multipart/form-data")]
    [Produces("application/json")]
    [ProducesResponseType<PdfSignatureValidationResult>(StatusCodes.Status200OK)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests)]
    [RequestFormLimits(MultipartBodyLengthLimit = 15 * 1024 * 1024)]
    [RequestSizeLimit(15 * 1024 * 1024)]
    public async Task<IActionResult> ValidateSignature(
        [FromForm] ValidatePdfSignatureRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await signatureValidationService.ValidateAsync(
                request.Pdf,
                cancellationToken);
            return Ok(result);
        }
        catch (StampValidationException exception)
        {
            ModelState.AddModelError(exception.Field, exception.Message);
            return ApiValidationProblemFactory.Create(HttpContext, ModelState, exception);
        }
    }

    /// <summary>
    /// Estampa el QR y firma digitalmente el PDF en una sola operación.
    /// </summary>
    /// <remarks>
    /// Envía el PDF, certificado P12/PFX, clave y posición como
    /// multipart/form-data. Los datos del firmante se obtienen del certificado;
    /// la clave privada se usa únicamente en memoria y no se almacena.
    /// </remarks>
    [HttpPost("estampar")]
    [Consumes("multipart/form-data")]
    [Produces("application/pdf")]
    [ProducesResponseType<FileContentResult>(StatusCodes.Status200OK)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests)]
    [RequestFormLimits(MultipartBodyLengthLimit = 15 * 1024 * 1024)]
    [RequestSizeLimit(15 * 1024 * 1024)]
    public async Task<IActionResult> Stamp(
        [FromForm] StampPdfRequest request,
        CancellationToken cancellationToken)
    {
        if (request?.Pdf is null || request.Certificado is null)
        {
            ModelState.AddModelError(
                "pdf",
                "Debe enviar el PDF y el certificado para estampar el documento.");
            return ApiValidationProblemFactory.Create(HttpContext, ModelState);
        }

        logger.LogInformation(
            "Procesando firma y estampación {RequestId}: PDF {PdfBytes} bytes, certificado {CertificateBytes} bytes, página {Page}",
            HttpContext.TraceIdentifier,
            request.Pdf.Length,
            request.Certificado.Length,
            request.Pagina);

        try
        {
            var result = await pdfStampService.StampAsync(request, cancellationToken);
            logger.LogInformation(
                "Firma y estampación {RequestId} completadas: PDF de salida {OutputBytes} bytes; SHA-256 original {OriginalSha256}; SHA-256 salida {OutputSha256}; respuesta application/pdf",
                HttpContext.TraceIdentifier,
                result.Pdf.Length,
                result.OriginalSha256,
                result.OutputSha256);

            Response.Headers.Append("X-Documento-Original-SHA256", result.OriginalSha256);
            Response.Headers.Append("X-Documento-Salida-SHA256", result.OutputSha256);
            Response.Headers.Append(
                "Content-Disposition",
                "attachment; filename=\"documento-firmado-estampado.pdf\"");

            return File(result.Pdf, "application/pdf");
        }
        catch (StampValidationException exception)
        {
            logger.LogWarning(
                exception,
                "Firma y estampación {RequestId} rechazada: campo {Field}; código diagnóstico {DiagnosticCode}; código criptográfico {CryptographicErrorCode}; excepción {ExceptionType}; HResult 0x{HResult:X8}; mensaje {ExceptionMessage}; interna {InnerExceptionType}: {InnerExceptionMessage}",
                HttpContext.TraceIdentifier,
                exception.Field,
                exception.DiagnosticCode ?? "no disponible",
                exception.CryptographicErrorCode ?? "no disponible",
                exception.GetType().FullName,
                exception.HResult,
                exception.Message,
                exception.InnerException?.GetType().FullName ?? "ninguna",
                exception.InnerException?.Message ?? "ninguno");
            ModelState.AddModelError(exception.Field, exception.Message);
            return ApiValidationProblemFactory.Create(HttpContext, ModelState, exception);
        }
    }
}
