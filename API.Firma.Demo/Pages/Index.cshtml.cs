using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace API.Firma.Demo.Pages;

public sealed class IndexModel(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    ILogger<IndexModel> logger) : PageModel
{
    [BindProperty]
    [Required(ErrorMessage = "Ingrese la API key.")]
    [StringLength(256, MinimumLength = 32, ErrorMessage = "La API key debe tener entre 32 y 256 caracteres.")]
    public string ApiKey { get; set; } = string.Empty;

    [BindProperty]
    [Required(ErrorMessage = "Seleccione un PDF.")]
    public IFormFile? Pdf { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Seleccione un certificado P12 o PFX.")]
    public IFormFile? CertificadoFirma { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Ingrese la clave del certificado.")]
    public string ClaveCertificado { get; set; } = string.Empty;

    [BindProperty]
    [StringLength(200)]
    public string? RazonFirma { get; set; } = "Firma digital del documento";

    [BindProperty]
    [StringLength(200)]
    public string? UbicacionFirma { get; set; }

    [BindProperty]
    [Range(1, int.MaxValue, ErrorMessage = "La página debe ser mayor que cero.")]
    public int Pagina { get; set; } = 1;

    [BindProperty]
    [Range(0, 2000, ErrorMessage = "X debe estar entre 0 y 2000 mm.")]
    public double XMm { get; set; }

    [BindProperty]
    [Range(0, 2000, ErrorMessage = "Y debe estar entre 0 y 2000 mm.")]
    public double YMm { get; set; }

    [BindProperty]
    [Range(56, 160, ErrorMessage = "El ancho debe estar entre 56 y 160 mm.")]
    public double AnchoMm { get; set; } = 70;

    [BindProperty]
    public bool PosicionSeleccionada { get; set; }

    [BindProperty]
    public string? QrEntrada { get; set; }

    [BindProperty]
    public IFormFile? PdfValidacion { get; set; }

    public string? ErrorMessage { get; private set; }

    public string? QrErrorMessage { get; private set; }

    public string? SignatureErrorMessage { get; private set; }

    public QrVerificationResponse? QrVerification { get; private set; }

    public PdfSignatureValidationResponse? SignatureValidation { get; private set; }

    public string? QrDatosJson => QrVerification is null
        ? null
        : JsonSerializer.Serialize(
            QrVerification.Datos,
            new JsonSerializerOptions { WriteIndented = true });

    public string DiagnosticId { get; private set; } = string.Empty;

    public bool? ApiAvailable { get; private set; }

    public bool QrUsesLocalhost { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        SetQrEnvironmentWarning();
        var configuredApiKey = GetConfiguredApiKey();
        ApiKey = configuredApiKey;

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var client = httpClientFactory.CreateClient("FirmaApi");
            using var response = await client.GetAsync(
                "api/salud",
                timeout.Token);
            ApiAvailable = response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or TaskCanceledException)
        {
            ApiAvailable = false;
            logger.LogWarning(
                "API.Firma no está disponible al abrir el Demo: {Message}",
                exception.Message);
        }
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        SetQrEnvironmentWarning();
        DiagnosticId = HttpContext.TraceIdentifier;
        var stopwatch = Stopwatch.StartNew();
        ApiKey = ApiKey.Trim();
        ClaveCertificado ??= string.Empty;
        logger.LogInformation(
            "Solicitud {RequestId}: inicio de firma y estampación desde Demo. PDF {PdfBytes} bytes, certificado {CertificateBytes} bytes, clave recibida {PasswordReceived}, longitud de clave {PasswordLength}, página {Page}, posición seleccionada {PositionSelected}",
            DiagnosticId,
            Pdf?.Length ?? 0,
            CertificadoFirma?.Length ?? 0,
            !string.IsNullOrEmpty(ClaveCertificado),
            ClaveCertificado.Length,
            Pagina,
            PosicionSeleccionada);

        if (ApiKey.Length < 32)
        {
            ModelState.AddModelError(nameof(ApiKey), "La API key debe tener al menos 32 caracteres.");
        }

        if (!PosicionSeleccionada)
        {
            ModelState.AddModelError(string.Empty, "Seleccione la posición del sello haciendo clic en el PDF.");
        }

        if (CertificadoFirma is not null)
        {
            if (CertificadoFirma.Length == 0)
            {
                ModelState.AddModelError(
                    nameof(CertificadoFirma),
                    "El certificado P12/PFX seleccionado está vacío.");
            }

            var extension = Path.GetExtension(CertificadoFirma.FileName);
            if (!string.Equals(extension, ".p12", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(extension, ".pfx", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError(
                    nameof(CertificadoFirma),
                    "El certificado debe tener extensión .p12 o .pfx.");
            }
        }

        if (string.IsNullOrEmpty(ClaveCertificado))
        {
            ModelState.AddModelError(
                nameof(ClaveCertificado),
                "No se recibió la clave del certificado.");
        }

        if (!ModelState.IsValid
            || Pdf is null
            || CertificadoFirma is null)
        {
            var invalidFields = ModelState
                .Where(entry => entry.Value?.Errors.Count > 0)
                .Select(entry => entry.Key)
                .ToArray();
            logger.LogWarning(
                "Solicitud {RequestId}: formulario rechazado antes de llamar al API. Campos: {InvalidFields}",
                DiagnosticId,
                string.Join(", ", invalidFields));
            return Page();
        }

        try
        {
            using var form = new MultipartFormDataContent();
            using var pdfContent = CreateFileContent(Pdf);
            using var certificateContent = CreateFileContent(CertificadoFirma);

            form.Add(pdfContent, "pdf", Pdf.FileName);
            form.Add(
                certificateContent,
                "certificado",
                CertificadoFirma.FileName);
            form.Add(new StringContent(ClaveCertificado), "clave");
            if (!string.IsNullOrWhiteSpace(RazonFirma))
            {
                form.Add(new StringContent(RazonFirma.Trim()), "razon");
            }

            if (!string.IsNullOrWhiteSpace(UbicacionFirma))
            {
                form.Add(
                    new StringContent(UbicacionFirma.Trim()),
                    "ubicacion");
            }

            form.Add(new StringContent(Pagina.ToString(CultureInfo.InvariantCulture)), "pagina");
            form.Add(new StringContent(XMm.ToString(CultureInfo.InvariantCulture)), "xMm");
            form.Add(new StringContent(YMm.ToString(CultureInfo.InvariantCulture)), "yMm");
            form.Add(new StringContent(AnchoMm.ToString(CultureInfo.InvariantCulture)), "anchoMm");

            var client = httpClientFactory.CreateClient("FirmaApi");
            client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "X-Correlation-ID",
                DiagnosticId);
            logger.LogInformation(
                "Solicitud {RequestId}: enviando multipart al API {ApiUrl}",
                DiagnosticId,
                new Uri(client.BaseAddress!, "api/documentos/estampar"));

            using var response = await client.PostAsync(
                "api/documentos/estampar",
                form,
                cancellationToken);
            ApiAvailable = true;
            var apiRequestId = response.Headers.TryGetValues(
                    "X-Request-ID",
                    out var requestIds)
                ? requestIds.FirstOrDefault()
                : null;
            logger.LogInformation(
                "Solicitud {RequestId}: API respondió HTTP {StatusCode} {ReasonPhrase}, versión {HttpVersion}, en {ElapsedMs} ms; API Request ID {ApiRequestId}; Content-Type {ContentType}; Content-Length {ContentLength}; SHA-256 original {OriginalSha256}; SHA-256 salida {OutputSha256}",
                DiagnosticId,
                (int)response.StatusCode,
                response.ReasonPhrase ?? "sin frase",
                response.Version,
                stopwatch.ElapsedMilliseconds,
                apiRequestId ?? "no disponible",
                response.Content.Headers.ContentType?.ToString() ?? "sin tipo",
                response.Content.Headers.ContentLength,
                GetHeaderValue(response, "X-Documento-Original-SHA256"),
                GetHeaderValue(response, "X-Documento-Salida-SHA256"));

            if (!response.IsSuccessStatusCode)
            {
                var detail = await ReadProblemDetailAsync(response, cancellationToken);
                logger.LogWarning(
                    "Solicitud {RequestId}: API rechazó la firma con HTTP {StatusCode}. API Request ID: {ApiRequestId}. Detalle completo seguro: {Detail}",
                    DiagnosticId,
                    (int)response.StatusCode,
                    apiRequestId ?? "no disponible",
                    detail);
                ErrorMessage = $"La API respondió {(int)response.StatusCode}: {detail}";
                return Page();
            }

            var result = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            logger.LogInformation(
                "Solicitud {RequestId}: recibidos {PdfBytes} bytes con tipo {ContentType}",
                DiagnosticId,
                result.Length,
                response.Content.Headers.ContentType?.MediaType ?? "sin tipo");
            if (result.Length < 5
                || !result.AsSpan(0, 5).SequenceEqual("%PDF-"u8))
            {
                ErrorMessage = "La API respondió correctamente, pero no devolvió un archivo PDF válido.";
                return Page();
            }

            logger.LogInformation(
                "Solicitud {RequestId}: devolviendo descarga documento-estampado.pdf en {ElapsedMs} ms",
                DiagnosticId,
                stopwatch.ElapsedMilliseconds);
            return File(
                result,
                "application/pdf",
                "documento-firmado-estampado.pdf");
        }
        catch (HttpRequestException exception)
        {
            ApiAvailable = false;
            logger.LogError(
                exception,
                "Solicitud {RequestId}: no fue posible conectar con API.Firma",
                DiagnosticId);
            ErrorMessage = "No se pudo conectar con la API. Verifique que API.Firma esté ejecutándose.";
            return Page();
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            ApiAvailable = false;
            logger.LogError(
                exception,
                "Solicitud {RequestId}: tiempo de espera agotado",
                DiagnosticId);
            ErrorMessage = "La API tardó demasiado en responder.";
            return Page();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(
                "Solicitud {RequestId}: cancelada por el cliente",
                DiagnosticId);
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Solicitud {RequestId}: error inesperado al generar la descarga",
                DiagnosticId);
            ErrorMessage =
                $"Ocurrió un error inesperado. Revise los logs con el identificador {DiagnosticId}.";
            return Page();
        }
    }

    public async Task<IActionResult> OnPostValidarQrAsync(
        CancellationToken cancellationToken)
    {
        ModelState.Clear();
        var configuredApiKey = GetConfiguredApiKey();
        ApiKey = configuredApiKey;
        QrEntrada = QrEntrada?.Trim() ?? string.Empty;

        if (!TryGetQrToken(QrEntrada, out var token, out var validationError))
        {
            QrErrorMessage = validationError;
            return Page();
        }

        try
        {
            var client = httpClientFactory.CreateClient("FirmaApi");
            using var response = await client.GetAsync(
                $"api/verificaciones/qr?token={Uri.EscapeDataString(token)}",
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                QrErrorMessage = await ReadProblemDetailAsync(
                    response,
                    cancellationToken);
                return Page();
            }

            QrVerification = await response.Content
                .ReadFromJsonAsync<QrVerificationResponse>(
                    cancellationToken: cancellationToken);

            if (QrVerification is null || !QrVerification.Valido)
            {
                QrVerification = null;
                QrErrorMessage = "La API no devolvió un resultado de verificación válido.";
            }

            return Page();
        }
        catch (HttpRequestException)
        {
            QrErrorMessage =
                "No se pudo conectar con la API. Verifique que API.Firma esté ejecutándose.";
            return Page();
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            QrErrorMessage = "La API tardó demasiado en responder.";
            return Page();
        }
        catch (JsonException)
        {
            QrErrorMessage = "La API devolvió una respuesta de verificación no válida.";
            return Page();
        }
    }

    public async Task<IActionResult> OnPostValidarFirmaAsync(
        CancellationToken cancellationToken)
    {
        ModelState.Clear();
        SetQrEnvironmentWarning();
        var validationApiKey = GetConfiguredApiKey().Trim();
        ApiKey = validationApiKey;
        DiagnosticId = HttpContext.TraceIdentifier;

        if (validationApiKey.Length is < 32 or > 256)
        {
            SignatureErrorMessage =
                "La API key del demo no está configurada correctamente.";
            return Page();
        }

        if (PdfValidacion is null || PdfValidacion.Length == 0)
        {
            SignatureErrorMessage = "Seleccione un documento PDF firmado.";
            return Page();
        }

        if (PdfValidacion.Length > 10 * 1024 * 1024)
        {
            SignatureErrorMessage = "El PDF no puede superar 10 MB.";
            return Page();
        }

        try
        {
            using var form = new MultipartFormDataContent();
            using var pdfContent = CreateFileContent(PdfValidacion);
            form.Add(pdfContent, "pdf", PdfValidacion.FileName);

            var client = httpClientFactory.CreateClient("FirmaApi");
            client.DefaultRequestHeaders.Add("X-API-Key", validationApiKey);
            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "X-Correlation-ID",
                DiagnosticId);
            using var response = await client.PostAsync(
                "api/documentos/validar-firma",
                form,
                cancellationToken);
            ApiAvailable = true;

            if (!response.IsSuccessStatusCode)
            {
                SignatureErrorMessage =
                    await ReadProblemDetailAsync(response, cancellationToken);
                return Page();
            }

            SignatureValidation = await response.Content
                .ReadFromJsonAsync<PdfSignatureValidationResponse>(
                    cancellationToken: cancellationToken);
            if (SignatureValidation is null)
            {
                SignatureErrorMessage =
                    "La API no devolvió un resultado de validación válido.";
            }

            logger.LogInformation(
                "Solicitud {RequestId}: validación de firma completada con {SignatureCount} firma(s), resultado {Valid}",
                DiagnosticId,
                SignatureValidation?.CantidadFirmas ?? 0,
                SignatureValidation?.Valido ?? false);
            return Page();
        }
        catch (HttpRequestException exception)
        {
            ApiAvailable = false;
            logger.LogError(
                exception,
                "Solicitud {RequestId}: no fue posible conectar con API.Firma para validar la firma",
                DiagnosticId);
            SignatureErrorMessage =
                "No se pudo conectar con la API. Verifique que API.Firma esté ejecutándose.";
            return Page();
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            ApiAvailable = false;
            SignatureErrorMessage =
                "La API tardó demasiado en comprobar certificados y revocación.";
            return Page();
        }
        catch (JsonException exception)
        {
            logger.LogError(
                exception,
                "Solicitud {RequestId}: respuesta de validación no válida",
                DiagnosticId);
            SignatureErrorMessage =
                "La API devolvió una respuesta de validación no válida.";
            return Page();
        }
    }

    private static StreamContent CreateFileContent(IFormFile file)
    {
        var content = new StreamContent(file.OpenReadStream());
        if (MediaTypeHeaderValue.TryParse(file.ContentType, out var contentType))
        {
            content.Headers.ContentType = contentType;
        }

        return content;
    }

    private static bool TryGetQrToken(
        string input,
        out string token,
        out string error)
    {
        token = string.Empty;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Pegue el token o la URL contenida en el QR.";
            return false;
        }

        if (input.Length > 12_000)
        {
            error = "El valor del QR excede el tamaño permitido.";
            return false;
        }

        if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                error = "La URL del QR debe usar HTTP o HTTPS.";
                return false;
            }

            token = QueryHelpers.ParseQuery(uri.Query)["token"].ToString().Trim();
            if (string.IsNullOrWhiteSpace(token))
            {
                error = "La URL no contiene el parámetro token.";
                return false;
            }
        }
        else
        {
            token = input;
        }

        if (token.Length > 8_000)
        {
            error = "El token del QR excede el tamaño permitido.";
            return false;
        }

        return true;
    }

    private static async Task<string> ReadProblemDetailAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(payload))
        {
            return $"La API rechazó la solicitud con estado {(int)response.StatusCode}.";
        }

        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            var messages = new List<string>();
            if (root.TryGetProperty("diagnosticCode", out var diagnosticCode)
                && diagnosticCode.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(diagnosticCode.GetString()))
            {
                messages.Add($"Código diagnóstico: {diagnosticCode.GetString()}.");
            }

            if (root.TryGetProperty("cryptographicErrorCode", out var cryptographicCode)
                && cryptographicCode.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(cryptographicCode.GetString()))
            {
                messages.Add($"Código criptográfico: {cryptographicCode.GetString()}.");
            }

            if (root.TryGetProperty("requestId", out var requestId)
                && requestId.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(requestId.GetString()))
            {
                messages.Add($"Request ID API: {requestId.GetString()}.");
            }

            if (root.TryGetProperty("errors", out var errors)
                && errors.ValueKind == JsonValueKind.Object)
            {
                foreach (var field in errors.EnumerateObject())
                {
                    var fieldName = string.IsNullOrWhiteSpace(field.Name)
                        ? null
                        : field.Name;

                    if (field.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var error in field.Value.EnumerateArray())
                        {
                            if (error.ValueKind == JsonValueKind.String
                                && !string.IsNullOrWhiteSpace(error.GetString()))
                            {
                                messages.Add(FormatValidationMessage(
                                    fieldName,
                                    error.GetString()!));
                            }
                        }
                    }
                    else if (field.Value.ValueKind == JsonValueKind.String
                             && !string.IsNullOrWhiteSpace(field.Value.GetString()))
                    {
                        messages.Add(FormatValidationMessage(
                            fieldName,
                            field.Value.GetString()!));
                    }
                }
            }

            if (messages.Count > 0)
            {
                return string.Join(" ", messages.Distinct());
            }

            if (root.TryGetProperty("detail", out var detail)
                && detail.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(detail.GetString()))
            {
                return detail.GetString()!;
            }

            if (root.TryGetProperty("title", out var title)
                && title.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(title.GetString()))
            {
                return title.GetString()!;
            }
        }
        catch (JsonException)
        {
            // La respuesta no tiene el formato ProblemDetails.
        }

        if (response.Content.Headers.ContentType?.MediaType
                ?.StartsWith("text/", StringComparison.OrdinalIgnoreCase) == true
            && payload.Length <= 1_000)
        {
            return payload.Trim();
        }

        return $"La API rechazó la solicitud con estado {(int)response.StatusCode}.";
    }

    private static string GetHeaderValue(
        HttpResponseMessage response,
        string headerName) =>
        response.Headers.TryGetValues(headerName, out var values)
            ? string.Join(",", values)
            : "no disponible";

    private static string FormatValidationMessage(string? field, string message) =>
        field is null ? message : $"{field}: {message}";

    private void SetQrEnvironmentWarning()
    {
        var verificationUrl = configuration["QrSecurity:VerificationBaseUrl"];
        QrUsesLocalhost = Uri.TryCreate(
                verificationUrl,
                UriKind.Absolute,
                out var uri)
            && (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                || uri.Host == "127.0.0.1"
                || uri.Host == "::1");
    }

    private string GetConfiguredApiKey() =>
        configuration["ApiSecurity:ApiKey"]
        ?? configuration["ApiFirma:ApiKey"]
        ?? string.Empty;
}

public sealed record QrVerificationResponse(
    bool Valido,
    int Version,
    JsonElement Datos,
    string DocumentoOriginalSha256,
    DateTimeOffset FirmadoEnUtc);

public sealed record PdfSignatureValidationResponse(
    bool Valido,
    int CantidadFirmas,
    bool DocumentoCompletoCubierto,
    IReadOnlyList<PdfSignatureDetailResponse> Firmas,
    string Estado,
    string Resumen,
    IReadOnlyList<PdfValidationIssueResponse> Errores);

public sealed record PdfValidationIssueResponse(
    string Codigo,
    string Mensaje,
    int? NumeroFirma);

public sealed record PdfSignatureDetailResponse(
    bool Valida,
    bool IntegridadValida,
    bool CertificadoVigente,
    bool CadenaConfiable,
    bool RevocacionValida,
    string EstadoRevocacion,
    bool CubreDocumentoCompleto,
    string? Firmante,
    string? Emisor,
    string? NumeroSerie,
    string? HuellaDigital,
    DateTimeOffset? FechaFirma,
    DateTimeOffset? CertificadoDesde,
    DateTimeOffset? CertificadoHasta,
    int? DiasVigenciaCertificado,
    int? DiasRestantesVigencia,
    string? AlgoritmoHash,
    bool? SelloTiempoValido,
    DateTimeOffset? FechaSelloTiempo,
    string? AutoridadSelloTiempo,
    string? Error,
    string? DetalleTecnico,
    string? CodigoError,
    string MensajeValidacion);
