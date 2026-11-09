namespace API.Firma.Models;

public sealed record PdfSignatureValidationResult(
    bool Valido,
    int CantidadFirmas,
    bool DocumentoCompletoCubierto,
    IReadOnlyList<PdfSignatureDetail> Firmas)
{
    public string Estado =>
        Valido
            ? "VALIDA"
            : CantidadFirmas == 0
                ? "SIN_FIRMAS"
                : TieneFalloDefinitivo()
                    ? "INVALIDA"
                    : "NO_VERIFICABLE";

    public string Resumen => Estado switch
    {
        "VALIDA" =>
            "La firma es íntegra, cubre el documento completo y su certificado fue validado.",
        "SIN_FIRMAS" =>
            "El PDF no contiene una firma digital CMS/PAdES reconocible.",
        "INVALIDA" =>
            "La firma presenta uno o más errores que invalidan el documento.",
        _ =>
            "La firma criptográfica existe, pero no fue posible confirmar completamente la confianza del certificado."
    };

    public IReadOnlyList<PdfValidationIssue> Errores => BuildIssues();

    private bool TieneFalloDefinitivo() =>
        !DocumentoCompletoCubierto
        || Firmas.Any(firma =>
            !firma.IntegridadValida
            || !firma.CertificadoVigente
            || string.Equals(
                firma.EstadoRevocacion,
                "Revocado",
                StringComparison.OrdinalIgnoreCase)
            || firma.SelloTiempoValido == false);

    private IReadOnlyList<PdfValidationIssue> BuildIssues()
    {
        var issues = new List<PdfValidationIssue>();
        if (CantidadFirmas == 0)
        {
            issues.Add(new(
                "SIN_FIRMAS",
                "No se encontró ninguna firma digital CMS/PAdES en el PDF.",
                null));
            return issues;
        }

        if (!DocumentoCompletoCubierto)
        {
            issues.Add(new(
                "DOCUMENTO_NO_CUBIERTO",
                "El PDF contiene contenido o cambios posteriores a la última firma.",
                null));
        }

        for (var index = 0; index < Firmas.Count; index++)
        {
            var firma = Firmas[index];
            var numeroFirma = index + 1;
            if (!firma.IntegridadValida)
            {
                issues.Add(new(
                    "INTEGRIDAD_INVALIDA",
                    "La firma criptográfica no coincide con el contenido del PDF. El documento o la firma pudo ser modificado.",
                    numeroFirma));
                continue;
            }

            if (!firma.CertificadoVigente)
            {
                issues.Add(new(
                    "CERTIFICADO_NO_VIGENTE",
                    "El certificado no era válido en la fecha comprobada y no existe un sello de tiempo válido que demuestre una firma anterior.",
                    numeroFirma));
            }

            if (string.Equals(
                    firma.EstadoRevocacion,
                    "Revocado",
                    StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new(
                    "CERTIFICADO_REVOCADO",
                    "La autoridad certificadora reportó el certificado como revocado.",
                    numeroFirma));
            }
            else if (string.Equals(
                         firma.EstadoRevocacion,
                         "NoDisponible",
                         StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new(
                    "REVOCACION_NO_COMPROBADA",
                    "No se pudo consultar OCSP/CRL. Esto no demuestra que el certificado esté revocado; la comprobación quedó inconclusa.",
                    numeroFirma));
            }

            if (!firma.CadenaConfiable)
            {
                issues.Add(new(
                    "CADENA_NO_CONFIABLE",
                    "No se pudo construir una cadena hasta una autoridad raíz confiable. Puede faltar un certificado intermedio o la raíz en el servidor.",
                    numeroFirma));
            }

            if (firma.SelloTiempoValido == false)
            {
                issues.Add(new(
                    "SELLO_TIEMPO_INVALIDO",
                    "El sello de tiempo RFC 3161 está presente, pero no superó su validación.",
                    numeroFirma));
            }
        }

        return issues;
    }
}

public sealed record PdfValidationIssue(
    string Codigo,
    string Mensaje,
    int? NumeroFirma);

public sealed record PdfSignatureDetail(
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
    string? AlgoritmoHash,
    bool? SelloTiempoValido,
    DateTimeOffset? FechaSelloTiempo,
    string? AutoridadSelloTiempo,
    string? Error,
    string? DetalleTecnico = null)
{
    public int? DiasVigenciaCertificado =>
        CertificadoDesde is null || CertificadoHasta is null
            ? null
            : Math.Max(
                0,
                (int)Math.Ceiling(
                    (CertificadoHasta.Value.UtcDateTime.Date
                     - CertificadoDesde.Value.UtcDateTime.Date).TotalDays));

    public int? DiasRestantesVigencia =>
        CertificadoHasta is null
            ? null
            : Math.Max(
                0,
                (int)Math.Ceiling(
                    (CertificadoHasta.Value.UtcDateTime.Date
                     - DateTime.UtcNow.Date).TotalDays));

    public string? CodigoError =>
        Valida
            ? null
            : !IntegridadValida
                ? "INTEGRIDAD_INVALIDA"
                : !CertificadoVigente
                    ? "CERTIFICADO_NO_VIGENTE"
                    : string.Equals(
                        EstadoRevocacion,
                        "Revocado",
                        StringComparison.OrdinalIgnoreCase)
                        ? "CERTIFICADO_REVOCADO"
                        : string.Equals(
                            EstadoRevocacion,
                            "NoDisponible",
                            StringComparison.OrdinalIgnoreCase)
                            ? "REVOCACION_NO_COMPROBADA"
                            : !CadenaConfiable
                                ? "CADENA_NO_CONFIABLE"
                                : SelloTiempoValido == false
                                    ? "SELLO_TIEMPO_INVALIDO"
                                    : !CubreDocumentoCompleto
                                        ? "DOCUMENTO_NO_CUBIERTO"
                                        : "VALIDACION_INCOMPLETA";

    public string MensajeValidacion =>
        Valida
            ? "La firma superó todas las validaciones."
            : Error ?? "La firma no superó todas las validaciones.";
}
