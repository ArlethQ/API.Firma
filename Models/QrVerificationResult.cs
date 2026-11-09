using System.Text.Json;

namespace API.Firma.Models;

public sealed record QrVerificationResult(
    bool Valido,
    int Version,
    JsonElement Datos,
    string DocumentoOriginalSha256,
    DateTimeOffset FirmadoEnUtc);
