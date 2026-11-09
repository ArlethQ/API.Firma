namespace API.Firma.Services;

public sealed class StampValidationException(
    string field,
    string message,
    Exception? innerException = null,
    string? diagnosticCode = null,
    string? cryptographicErrorCode = null)
    : Exception(message, innerException)
{
    public string Field { get; } = field;

    public string? DiagnosticCode { get; } = diagnosticCode;

    public string? CryptographicErrorCode { get; } = cryptographicErrorCode;
}
