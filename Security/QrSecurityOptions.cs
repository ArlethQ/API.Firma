namespace API.Firma.Security;

public sealed class QrSecurityOptions
{
    public const string SectionName = "QrSecurity";

    public string SigningKey { get; init; } = string.Empty;
    public string VerificationBaseUrl { get; init; } = string.Empty;
}
