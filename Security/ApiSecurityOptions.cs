namespace API.Firma.Security;

public sealed class ApiSecurityOptions
{
    public const string SectionName = "ApiSecurity";

    public string ApiKey { get; init; } = string.Empty;
    public List<string> AllowedIpAddresses { get; init; } = [];
}
