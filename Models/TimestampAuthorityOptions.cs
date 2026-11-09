namespace API.Firma.Models;

public sealed class TimestampAuthorityOptions
{
    public const string SectionName = "TimestampAuthority";

    public bool Enabled { get; set; }

    public string Url { get; set; } = "https://tsa.uanataca.com/tsa/tss03";

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public int TimeoutSeconds { get; set; } = 20;
}
