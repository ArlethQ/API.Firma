namespace API.Firma.Models;

public sealed record StampResult(
    byte[] Pdf,
    string OriginalSha256,
    string OutputSha256);
