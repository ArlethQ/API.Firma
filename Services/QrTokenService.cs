using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using API.Firma.Models;
using API.Firma.Security;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace API.Firma.Services;

public sealed class QrTokenService(IOptions<QrSecurityOptions> options)
{
    private const int CompactHeaderBytes = sizeof(long) + 32;
    private const int CompactHmacBytes = 16;
    private const int MaxExpandedPayloadBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly QrSecurityOptions options = options.Value;

    public string CreatePlainText(JsonElement data, DateTimeOffset signedAtUtc)
    {
        var holderName = GetText(data, "n");
        var identification = GetText(data, "i");
        var lines = new List<string>(3);
        if (!string.IsNullOrWhiteSpace(holderName))
        {
            lines.Add($"Firmado por: {NormalizeText(holderName)}");
        }

        if (!string.IsNullOrWhiteSpace(identification))
        {
            lines.Add($"Identificacion: {NormalizeText(identification)}");
        }

        lines.Add($"Fecha: {signedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        return string.Join('\n', lines);
    }

    public string CreateVerificationUrl(
        JsonElement data,
        string originalDocumentSha256,
        DateTimeOffset signedAtUtc)
    {
        var documentHash = Convert.FromHexString(originalDocumentSha256);
        var compressedData = Compress(JsonSerializer.SerializeToUtf8Bytes(data, JsonOptions));
        var payload = new byte[CompactHeaderBytes + compressedData.Length];
        BinaryPrimitives.WriteInt64BigEndian(
            payload.AsSpan(0, sizeof(long)),
            signedAtUtc.ToUnixTimeSeconds());
        documentHash.CopyTo(payload, sizeof(long));
        compressedData.CopyTo(payload, CompactHeaderBytes);

        var encodedPayload = WebEncoders.Base64UrlEncode(payload);
        var signature = Sign(encodedPayload)[..CompactHmacBytes];
        var token = $"v2.{encodedPayload}.{WebEncoders.Base64UrlEncode(signature)}";

        return $"{options.VerificationBaseUrl.TrimEnd('/')}?token={Uri.EscapeDataString(token)}";
    }

    public QrVerificationResult Verify(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8_000)
        {
            throw new StampValidationException("token", "El token del QR no es válido.");
        }

        var parts = token.Split('.', StringSplitOptions.None);
        if (parts.Length != 3)
        {
            throw new StampValidationException("token", "El token del QR no tiene un formato compatible.");
        }

        return parts[0] switch
        {
            "v1" => VerifyLegacy(parts),
            "v2" => VerifyCompact(parts),
            _ => throw new StampValidationException("token", "El token del QR no tiene un formato compatible.")
        };
    }

    private QrVerificationResult VerifyCompact(string[] parts)
    {
        byte[] suppliedSignature;
        byte[] payload;
        try
        {
            payload = WebEncoders.Base64UrlDecode(parts[1]);
            suppliedSignature = WebEncoders.Base64UrlDecode(parts[2]);
        }
        catch (FormatException exception)
        {
            throw new StampValidationException("token", "El token del QR no es válido.", exception);
        }

        var expectedSignature = Sign(parts[1])[..CompactHmacBytes];
        if (payload.Length <= CompactHeaderBytes
            || suppliedSignature.Length != CompactHmacBytes
            || !CryptographicOperations.FixedTimeEquals(suppliedSignature, expectedSignature))
        {
            throw new StampValidationException(
                "token",
                "La firma del QR no es válida; los datos pudieron ser alterados.");
        }

        try
        {
            var signedAtUtc = DateTimeOffset.FromUnixTimeSeconds(
                BinaryPrimitives.ReadInt64BigEndian(payload.AsSpan(0, sizeof(long))));
            var documentHash = Convert.ToHexString(
                payload.AsSpan(sizeof(long), 32));
            var data = JsonSerializer.Deserialize<JsonElement>(
                Decompress(payload[CompactHeaderBytes..]),
                JsonOptions);
            if (data.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException();
            }

            return new QrVerificationResult(
                true,
                2,
                data,
                documentHash,
                signedAtUtc);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new StampValidationException("token", "El contenido del QR no es válido.", exception);
        }
        catch (InvalidDataException exception)
        {
            throw new StampValidationException("token", "El contenido del QR no es válido.", exception);
        }
        catch (JsonException exception)
        {
            throw new StampValidationException("token", "El contenido del QR no es válido.", exception);
        }
    }

    private QrVerificationResult VerifyLegacy(string[] parts)
    {

        byte[] suppliedSignature;
        byte[] compressedPayload;
        try
        {
            compressedPayload = WebEncoders.Base64UrlDecode(parts[1]);
            suppliedSignature = WebEncoders.Base64UrlDecode(parts[2]);
        }
        catch (FormatException exception)
        {
            throw new StampValidationException("token", "El token del QR no es válido.", exception);
        }

        var expectedSignature = Sign(parts[1]);
        if (compressedPayload.Length == 0
            || suppliedSignature.Length != expectedSignature.Length
            || !CryptographicOperations.FixedTimeEquals(suppliedSignature, expectedSignature))
        {
            throw new StampValidationException(
                "token",
                "La firma del QR no es válida; los datos pudieron ser alterados.");
        }

        try
        {
            var json = Decompress(compressedPayload);
            var claims = JsonSerializer.Deserialize<QrClaims>(json, JsonOptions)
                ?? throw new JsonException();

            if (claims.Version != 1
                || claims.Datos.ValueKind != JsonValueKind.Object
                || !IsSha256(claims.DocumentoOriginalSha256))
            {
                throw new JsonException();
            }

            return new QrVerificationResult(
                true,
                claims.Version,
                claims.Datos,
                claims.DocumentoOriginalSha256,
                claims.FirmadoEnUtc);
        }
        catch (InvalidDataException exception)
        {
            throw new StampValidationException("token", "El contenido del QR no es válido.", exception);
        }
        catch (JsonException exception)
        {
            throw new StampValidationException("token", "El contenido del QR no es válido.", exception);
        }
    }

    private byte[] Sign(string encodedPayload) =>
        HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(options.SigningKey),
            Encoding.ASCII.GetBytes(encodedPayload));

    private static string? GetText(JsonElement data, string propertyName) =>
        data.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string NormalizeText(string value) =>
        value.Replace('\r', ' ').Replace('\n', ' ').Trim();

    private static byte[] Compress(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var compressor = new BrotliStream(output, CompressionLevel.SmallestSize, true))
        {
            compressor.Write(bytes);
        }

        return output.ToArray();
    }

    private static byte[] Decompress(byte[] bytes)
    {
        using var input = new MemoryStream(bytes);
        using var decompressor = new BrotliStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[4096];

        while (true)
        {
            var read = decompressor.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > MaxExpandedPayloadBytes)
            {
                throw new InvalidDataException("El contenido descomprimido excede el límite.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private sealed record QrClaims(
        [property: JsonPropertyName("v")]
        int Version,
        [property: JsonPropertyName("d")]
        JsonElement Datos,
        [property: JsonPropertyName("h")]
        string DocumentoOriginalSha256,
        [property: JsonPropertyName("t")]
        DateTimeOffset FirmadoEnUtc);
}
