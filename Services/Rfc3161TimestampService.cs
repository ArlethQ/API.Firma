using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using API.Firma.Models;
using Microsoft.Extensions.Options;

namespace API.Firma.Services;

public sealed class Rfc3161TimestampService(
    HttpClient httpClient,
    IOptions<TimestampAuthorityOptions> options,
    ILogger<Rfc3161TimestampService> logger)
{
    private const string SignatureTimestampOid = "1.2.840.113549.1.9.16.2.14";
    private static readonly Oid Sha256Oid = new("2.16.840.1.101.3.4.2.1");

    public bool IsEnabled => options.Value.Enabled;

    public async Task<byte[]> AddTimestampAsync(
        SignedCms cms,
        CancellationToken cancellationToken)
    {
        var configuration = options.Value;
        if (!configuration.Enabled)
        {
            return cms.Encode();
        }

        if (!Uri.TryCreate(configuration.Url, UriKind.Absolute, out var timestampUri)
            || !string.Equals(timestampUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new StampValidationException(
                "certificado",
                "La URL de la autoridad de sello de tiempo debe usar HTTPS.",
                diagnosticCode: "TSA_URL_INVALIDA");
        }

        if (string.IsNullOrWhiteSpace(configuration.Username)
            || string.IsNullOrWhiteSpace(configuration.Password))
        {
            throw new StampValidationException(
                "certificado",
                "La autoridad de sello de tiempo requiere usuario y clave configurados.",
                diagnosticCode: "TSA_CREDENTIALS_MISSING");
        }

        if (configuration.TimeoutSeconds is < 5 or > 120)
        {
            throw new StampValidationException(
                "certificado",
                "El tiempo de espera de la autoridad de sello debe estar entre 5 y 120 segundos.",
                diagnosticCode: "TSA_TIMEOUT_INVALIDO");
        }

        var signer = cms.SignerInfos.Cast<SignerInfo>().Single();
        var request = Rfc3161TimestampRequest.CreateFromHash(
            SHA256.HashData(signer.GetSignature()),
            Sha256Oid,
            requestedPolicyId: null,
            nonce: null,
            requestSignerCertificates: false,
            extensions: null!);

        using var requestMessage = new HttpRequestMessage(HttpMethod.Post, timestampUri)
        {
            Content = new ByteArrayContent(request.Encode())
        };
        requestMessage.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/timestamp-query");
        requestMessage.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));
        requestMessage.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes(
                        $"{configuration.Username}:{configuration.Password}")));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(configuration.TimeoutSeconds));

        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(
                requestMessage,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new StampValidationException(
                "certificado",
                "La autoridad de sello de tiempo no respondió dentro del tiempo permitido.",
                diagnosticCode: "TSA_TIMEOUT");
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(
                exception,
                "No fue posible conectar con la autoridad de sello de tiempo {TimestampAuthority}",
                timestampUri);
            throw new StampValidationException(
                "certificado",
                "No fue posible conectar con la autoridad de sello de tiempo.",
                exception,
                "TSA_UNAVAILABLE");
        }

        using (response)
        {
            var responseBytes = await response.Content.ReadAsByteArrayAsync(timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                var responseDetail = Encoding.UTF8.GetString(responseBytes).Trim();
                if (responseDetail.Length > 500)
                {
                    responseDetail = responseDetail[..500];
                }

                logger.LogWarning(
                    "La TSA rechazó la solicitud: HTTP {StatusCode}; detalle {ResponseDetail}",
                    (int)response.StatusCode,
                    responseDetail);
                throw new StampValidationException(
                    "certificado",
                    string.IsNullOrWhiteSpace(responseDetail)
                        ? $"La autoridad de sello de tiempo rechazó la solicitud (HTTP {(int)response.StatusCode})."
                        : $"La autoridad de sello de tiempo rechazó la solicitud (HTTP {(int)response.StatusCode}): {responseDetail}",
                    diagnosticCode: "TSA_REJECTED");
            }

            try
            {
                var token = request.ProcessResponse(responseBytes, out var bytesConsumed);
                if (bytesConsumed != responseBytes.Length)
                {
                    throw new CryptographicException(
                        "La respuesta de la autoridad de sello contiene datos adicionales.");
                }

                if (!token.VerifySignatureForSignerInfo(
                        signer,
                        out _,
                        token.AsSignedCms().Certificates))
                {
                    throw new CryptographicException(
                        "La respuesta de la autoridad de sello no corresponde a la firma.");
                }

                signer.AddUnsignedAttribute(
                    new AsnEncodedData(
                        SignatureTimestampOid,
                        token.AsSignedCms().Encode()));
                logger.LogInformation(
                    "Sello RFC 3161 agregado por {TimestampAuthority} para el certificado {CertificateThumbprint}",
                    timestampUri,
                    signer.Certificate?.Thumbprint);
                return cms.Encode();
            }
            catch (CryptographicException exception)
            {
                logger.LogWarning(
                    exception,
                    "La respuesta RFC 3161 de {TimestampAuthority} no pudo validarse",
                    timestampUri);
                throw new StampValidationException(
                    "certificado",
                    "La autoridad de sello devolvió una respuesta RFC 3161 no válida.",
                    exception,
                    "TSA_RESPONSE_INVALID");
            }
        }
    }
}
