using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace API.Firma.Services;

public sealed class UanatacaTrustStore : IDisposable
{
    internal const string RootThumbprint =
        "6DC08450A95CD32662C0910F8C2DCE230D7466AD";
    internal const string Ca2Thumbprint =
        "0ECE527803C9DB6E63BCEA5536B93AE8284E8D2D";

    private readonly X509Certificate2 root;
    private readonly X509Certificate2 ca2;

    internal X509Certificate2 Root => root;

    internal X509Certificate2 Ca2 => ca2;

    public UanatacaTrustStore(ILogger<UanatacaTrustStore> logger)
    {
        root = LoadCertificate(
            "uanataca-root-2016.pem",
            RootThumbprint);
        ca2 = LoadCertificate(
            "uanataca-ca2-2016.pem",
            Ca2Thumbprint);
        ValidateHierarchy();

        logger.LogInformation(
            "Autoridades de confianza UANATACA cargadas: raíz {RootThumbprint}, intermedia {IntermediateThumbprint}",
            root.Thumbprint,
            ca2.Thumbprint);
    }

    public void AddIntermediates(X509Certificate2Collection certificates) =>
        certificates.Add(ca2);

    public void ApplyCustomTrust(X509ChainPolicy policy)
    {
        policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        policy.CustomTrustStore.Add(root);
        AddIntermediates(policy.ExtraStore);
    }

    public void Dispose()
    {
        root.Dispose();
        ca2.Dispose();
    }

    private static X509Certificate2 LoadCertificate(
        string fileName,
        string expectedThumbprint)
    {
        var assembly = typeof(UanatacaTrustStore).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .SingleOrDefault(name =>
                name.EndsWith(fileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"No se encontró el certificado de confianza {fileName}.");

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"No se pudo abrir el certificado de confianza {fileName}.");
        using var reader = new StreamReader(stream);
        var certificate = X509Certificate2.CreateFromPem(reader.ReadToEnd());

        if (!string.Equals(
                certificate.Thumbprint,
                expectedThumbprint,
                StringComparison.OrdinalIgnoreCase))
        {
            certificate.Dispose();
            throw new CryptographicException(
                $"La huella del certificado {fileName} no coincide con la autorizada.");
        }

        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();
        if (basicConstraints?.CertificateAuthority != true)
        {
            certificate.Dispose();
            throw new CryptographicException(
                $"El certificado {fileName} no corresponde a una autoridad certificadora.");
        }

        return certificate;
    }

    private void ValidateHierarchy()
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.ExtraStore.Add(ca2);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;

        if (!chain.Build(ca2))
        {
            var statuses = string.Join(
                ", ",
                chain.ChainStatus.Select(status => status.Status));
            throw new CryptographicException(
                $"La jerarquía de confianza UANATACA no es válida: {statuses}.");
        }
    }
}
