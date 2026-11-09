using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using API.Firma.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace API.Firma.Tests;

public sealed class UanatacaTrustStoreTests
{
    [Fact]
    public void EmbeddedCertificates_HavePinnedThumbprintsAndValidHierarchy()
    {
        using var store = CreateStore();
        using var chain = CreateCustomChain(store);

        Assert.Equal(
            UanatacaTrustStore.RootThumbprint,
            store.Root.Thumbprint);
        Assert.Equal(
            UanatacaTrustStore.Ca2Thumbprint,
            store.Ca2.Thumbprint);
        Assert.True(chain.Build(store.Ca2));
    }

    [Fact]
    public void CustomTrust_DoesNotAcceptUnrelatedSelfSignedCertificate()
    {
        using var store = CreateStore();
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=NO CONFIABLE",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        using var chain = CreateCustomChain(store);

        Assert.False(chain.Build(certificate));
    }

    private static UanatacaTrustStore CreateStore() =>
        new(NullLogger<UanatacaTrustStore>.Instance);

    private static X509Chain CreateCustomChain(UanatacaTrustStore store)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        store.ApplyCustomTrust(chain.ChainPolicy);
        return chain;
    }
}
