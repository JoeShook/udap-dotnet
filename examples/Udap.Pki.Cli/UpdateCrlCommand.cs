using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Cloud.Storage.V1;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Spectre.Console;
using Spectre.Console.Cli;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Udap.Pki.Cli;

public class UpdateCrlCommand : AsyncCommand<UpdateCrlSettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, UpdateCrlSettings settings)
    {
        var isProduction = settings.IsProduction;

        if (isProduction)
        {
            AnsiConsole.MarkupLine("[bold green]Running in PRODUCTION mode[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("[bold yellow]Running in TEST mode (default)[/]");
        }

        AnsiConsole.MarkupLine("[green]GCP CA/CRL Manager CLI[/]");

        // Load configuration
        var config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false)
            .Build();
        var gcpPkiConfig = config.GetSection("PrivatePkiStore").Get<PrivatePkiStoreConfig>()!;
        var publicCertStoreConfig = config.GetSection("PublicCertStore").Get<PublicCertStoreConfig>()!;

        // Select paths based on type
        string p12Path, crlPath;
        if (settings.Type == CrlType.CA)
        {
            p12Path = gcpPkiConfig.CaP12Path;
            crlPath = gcpPkiConfig.CaCrlPath;
        }
        else
        {
            p12Path = gcpPkiConfig.SubCaP12Path;
            crlPath = gcpPkiConfig.SubCaCrlPath;
        }

        // Download CA P12
        var storage = StorageClient.Create();
        using var caP12Stream = new MemoryStream();
        await storage.DownloadObjectAsync(gcpPkiConfig.CaBucket, p12Path, caP12Stream);
        caP12Stream.Position = 0;

        // Load CA certificate
        var caPassword = AnsiConsole.Prompt(
            new TextPrompt<string>("Enter the [yellow]CA P12 password[/]:").PromptStyle("red").Secret());
        var caCert = new X509Certificate2(caP12Stream.ToArray(), caPassword, X509KeyStorageFlags.Exportable);

        // Download CRL
        using var crlStream = new MemoryStream();
        await storage.DownloadObjectAsync(gcpPkiConfig.CaBucket, crlPath, crlStream);
        crlStream.Position = 0;
        var crlBytes = crlStream.ToArray();

        // Parse CRL and show version
        var crlParser = new X509CrlParser();
        var crl = crlParser.ReadCrl(crlBytes);
        AnsiConsole.MarkupLine($"[blue]Current CRL version:[/] {crl.Version}");

        // Generate new CRL
        var newCrlBytes = GenerateNewCrl(caCert, caPassword, crlBytes);

        if (isProduction)
        {
            using var uploadStream = new MemoryStream(newCrlBytes);
            await storage.UploadObjectAsync(gcpPkiConfig.CaBucket, crlPath, "application/pkix-crl", uploadStream);

            AnsiConsole.MarkupLine("[green]New CRL uploaded successfully![/]");

            var publicCrlObjectName = $"{publicCertStoreConfig.CrlPath}/{Path.GetFileName(crlPath)}";
            using var publicUploadStream = new MemoryStream(newCrlBytes);

            await storage.UploadObjectAsync(
                publicCertStoreConfig.CrlBucket,
                publicCrlObjectName,
                "application/pkix-crl",
                publicUploadStream);

            AnsiConsole.MarkupLine($"[green]New CRL also uploaded to public bucket: {publicCertStoreConfig.CrlBucket}/{publicCrlObjectName}[/]");
        }
        else
        {
            // Write CRL to disk for inspection
            var crlFilePath = settings.Type == CrlType.CA ? "c://temp/CA.crl" : "c://temp/SubCA.crl";
            await File.WriteAllBytesAsync(crlFilePath, newCrlBytes);
            AnsiConsole.MarkupLine($"[yellow]New CRL written to disk at:[/] {crlFilePath}");
        }

        return 0;
    }

    public static byte[] GenerateNewCrl(X509Certificate2 caCert, string caPassword, byte[] previousCrlBytes)
    {
        var (bouncyCertificate, privateKey) = GetCertificateData(caCert);

        var crlParser = new X509CrlParser();
        var previousCrl = crlParser.ReadCrl(previousCrlBytes);
        var nextCrlNumber = GetNextCrlNumber(previousCrl);

        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(bouncyCertificate.SubjectDN);
        var now = DateTime.UtcNow;
        crlGen.SetThisUpdate(now);
        crlGen.SetNextUpdate(DateTime.UtcNow.AddDays(1));

        foreach (X509CrlEntry entry in previousCrl.GetRevokedCertificates() ?? Enumerable.Empty<X509CrlEntry>())
        {
            var reasonExt = entry.GetExtensionValue(X509Extensions.ReasonCode);

            if (reasonExt != null)
            {
                crlGen.AddCrlEntry(
                    entry.SerialNumber,
                    entry.RevocationDate,
                    new X509Extensions(
                        new DerObjectIdentifier[] { X509Extensions.ReasonCode },
                        new[] { new Org.BouncyCastle.Asn1.X509.X509Extension(false, reasonExt) }
                    )
                );
            }
            else
            {
                crlGen.AddCrlEntry(
                    entry.SerialNumber,
                    entry.RevocationDate,
                    null
                );
            }
        }
        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, X509ExtensionUtilities.CreateAuthorityKeyIdentifier(bouncyCertificate.GetPublicKey()));
        crlGen.AddExtension(X509Extensions.CrlNumber, false, nextCrlNumber);

        var sigFactory = new Asn1SignatureFactory("SHA256WithRSAEncryption", privateKey);
        var crl = crlGen.Generate(sigFactory);

        return crl.GetEncoded();
    }

    private static (X509Certificate bouncyCertificate, AsymmetricKeyParameter privateKey) GetCertificateData(
        X509Certificate2 p12Certificate)
    {
        var bouncyCertificate = DotNetUtilities.FromX509Certificate(p12Certificate);
        var rsaPrivateKey = p12Certificate.GetRSAPrivateKey();
        AnsiConsole.MarkupLine($"[yellow]Private key type:[/] {rsaPrivateKey?.GetType().FullName}");

        RSA exportableRsa;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && rsaPrivateKey is RSACng cng)
        {
            if (!cng.Key.ExportPolicy.HasFlag(CngExportPolicies.AllowExport))
            {
                throw new InvalidOperationException("The private key is not exportable. Re-create the P12 with an exportable key.");
            }

            var encryptedPrivateKeyBytes = cng.ExportEncryptedPkcs8PrivateKey(
                "ILikePasswords",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            exportableRsa = RSA.Create();
            exportableRsa.ImportEncryptedPkcs8PrivateKey("ILikePasswords".AsSpan(), encryptedPrivateKeyBytes.AsSpan(), out _);
        }
        else
        {
            var privateKeyBytes = rsaPrivateKey!.ExportPkcs8PrivateKey();
            exportableRsa = RSA.Create();
            exportableRsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
        }

        var privateKey = DotNetUtilities.GetKeyPair(exportableRsa).Private;
        return (bouncyCertificate, privateKey);
    }

    public static CrlNumber GetNextCrlNumber(X509Crl crl)
    {
        var crlNumExt = crl.GetExtensionValue(X509Extensions.CrlNumber);

        if (crlNumExt == null)
        {
            // If no CRL number, start at 1
            return new CrlNumber(BigInteger.One);
        }

        var asn1Object = X509ExtensionUtilities.FromExtensionValue(crlNumExt);
        var prevCrlNum = DerInteger.GetInstance(asn1Object).PositiveValue;

        return new CrlNumber(prevCrlNum.Add(BigInteger.One));
    }
}