#region (c) 2024-2025 Joseph Shook. All rights reserved;
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using FluentAssertions;
using Duende.IdentityModel;
using Udap.Model.Registration;
using Xunit.Abstractions;

namespace Udap.Common.Tests.Model.Registration
{
    public class CertificationsDocumentTest
    {
        private static readonly JsonSerializerOptions IndentedJsonOptions = new JsonSerializerOptions { WriteIndented = true };
        private readonly ITestOutputHelper _testOutputHelper;

        public CertificationsDocumentTest(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void UdapCertificationAndEndorsementDocument_SerializationTest()
        {
            var document = new UdapCertificationAndEndorsementDocument("Test Certification")
            {
                Issuer = "joe",
                Subject = "joe"
            };

            _testOutputHelper.WriteLine(JsonSerializer.Serialize(document, IndentedJsonOptions));
        }

        [Fact]
        public void CertificateTest()
        {
            //
            // Certificate required
            //
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification")
                .WithExpiration(DateTime.Now.AddDays(1));

            act.Should().Throw<Exception>()
                .Where(e => e.Message.StartsWith("Certificate required"));

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification")
                .BuildSoftwareStatement();


            act.Should().Throw<Exception>()
                .Where(e => e.Message.StartsWith("Missing certificate"));
        }

        [Fact]
        public void CertificationExpirationTests()
        {
            var certificationCert =
                new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
            .WithExpiration(DateTime.Now.AddYears(3).Subtract(TimeSpan.FromSeconds(10)));

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("expirationOffset")
                .Where(e => e.Message.StartsWith("Expiration must not expire after certificate"));

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(DateTime.Now.AddYears(3));

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("expirationOffset")
                .Where(e => e.Message.StartsWith("Expiration limit to 3 years"));

            //
            // Still good on the actual expiration DateTime
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration);

            act.Should().NotThrow();

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration + TimeSpan.FromSeconds(1));

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("expirationOffset")
                .Where(e => e.Message.StartsWith("Expiration must not expire after certificate"));



            //
            // User supplies Epoch time
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(DateTime.Now.AddYears(3).ToEpochTime());

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithParameterName("expirationOffset")
                .Where(e => e.Message.StartsWith("Expiration must not expire after certificate"));

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration.ToEpochTime());

            act.Should().NotThrow();
        }

        [Fact]
        public void LogoTests()
        {
            //
            // logo_uri
            //

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLogoUri("Poof");

            act.Should().Throw<UriFormatException> ()
                .WithMessage("Invalid URI: The format of the URI could not be determined.");

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png");

            act.Should().NotThrow();

            //
            // certification_logo
            //
            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationLogo("Poof");

            act.Should().Throw<UriFormatException>()
                .WithMessage("Invalid URI: The format of the URI could not be determined.");

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationLogo("https://certifications.fhirlabs.net/logo.png");

            act.Should().NotThrow();

            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name");
        }

        [Fact]
        public void LaunchUriTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("Poof");

            act.Should().Throw<UriFormatException>()
                .WithMessage("Invalid URI: The format of the URI could not be determined.");

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("https://smart.fhirlabs.net/launch");

            act.Should().NotThrow();
        }

        [Fact]
        public void AudienceTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithAudience("Poof");

            act.Should().Throw<UriFormatException>()
                .WithMessage("Invalid URI: The format of the URI could not be determined.");

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithLaunchUri("https://securedcontrols.net/connect/register");

            act.Should().NotThrow();
        }

        /// <summary>
        /// It is not typical to set the iat claim yourself.  It is exposed to facilitate tooling that wants to
        /// test servers for how they handle an invalid iat claims.
        /// </summary>
        [Fact]
        public void IssuedAtTests()
        {
            var now = DateTime.Now.ToEpochTime();
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithIssuedAt(now)
                .Build();

            certificationsDoc.IssuedAt.Should().Be(now);

        }

        [Fact]
        public void JwtIdTests()
        {
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            var firstJwtId = certificationsDoc.JwtId;
            certificationsDoc.JwtId.Should().NotBeNullOrWhiteSpace();

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            certificationsDoc.JwtId.Should().NotBe(firstJwtId);

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithJwtId("Joe-JwtId-1")
                .Build();

            certificationsDoc.JwtId.Should().Be("Joe-JwtId-1");
        }

        [Fact]
        public void CertificationDescriptionTests()
        {
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .Build();

            certificationsDoc.CertificationDescription.Should().BeNull();

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("Client Name")
                .WithCertificationDescription("Sample Description")
                .Build();

            certificationsDoc.CertificationDescription.Should().Be("Sample Description");

        }

        [Fact]
        public void CertificationStatusEndpointTests()
        {
            //
            // logo_uri
            //

            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithCertificationStatusEndpoint("Poof");

            act.Should().Throw<UriFormatException>()
                .WithMessage("Invalid URI: The format of the URI could not be determined.");

            act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithCertificationStatusEndpoint("https://certification.securedcontrols.net/status/AdminFhirLabsCertification");

            act.Should().NotThrow();
        }

        [Fact]
        public void EndorsementTests()
        {
            //
            // logo_uri
            //

           var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .Build();

           certificationsDoc.IsEndorsement.Should().BeFalse();

           certificationsDoc = UdapCertificationsAndEndorsementBuilder
               .Create("AdminFhirLabsCertification")
               .WithEndorsement(true)
               .Build();

           certificationsDoc.IsEndorsement.Should().BeTrue();
        }

        [Fact]
        public void JwksTests()
        {
            Action act = () => UdapCertificationsAndEndorsementBuilder
                .Create("AdminFhirLabsCertification")
                .WithJwks("Poof");

            act.Should().Throw<NotImplementedException>();
        }

        [Fact]
        public void BuildCertification()
        {
            var certificationCert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years
            
            var certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>(){ "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>(){ "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>(){ "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>(){"authorization_code", "refresh_token", "client_credentials"})
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt")  // 'none' if authorization server allows it.
                                                                 // 'client_secret_post': The client uses the HTTP POST parameters
                                                                 // as defined in OAuth 2.0, Section 2.3.1.
                                                                 // "client_secret_basic": The client uses HTTP Basic as defined in
                                                                 // OAuth 2.0, Section 2.3.1.
                                                                 //
                                                                 // The additional value private_key_jwt may also be used.
                                                                 //
                .Build();

            certificationsDoc.Audience.Should().Be(null);
            

            certificationsDoc = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithAudience("https://securedcontrols.net/connect/register")
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>() { "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>() { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string> { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>() { "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>() { "authorization_code", "refresh_token", "client_credentials" })
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt")  // 'none' if authorization server allows it.
                                                                 // 'client_secret_post': The client uses the HTTP POST parameters
                                                                 // as defined in OAuth 2.0, Section 2.3.1.
                                                                 // "client_secret_basic": The client uses HTTP Basic as defined in
                                                                 // OAuth 2.0, Section 2.3.1.
                                                                 //
                                                                 // The additional value private_key_jwt may also be used.
                                                                 //
                .Build();

            certificationsDoc.Audience.Should().Be("https://securedcontrols.net/connect/register");
            certificationsDoc.CertificationName.Should().Be("FhirLabs Administrator Certification");
            certificationsDoc.Expiration.Should().Be(expiration.ToEpochTime());
            
        }

        [Fact]
        public void BuildSotwareStatementForCertification()
        {
            var certificationCert =
                new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            var expiration = certificationCert.NotAfter; // remember cannot be greater than 3 years

            var signedSoftwareStatement = UdapCertificationsAndEndorsementBuilder
                .Create("FhirLabs Administrator Certification", certificationCert)
                .WithExpiration(expiration)
                .WithCertificationDescription("Application can perform all CRUD operations against the FHIR server.")
                .WithCertificationUris(new List<string>()
                    { "https://certifications.fhirlabs.net/criteria/admin-2024.7" })
                .WithDeveloperName("Joe Shook")
                .WithDeveloperAddress("Portland Oregon")
                .WithClientName("Udap.Common.Tests")
                .WithSoftwareId("XUnit.Test")
                .WithSoftwareVersion("0.3.0")
                .WithClientUri("https://certifications.fhirlabs.net")
                .WithLogoUri("https://certifications.fhirlabs.net/logo.png")
                .WithTermsOfService("https://certifications.fhirlabs.net")
                .WithPolicyUri("https://certifications.fhirlabs.net")
                .WithContacts(new List<string>() { "mailto:Joseph.Shook@Surescripts.com", "mailto:JoeShook@gmail.com" })
                // SMART
                //.WithLaunchUri("https://udaped.fhirlabs.net/smart/launch?iss=https://launch.smarthealthit.org/v/r4/fhir&launch=WzAsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCJhdXRoX2ludmFsaWRfY2xpZW50X2lkIiwiIiwiIiwyLDFd")
                .WithRedirectUris(new List<string>
                    { new Uri($"https://client.fhirlabs.net/redirect/{Guid.NewGuid()}").AbsoluteUri })
                .WithIPsAllowed(new List<string>() { "198.51.100.0/24", "203.0.113.55" })
                .WithGrantTypes(new List<string>() { "authorization_code", "refresh_token", "client_credentials" })
                .WithResponseTypes(new HashSet<string> { "code" }) // omit for client_credentials rule
                .WithScope("user/*.write")
                .WithTokenEndpointAuthMethod("private_key_jwt") // 'none' if authorization server allows it.
                // 'client_secret_post': The client uses the HTTP POST parameters
                // as defined in OAuth 2.0, Section 2.3.1.
                // "client_secret_basic": The client uses HTTP Basic as defined in
                // OAuth 2.0, Section 2.3.1.
                //
                // The additional value private_key_jwt may also be used.
                //
                .BuildSoftwareStatement();
        }

        [Fact]
        public void ClampedExpiration_DefaultsToFiveMinutes()
        {
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            var before = DateTime.UtcNow.AddMinutes(5).AddSeconds(-5);
            var after = DateTime.UtcNow.AddMinutes(5).AddSeconds(5);

            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, cert);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            expDt.Should().BeAfter(before).And.BeBefore(after);
            expDt.Should().BeOnOrBefore(cert.NotAfter.ToUniversalTime());
        }

        [Fact]
        public void ClampedExpiration_NegativeOffset_Throws()
        {
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");

            Action act = () => UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.FromSeconds(-1), cert);
            act.Should()
                .Throw<ArgumentOutOfRangeException>()
                .WithParameterName("expirationOffset");
        }

        [Fact]
        public void ClampedExpiration_ExceedsThreeYearPolicy_Clamped()
        {
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");

            var requested = TimeSpan.FromDays(365 * 5); // 5 years
            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(requested, cert);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            var maxPolicy = DateTime.UtcNow.AddYears(3).AddSeconds(10); // allow small timing drift
            expDt.Should().BeBefore(maxPolicy);
        }

        [Fact]
        public void ClampedExpiration_ExceedsCertificate_NotAfterSafetyApplied()
        {
            var cert = new X509Certificate2(Path.Combine("CertStore/issued", "FhirLabsAdminCertification.pfx"), "udap-test");
            var safetySeconds = 7;
            var huge = TimeSpan.FromDays(2000);

            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(huge, cert, safetySeconds);

            var expected = cert.NotAfter.ToUniversalTime().AddSeconds(-safetySeconds);
            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;

            (expected - expDt).Duration().Should().BeLessThan(TimeSpan.FromSeconds(2));
        }

        [Fact]
        public void ClampedExpiration_CertificateTooShort_Throws()
        {
            //
            // This must create a certificate whose NotAfter is within (<=) safetySeconds of now
            // so that certLimit = NotAfter - safetySeconds is <= now and the method throws.
            //
            using var rsa = RSA.Create(2048);
            var now = DateTimeOffset.UtcNow;
            var req = new CertificateRequest("CN=ShortLived", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // NotBefore slightly in past, NotAfter only 4 seconds in the future.
            // Default safetySeconds = 5  => certLimit = (now + 4s) - 5s = now - 1s  => triggers the throw condition.
            var veryShortCert = req.CreateSelfSigned(now.AddSeconds(-30), now.AddSeconds(4));

            Action act = () => UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, veryShortCert);
            act.Should()
                .Throw<ArgumentOutOfRangeException>()
                .WithParameterName("certificate");
        }

        [Fact]
        public void ClampedExpiration_CertificateSoonButNotTooSoon_IsClampedNotThrown()
        {
            //
            // Certificate that expires soon (e.g. 90 seconds) but still outside safety window.
            // Should clamp (not throw) and set exp to NotAfter - safetySeconds.
            //
            using var rsa = RSA.Create(2048);
            var now = DateTimeOffset.UtcNow;
            var req = new CertificateRequest("CN=ShortButValid", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var shortButValidCert = req.CreateSelfSigned(now.AddSeconds(-10), now.AddSeconds(90)); // ~90s lifetime remaining

            var safetySeconds = 5;
            var exp = UdapCertificationsAndEndorsementBuilder.WithClampedExpiration(TimeSpan.Zero, shortButValidCert, safetySeconds);

            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime;
            var expected = shortButValidCert.NotAfter.ToUniversalTime().AddSeconds(-safetySeconds);

            // Allow tiny drift
            (expected - expDt).Duration().Should().BeLessThan(TimeSpan.FromSeconds(2));
        }
    }

    //
    // Register with only client_credentials C&E and then fail when a toke is requested for authorization_code.
    // Even if the standard registration contained authorization_code.  This 
    //

    //
    // Important quote: the OAuth Server can also use the information in the certifications to inform the end user about the client.
    // From https://www.udap.org/udap-certifications-and-endorsements.html
    //


}