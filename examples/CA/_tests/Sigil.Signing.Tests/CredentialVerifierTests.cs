#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Did.Services;
using Sigil.Did.ViewModels;
using Sigil.Vc.Services;
using Sigil.Vc.ViewModels;

namespace Sigil.Signing.Tests;

public class CredentialVerifierTests
{
    private const string MemberSchema = """
        {
          "type": "object",
          "required": ["name", "role"],
          "properties": {
            "name": { "type": "string" },
            "role": { "type": "string" }
          },
          "additionalProperties": false
        }
        """;

    private readonly TestDbContextFactory _dbFactory = new();
    private readonly LocalSigningProvider _signing = new();

    [Fact]
    public async Task Verify_ValidCredential_ReturnsValid()
    {
        var jwt = await IssueOneAsync();
        var verifier = new CredentialVerifier(_dbFactory);

        var result = await verifier.VerifyAsync(jwt);

        result.Valid.ShouldBeTrue(result.Message);
    }

    [Fact]
    public async Task Verify_TamperedSignature_ReturnsInvalid()
    {
        var jwt = await IssueOneAsync();
        var verifier = new CredentialVerifier(_dbFactory);

        // Tamper a character near the start of the signature segment.
        // (The very last char in base64url only encodes a couple of bits and flipping it
        //  can yield bytes equivalent to the original.)
        var lastDot = jwt.LastIndexOf('.');
        var sig = jwt[(lastDot + 1)..];
        var ch = sig[0];
        var flippedFirst = ch == 'A' ? 'B' : 'A';
        var tampered = jwt[..(lastDot + 1)] + flippedFirst + sig[1..];

        var result = await verifier.VerifyAsync(tampered);

        result.Valid.ShouldBeFalse();
        result.Message.ShouldContain("Signature");
    }

    [Fact]
    public async Task Verify_UnknownIssuer_ReturnsInvalid()
    {
        var jwt = await IssueOneAsync();

        // Wipe DID Documents from the DB; verifier will fail to resolve issuer.
        await using (var db = _dbFactory.CreateDbContext())
        {
            db.DidDocuments.RemoveRange(db.DidDocuments);
            await db.SaveChangesAsync();
        }

        var verifier = new CredentialVerifier(_dbFactory);
        var result = await verifier.VerifyAsync(jwt);

        result.Valid.ShouldBeFalse();
        result.Message.ShouldContain("Unknown issuer");
    }

    [Fact]
    public async Task Verify_MalformedJwt_ReturnsInvalid()
    {
        var verifier = new CredentialVerifier(_dbFactory);
        var result = await verifier.VerifyAsync("not.a.valid-jwt-because.too.many.segments");

        result.Valid.ShouldBeFalse();
    }

    private async Task<string> IssueOneAsync()
    {
        var didService = new DidIssuanceService(
            _dbFactory, [new DidKeyMethodProvider()], _signing, NullLogger<DidIssuanceService>.Instance);

        await using var db = _dbFactory.CreateDbContext();
        var td = new TrustDomain { Name = "td" };
        var tmpl = new DidTemplate { Name = "key-ed25519", Method = "key", KeyAlgorithm = "Ed25519", DefaultPurposes = "assertionMethod" };
        var schema = new CredentialSchema
        {
            Name = "MemberCredential",
            Format = "jwt_vc",
            ClaimsSchemaJson = MemberSchema,
            DefaultValidityDays = 365
        };
        db.TrustDomains.Add(td);
        db.DidTemplates.Add(tmpl);
        db.CredentialSchemas.Add(schema);
        await db.SaveChangesAsync();

        var mint = await didService.IssueDidAsync(new DidIssuanceRequest(td.Id, tmpl.Id));

        var credentialService = new CredentialIssuanceService(_dbFactory, _signing, NullLogger<CredentialIssuanceService>.Instance);
        var result = await credentialService.IssueAsync(new CredentialIssuanceRequest(
            td.Id, schema.Id, mint.DidDocumentId,
            "did:key:zSubject",
            """{ "name": "Joe", "role": "engineer" }"""));

        return result.SignedCredential;
    }
}
