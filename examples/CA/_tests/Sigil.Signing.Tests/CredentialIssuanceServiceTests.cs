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

public class CredentialIssuanceServiceTests
{
    private const string MemberSchema = """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "required": ["name", "role"],
          "properties": {
            "name": { "type": "string", "minLength": 1 },
            "role": { "type": "string", "minLength": 1 }
          },
          "additionalProperties": false
        }
        """;

    private readonly TestDbContextFactory _dbFactory = new();
    private readonly LocalSigningProvider _signing = new();

    [Fact]
    public async Task IssueAsync_ValidClaims_ProducesJwtVc()
    {
        var (trustDomainId, schemaId, issuerDidId) = await SeedAsync();
        var service = new CredentialIssuanceService(_dbFactory, _signing, NullLogger<CredentialIssuanceService>.Instance);

        var result = await service.IssueAsync(new CredentialIssuanceRequest(
            TrustDomainId: trustDomainId,
            CredentialSchemaId: schemaId,
            IssuerDidDocumentId: issuerDidId,
            SubjectDid: "did:key:zSubject123",
            ClaimsJson: """{ "name": "Joe", "role": "engineer" }"""));

        result.CredentialId.ShouldStartWith("urn:uuid:");
        result.SignedCredential.Split('.').Length.ShouldBe(3); // header.payload.signature

        var (headerJson, payloadJson, _) = CredentialJwtBuilder.Decompose(result.SignedCredential);
        headerJson.ShouldContain("\"alg\":\"EdDSA\"");
        headerJson.ShouldContain("\"typ\":\"vc+jwt\"");
        payloadJson.ShouldContain("\"sub\":\"did:key:zSubject123\"");
        payloadJson.ShouldContain("\"role\":\"engineer\"");
    }

    [Fact]
    public async Task IssueAsync_InvalidClaims_Throws()
    {
        var (trustDomainId, schemaId, issuerDidId) = await SeedAsync();
        var service = new CredentialIssuanceService(_dbFactory, _signing, NullLogger<CredentialIssuanceService>.Instance);

        // Missing required "role" field.
        await Should.ThrowAsync<InvalidOperationException>(async () =>
            await service.IssueAsync(new CredentialIssuanceRequest(
                trustDomainId, schemaId, issuerDidId, "did:key:zX", """{ "name": "Joe" }""")));
    }

    [Fact]
    public async Task IssueAsync_DeactivatedIssuer_Throws()
    {
        var (trustDomainId, schemaId, issuerDidId) = await SeedAsync();

        await using (var db = _dbFactory.CreateDbContext())
        {
            var doc = await db.DidDocuments.FindAsync(issuerDidId);
            doc!.Deactivated = true;
            await db.SaveChangesAsync();
        }

        var service = new CredentialIssuanceService(_dbFactory, _signing, NullLogger<CredentialIssuanceService>.Instance);

        await Should.ThrowAsync<InvalidOperationException>(async () =>
            await service.IssueAsync(new CredentialIssuanceRequest(
                trustDomainId, schemaId, issuerDidId, "did:key:zX", """{ "name": "Joe", "role": "eng" }""")));
    }

    private async Task<(int TrustDomainId, int SchemaId, int IssuerDidId)> SeedAsync()
    {
        // Mint issuer DID
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
        return (td.Id, schema.Id, mint.DidDocumentId);
    }
}
