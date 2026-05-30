#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.Services.Signing;
using Sigil.Vc.ViewModels;

namespace Sigil.Vc.Services;

public class CredentialIssuanceService
{
    private const string AssertionMethodPurpose = "assertionMethod";
    private static readonly string[] DefaultContexts = ["https://www.w3.org/ns/credentials/v2"];

    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ISigningProvider _signingProvider;
    private readonly ILogger<CredentialIssuanceService> _logger;

    public CredentialIssuanceService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ISigningProvider signingProvider,
        ILogger<CredentialIssuanceService> logger)
    {
        _dbFactory = dbFactory;
        _signingProvider = signingProvider;
        _logger = logger;
    }

    public async Task<CredentialIssuanceResult> IssueAsync(
        CredentialIssuanceRequest request, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var schema = await db.CredentialSchemas.FindAsync([request.CredentialSchemaId], ct)
            ?? throw new InvalidOperationException($"Credential schema {request.CredentialSchemaId} not found.");

        var trustDomain = await db.TrustDomains.FindAsync([request.TrustDomainId], ct)
            ?? throw new InvalidOperationException($"Trust domain {request.TrustDomainId} not found.");

        var issuerDoc = await db.DidDocuments
            .Include(d => d.VerificationMethods)
            .FirstOrDefaultAsync(d => d.Id == request.IssuerDidDocumentId, ct)
            ?? throw new InvalidOperationException($"Issuer DID {request.IssuerDidDocumentId} not found.");

        if (issuerDoc.Deactivated)
            throw new InvalidOperationException($"Issuer DID {issuerDoc.Did} is deactivated.");

        var assertionKey = issuerDoc.VerificationMethods.FirstOrDefault(vm =>
            vm.Purposes.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Contains(AssertionMethodPurpose, StringComparer.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"Issuer DID {issuerDoc.Did} has no verification method with purpose '{AssertionMethodPurpose}'.");

        var validationError = CredentialSchemaService.ValidateClaims(schema.ClaimsSchemaJson, request.ClaimsJson);
        if (validationError != null)
            throw new InvalidOperationException($"Claims failed schema validation: {validationError}");

        var claimsNode = JsonNode.Parse(request.ClaimsJson) as JsonObject
            ?? throw new InvalidOperationException("Claims JSON must be a JSON object.");

        var credentialId = $"urn:uuid:{Guid.NewGuid()}";
        var issuedAt = DateTime.UtcNow;
        var validity = request.ValidityDaysOverride ?? schema.DefaultValidityDays;
        var validUntil = validity.HasValue ? issuedAt.AddDays(validity.Value) : (DateTime?)null;

        var types = new List<string> { "VerifiableCredential" };
        types.Add(string.IsNullOrWhiteSpace(schema.TypeUri) ? schema.Name : schema.TypeUri);

        var header = CredentialJwtBuilder.BuildVcHeader(assertionKey);
        var payload = CredentialJwtBuilder.BuildVcPayload(
            issuerDid: issuerDoc.Did,
            subjectDid: request.SubjectDid,
            credentialId: credentialId,
            contexts: DefaultContexts,
            types: types,
            credentialSubjectClaims: claimsNode,
            issuedAt: issuedAt,
            validUntil: validUntil);

        var jwt = await CredentialJwtBuilder.BuildAsync(assertionKey, header, payload, _signingProvider, ct);

        var entity = new IssuedCredential
        {
            TrustDomainId = trustDomain.Id,
            CredentialSchemaId = schema.Id,
            IssuerDidDocumentId = issuerDoc.Id,
            SubjectDid = request.SubjectDid,
            ClaimsJson = request.ClaimsJson,
            Format = "jwt_vc",
            SignedCredential = jwt,
            CredentialId = credentialId,
            IssuedAt = issuedAt,
            ValidUntil = validUntil,
        };

        db.IssuedCredentials.Add(entity);
        await db.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Issued credential {CredentialId} (schema {SchemaId}) by {IssuerDid} to {SubjectDid}",
            credentialId, schema.Id, issuerDoc.Did, request.SubjectDid);

        return new CredentialIssuanceResult(entity.Id, credentialId, jwt);
    }

    public async Task<List<IssuedCredentialViewModel>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var creds = await db.IssuedCredentials
            .Include(c => c.TrustDomain)
            .Include(c => c.Schema)
            .Include(c => c.IssuerDid)
            .OrderByDescending(c => c.IssuedAt)
            .ToListAsync(ct);

        return creds.Select(ToViewModel).ToList();
    }

    public async Task<IssuedCredentialViewModel?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var cred = await db.IssuedCredentials
            .Include(c => c.TrustDomain)
            .Include(c => c.Schema)
            .Include(c => c.IssuerDid)
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        return cred == null ? null : ToViewModel(cred);
    }

    public async Task RevokeAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.IssuedCredentials.FindAsync([id], ct);
        if (entity == null || entity.Revoked) return;

        entity.Revoked = true;
        entity.RevokedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("Revoked credential {CredentialId}", entity.CredentialId);
    }

    private static IssuedCredentialViewModel ToViewModel(IssuedCredential entity)
    {
        var (headerJson, payloadJson, _) = CredentialJwtBuilder.Decompose(entity.SignedCredential);
        return new IssuedCredentialViewModel
        {
            Id = entity.Id,
            TrustDomainId = entity.TrustDomainId,
            TrustDomainName = entity.TrustDomain?.Name ?? string.Empty,
            CredentialId = entity.CredentialId,
            SubjectDid = entity.SubjectDid,
            IssuerDid = entity.IssuerDid?.Did ?? string.Empty,
            SchemaName = entity.Schema?.Name ?? string.Empty,
            Format = entity.Format,
            SignedCredential = entity.SignedCredential,
            DecodedHeaderJson = headerJson,
            DecodedPayloadJson = payloadJson,
            ClaimsJson = entity.ClaimsJson,
            IssuedAt = entity.IssuedAt,
            ValidUntil = entity.ValidUntil,
            Revoked = entity.Revoked,
            RevokedAt = entity.RevokedAt
        };
    }
}
