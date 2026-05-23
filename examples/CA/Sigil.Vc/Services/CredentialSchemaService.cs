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
using Json.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigil.Common.Data;
using Sigil.Common.Data.Entities;
using Sigil.Common.ViewModels;

namespace Sigil.Vc.Services;

public class CredentialSchemaService
{
    private readonly IDbContextFactory<SigilDbContext> _dbFactory;
    private readonly ILogger<CredentialSchemaService> _logger;

    public CredentialSchemaService(
        IDbContextFactory<SigilDbContext> dbFactory,
        ILogger<CredentialSchemaService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<List<CredentialSchema>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CredentialSchemas
            .OrderByDescending(s => s.IsPreset)
            .ThenBy(s => s.Name)
            .ToListAsync(ct);
    }

    public async Task<CredentialSchema?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CredentialSchemas.FindAsync([id], ct);
    }

    public async Task<CredentialSchema> SaveAsync(CredentialSchema entity, CancellationToken ct = default)
    {
        // Validate the schema text parses as a JSON Schema before persisting.
        try { JsonSchema.FromText(entity.ClaimsSchemaJson); }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"ClaimsSchemaJson is not a valid JSON Schema: {ex.Message}", ex);
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.CredentialSchemas.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.CredentialSchemas.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.CredentialSchemas.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.CredentialSchemas.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int schemaId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var count = await db.IssuedCredentials.CountAsync(c => c.CredentialSchemaId == schemaId, ct);
        if (count > 0)
            impacts.Add(new ImpactItem(count, "issued credential(s) reference this schema", ImpactSeverity.Warning));

        return impacts;
    }

    /// <summary>
    /// Validates a claims object against the schema. Returns null on success;
    /// returns an error message on failure.
    /// </summary>
    public static string? ValidateClaims(string schemaJson, string claimsJson)
    {
        JsonSchema schema;
        JsonNode? claims;
        try { schema = JsonSchema.FromText(schemaJson); }
        catch (Exception ex) { return $"Schema parse error: {ex.Message}"; }

        try { claims = JsonNode.Parse(claimsJson); }
        catch (Exception ex) { return $"Claims parse error: {ex.Message}"; }

        var results = schema.Evaluate(claims, new EvaluationOptions
        {
            OutputFormat = OutputFormat.List
        });

        if (results.IsValid) return null;

        var errors = new List<string>();
        CollectErrors(results, errors);
        return errors.Count == 0
            ? "Claims failed schema validation."
            : string.Join("; ", errors);
    }

    private static void CollectErrors(EvaluationResults results, List<string> sink)
    {
        if (results.HasErrors && results.Errors != null)
        {
            foreach (var (key, val) in results.Errors)
                sink.Add($"{results.EvaluationPath}: {key}: {val}");
        }
        if (results.Details != null)
        {
            foreach (var detail in results.Details)
                CollectErrors(detail, sink);
        }
    }
}
