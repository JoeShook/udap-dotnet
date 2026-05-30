#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.Common.Data.Entities;

public class CredentialSchema
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Optional VC `type` URI added to the credential's `type` array.</summary>
    public string? TypeUri { get; set; }

    /// <summary>Securing format: "jwt_vc" for Phase D. Future: "vc+sd-jwt", "ldp_vc".</summary>
    public string Format { get; set; } = "jwt_vc";

    /// <summary>JSON Schema document describing required/permitted claims for credentialSubject.</summary>
    public string ClaimsSchemaJson { get; set; } = "{}";

    public int? DefaultValidityDays { get; set; }

    public bool IsPreset { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<IssuedCredential> IssuedCredentials { get; set; } = new List<IssuedCredential>();
}
