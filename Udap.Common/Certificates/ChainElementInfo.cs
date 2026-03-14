#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Udap.Common.Certificates;

/// <summary>
/// Represents a certificate in a validated chain along with any validation problems.
/// This is a platform-independent replacement for <see cref="X509ChainElement"/>
/// that works with BouncyCastle chain validation.
/// </summary>
public class ChainElementInfo
{
    public ChainElementInfo(X509Certificate2 certificate)
    {
        Certificate = certificate;
    }

    public ChainElementInfo(X509Certificate2 certificate, IReadOnlyList<ChainProblem> problems)
    {
        Certificate = certificate;
        Problems = problems;
    }

    /// <summary>
    /// The certificate at this position in the chain.
    /// </summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Validation problems found for this certificate, if any.
    /// </summary>
    public IReadOnlyList<ChainProblem> Problems { get; } = Array.Empty<ChainProblem>();

    /// <summary>
    /// Returns true if this element has any validation problems.
    /// </summary>
    public bool HasProblems => Problems.Count > 0;
}

/// <summary>
/// Describes a single validation problem found during chain validation.
/// </summary>
public class ChainProblem
{
    public ChainProblem(ChainProblemStatus status, string statusInformation)
    {
        Status = status;
        StatusInformation = statusInformation;
    }

    public ChainProblemStatus Status { get; }
    public string StatusInformation { get; }
}

/// <summary>
/// Status flags for chain validation problems.
/// Maps conceptually to <see cref="X509ChainStatusFlags"/> but is platform-independent.
/// </summary>
[Flags]
public enum ChainProblemStatus
{
    None = 0,
    NotTimeValid = 1,
    Revoked = 2,
    NotSignatureValid = 4,
    InvalidBasicConstraints = 8,
    OfflineRevocation = 16,
    UntrustedRoot = 32,
    PartialChain = 64,
    CrlNotFound = 128,
    CrlFetchFailed = 256,
    RevocationStatusUnknown = 512
}

/// <summary>
/// Result of chain validation, returned by async validation methods.
/// Replaces the out parameters from the synchronous API.
/// </summary>
public class ChainValidationResult
{
    public ChainValidationResult(bool isValid, IReadOnlyList<ChainElementInfo> chainElements, long? communityId = null)
    {
        IsValid = isValid;
        ChainElements = chainElements;
        CommunityId = communityId;
    }

    public bool IsValid { get; }
    public IReadOnlyList<ChainElementInfo> ChainElements { get; }
    public long? CommunityId { get; }
}
