#region (c) 2022 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common;

/// <summary>
/// Error codes for UDAP certificate store operations.
/// </summary>
public enum UdapStoreError
{
    /// <summary>A unique constraint violation occurred in the store.</summary>
    UniqueConstraint,
}

/// <summary>
/// Thrown when attempting to add a community that already exists in the store.
/// </summary>
public class DuplicateCommunityException : Exception
{
    /// <inheritdoc />
    public DuplicateCommunityException(string message) : base(message)
    {
    }
}

/// <summary>
/// Thrown when attempting to add a trust anchor that already exists in the store.
/// </summary>
public class DuplicateAnchorException : Exception
{
    /// <inheritdoc />
    public DuplicateAnchorException(string message) : base(message)
    {
    }
}

/// <summary>
/// Thrown when attempting to add an intermediate certificate that already exists in the store.
/// </summary>
public class DuplicateIntermediateCertificateException : Exception
{
    /// <inheritdoc />
    public DuplicateIntermediateCertificateException(string message) : base(message)
    {
    }
}