#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Common.Standard;
/// <summary>
/// Experimental OID constants for UDAP access control encoded in X.509 certificate extensions.
/// </summary>
public static class ObjectIdentifiers
{
    /// <summary>
    /// Experimental UDAP OID namespace for access control extensions.
    /// </summary>
    public static class UdapExperimental
    {
        /// <summary>
        /// OIDs for UDAP access control policies.
        /// </summary>
        public static class UdapAccessControl
        {
            /// <summary>
            /// General CRUD and admin access control OIDs.
            /// </summary>
            public static class General
            {
                /// <summary>Create access OID.</summary>
                public const string Create = "1.3.6.1.4.1.12345.1.1";
                /// <summary>Read access OID.</summary>
                public const string Read = "1.3.6.1.4.1.12345.1.2";
                /// <summary>Update access OID.</summary>
                public const string Update = "1.3.6.1.4.1.12345.1.3";
                /// <summary>Delete access OID.</summary>
                public const string Delete = "1.3.6.1.4.1.12345.1.4";
                /// <summary>Admin access OID.</summary>
                public const string Admin = "1.3.6.1.4.1.12345.1.5";
            }
        }
    }
}
