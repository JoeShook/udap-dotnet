#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Nodes;
using Sigil.Common.Data.Entities;

namespace Sigil.Did.Services;

/// <summary>
/// Synthesizes a DID Document JSON representation from a persisted <see cref="DidDocument"/>
/// and its <see cref="VerificationMethod"/>s. For did:key the document is fully derivable from
/// the DID + keys; for did:web (later) it will also include service endpoints.
/// </summary>
public static class DidDocumentBuilder
{
    public static string Build(DidDocument document, IEnumerable<VerificationMethod> verificationMethods)
    {
        var context = new JsonArray { "https://www.w3.org/ns/did/v1" };

        var purposeBuckets = new Dictionary<string, JsonArray>(StringComparer.OrdinalIgnoreCase);
        var methodArray = new JsonArray();

        foreach (var vm in verificationMethods)
        {
            switch (vm.KeyAlgorithm)
            {
                case "Ed25519":
                    if (!ContextContains(context, "https://w3id.org/security/suites/ed25519-2020/v1"))
                        context.Add("https://w3id.org/security/suites/ed25519-2020/v1");
                    methodArray.Add(new JsonObject
                    {
                        ["id"] = vm.MethodId,
                        ["type"] = "Ed25519VerificationKey2020",
                        ["controller"] = document.Did,
                        ["publicKeyMultibase"] = vm.PublicKeyMultibase
                    });
                    break;
                default:
                    methodArray.Add(new JsonObject
                    {
                        ["id"] = vm.MethodId,
                        ["type"] = "Multikey",
                        ["controller"] = document.Did,
                        ["publicKeyMultibase"] = vm.PublicKeyMultibase
                    });
                    break;
            }

            foreach (var purpose in SplitPurposes(vm.Purposes))
            {
                if (!purposeBuckets.TryGetValue(purpose, out var bucket))
                {
                    bucket = new JsonArray();
                    purposeBuckets[purpose] = bucket;
                }
                bucket.Add(vm.MethodId);
            }
        }

        var doc = new JsonObject
        {
            ["@context"] = context,
            ["id"] = document.Did,
            ["verificationMethod"] = methodArray
        };

        foreach (var (purpose, ids) in purposeBuckets)
            doc[purpose] = ids;

        if (document.Deactivated)
            doc["deactivated"] = true;

        return doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static IEnumerable<string> SplitPurposes(string purposes) =>
        purposes.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool ContextContains(JsonArray context, string value)
    {
        foreach (var node in context)
        {
            if (node is JsonValue v && v.TryGetValue<string>(out var s) && s == value)
                return true;
        }
        return false;
    }
}
