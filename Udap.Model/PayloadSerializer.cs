#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Udap.Model.UdapAuthenticationExtensions;

namespace Udap.Model;

/// <summary>
/// Helper that can understand the type being deserialized and use the appropriate converters.
/// Custom extension deserializers can be provided via <see cref="IAuthorizationExtensionDeserializer"/>
/// to support profile-specific extensions (e.g., TEFCA) without modifying core code.
/// </summary>
public static class PayloadSerializer
{
    /// <summary>
    /// <see cref="JsonElement"/> must be of ValueKind of <see cref="JsonValueKind.Object"/>
    /// </summary>
    /// <param name="jsonElement"></param>
    /// <param name="customDeserializers">Optional custom deserializers registered via DI.</param>
    /// <returns></returns>
    public static Dictionary<string, object> Deserialize(
        JsonElement jsonElement,
        IEnumerable<IAuthorizationExtensionDeserializer>? customDeserializers = null)
    {
        var claimValues = new Dictionary<string, object>();
        var customMap = customDeserializers?.ToDictionary(d => d.ExtensionKey);

        foreach (var item in jsonElement.EnumerateObject())
        {
            var rawText = item.Value.GetRawText();
            object? deserializedValue;

            if (customMap != null && customMap.TryGetValue(item.Name, out var customDeserializer))
            {
                deserializedValue = customDeserializer.Deserialize(rawText);
            }
            else
            {
                deserializedValue = DeserializeBuiltIn(item.Name, rawText);
            }

            if (deserializedValue != null)
            {
                claimValues.Add(item.Name, deserializedValue);
            }
        }

        return claimValues;
    }

    /// <summary>
    /// Deserializes from a dictionary of key-value JSON strings.
    /// </summary>
    /// <param name="jsonElement"></param>
    /// <param name="customDeserializers">Optional custom deserializers registered via DI.</param>
    /// <returns></returns>
    public static Dictionary<string, object> Deserialize(
        Dictionary<string, string> jsonElement,
        IEnumerable<IAuthorizationExtensionDeserializer>? customDeserializers = null)
    {
        var claimValues = new Dictionary<string, object>();
        var customMap = customDeserializers?.ToDictionary(d => d.ExtensionKey);

        foreach (var item in jsonElement)
        {
            object? deserializedValue;

            if (customMap != null && customMap.TryGetValue(item.Key, out var customDeserializer))
            {
                deserializedValue = customDeserializer.Deserialize(item.Value);
            }
            else
            {
                deserializedValue = DeserializeBuiltIn(item.Key, item.Value);
            }

            if (deserializedValue != null)
            {
                claimValues.Add(item.Key, deserializedValue);
            }
        }

        return claimValues;
    }

    private static object? DeserializeBuiltIn(string key, string json)
    {
        if (key == UdapConstants.UdapAuthorizationExtensions.Hl7B2B)
        {
            return JsonSerializer.Deserialize<HL7B2BAuthorizationExtension>(json);
        }

        if (key == UdapConstants.UdapAuthorizationExtensions.Hl7B2BUSER)
        {
            return JsonSerializer.Deserialize<HL7B2BUserAuthorizationExtension>(json);
        }

        // Default deserialization for unrecognized types
        return JsonSerializer.Deserialize<object>(json);
    }
}
