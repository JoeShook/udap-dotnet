﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Udap.Model.UdapAuthenticationExtensions;

public class B2BAuthorizationExtensionConverter : JsonConverter<B2BAuthorizationExtension>
{
    public override B2BAuthorizationExtension Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader, options);
        var extension = new B2BAuthorizationExtension();
        foreach (var kvp in dictionary)
        {
            if (kvp.Value is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.Array)
            {
                var list = JsonSerializer.Deserialize<List<string>>(jsonElement.GetRawText(), options);
                var properties = typeof(B2BAuthorizationExtension).GetProperties(BindingFlags.Public | BindingFlags.Instance);
                
                foreach (var property in properties)
                {
                    var jsonPropertyNameAttribute = property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false)
                        .FirstOrDefault() as JsonPropertyNameAttribute;

                    if (jsonPropertyNameAttribute != null && jsonPropertyNameAttribute.Name == kvp.Key)
                    {
                        if (property.CanWrite)
                        {
                            property.SetValue(extension, list);
                            break;
                        }
                    }
                }
            }
            else
            {
                extension[kvp.Key] = kvp.Value;
            }
        }
        return extension;
    }

    public override void Write(Utf8JsonWriter writer, B2BAuthorizationExtension value, JsonSerializerOptions options)
    {
        var dictionary = new Dictionary<string, object>(value);
        var properties = value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        foreach (var property in properties)
        {
            if (property.CanRead && property.GetValue(value) is object propertyValue)
            {
                var jsonPropertyName = property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false)
                    .FirstOrDefault() as JsonPropertyNameAttribute;
                var propertyName = jsonPropertyName?.Name ?? property.Name;
                dictionary[propertyName] = propertyValue;
            }
        }
        JsonSerializer.Serialize(writer, dictionary, options);
    }
}
