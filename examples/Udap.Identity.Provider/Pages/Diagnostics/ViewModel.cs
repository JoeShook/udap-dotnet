// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using System.Buffers.Text;
using Duende.IdentityModel;
using Microsoft.AspNetCore.Authentication;
using System.Text;
using System.Text.Json;

namespace Udap.Identity.Provider.Pages.Diagnostics;

public class ViewModel
{
    public ViewModel(AuthenticateResult result)
    {
        AuthenticateResult = result;

        if (result.Properties.Items.ContainsKey("client_list"))
        {
            var encoded = result.Properties.Items["client_list"];
            var bytes = System.Buffers.Text.Base64Url.DecodeFromChars(encoded);
            var value = Encoding.UTF8.GetString(bytes);

            Clients = JsonSerializer.Deserialize<string[]>(value);
        }
    }

    public AuthenticateResult AuthenticateResult { get; }
    public IEnumerable<string> Clients { get; } = new List<string>();
}