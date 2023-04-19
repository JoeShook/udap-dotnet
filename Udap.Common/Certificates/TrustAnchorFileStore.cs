﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Udap.Common.Models;

namespace Udap.Common.Certificates;

public class TrustAnchorFileStore : ITrustAnchorStore
{
    private readonly IOptionsMonitor<UdapFileCertStoreManifest> _manifest;
    private readonly ILogger<TrustAnchorFileStore> _logger;
    private readonly string? _resourceServerName;
    private bool _resolved;


    public TrustAnchorFileStore(
        IOptionsMonitor<UdapFileCertStoreManifest> manifest,
        ILogger<TrustAnchorFileStore> logger,
        string? resourceServerName = null)
    {
        _manifest = manifest;
        _resourceServerName = resourceServerName;
        _logger = logger;

        _manifest.OnChange(_ =>
        {
            _resolved = false;
        });
    }

    public Task<ITrustAnchorStore> Resolve()
    {
        if (_resolved == false)
        {
            LoadCertificates(_manifest.CurrentValue);
        }
        _resolved = true;

        return Task.FromResult(this as ITrustAnchorStore);
    }

    public ICollection<Anchor> AnchorCertificates { get; set; } = new HashSet<Anchor>();

    // TODO convert to Lazy<T> to protect from race conditions
    private void LoadCertificates(UdapFileCertStoreManifest manifestCurrentValue)
    {
        ICollection<Common.Metadata.Community>? communities;

        if (_resourceServerName == null)
        {
            _logger.LogInformation($"Loading first ResourceServers from UdapFileCertStoreManifest:ResourceServers.");

            communities = manifestCurrentValue.ResourceServers.FirstOrDefault()?.Communities;
        }
        else
        {
            _logger.LogInformation($"Loading UdapFileCertStoreManifest:ResourceServers:Name {_resourceServerName}.");

            communities = manifestCurrentValue
                .ResourceServers
                .SingleOrDefault(r => r.Name == _resourceServerName)
                ?.Communities;
        }

        _logger.LogInformation($"{communities?.Count ?? 0} communities loaded");

        if (communities == null) return;

        foreach (var community in communities)
        {
            var intermediates = new List<Intermediate>();
            if (community.Intermediates.Any())
            {
                foreach (var intermediateFilePath in community.Intermediates)
                {
                    intermediates.Add(new Intermediate(new X509Certificate2(Path.Combine(AppContext.BaseDirectory, intermediateFilePath))));
                }
            }

            foreach (var communityAnchor in community.Anchors)
            {
                if (communityAnchor.FilePath == null)
                {
                    throw new Exception($"Missing file path in on of the anchors {nameof(community.Anchors)}");
                }

                var path = Path.Combine(AppContext.BaseDirectory, communityAnchor.FilePath);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"Cannot find file: {path}");
                }

                AnchorCertificates.Add(new Anchor(new X509Certificate2(path))
                {
                    Community = community.Name,
                    Intermediates = intermediates
                });
            }
        }
    }

}