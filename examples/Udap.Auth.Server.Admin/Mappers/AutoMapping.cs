using System.Security.Cryptography.X509Certificates;
using Udap.Common.Models;
using Udap.Util.Extensions;

namespace Udap.Auth.Server.Admin.Mappers;

public static class ModelMapper
{
    public static ViewModel.Community ToViewModel(this Community model)
    {
        return new ViewModel.Community
        {
            Id = model.Id,
            Name = model.Name,
            Enabled = model.Enabled,
            Default = model.Default,
            Anchors = model.Anchors?.Select(a => a.ToViewModel()).ToHashSet() ?? new HashSet<ViewModel.Anchor>(),
            Certifications = model.Certifications?.Select(c => new ViewModel.Certification
            {
                Id = c.Id.ToString(),
                Name = c.Name
            }).ToHashSet() ?? new HashSet<ViewModel.Certification>()
        };
    }

    public static Community ToModel(this ViewModel.Community vm)
    {
        return new Community
        {
            Id = (int)vm.Id,
            Name = vm.Name ?? string.Empty,
            Enabled = vm.Enabled,
            Default = vm.Default,
            Anchors = vm.Anchors.Select(a => a.ToModel()).ToList(),
            Certifications = vm.Certifications.Select(c => new Certification
            {
                Id = long.TryParse(c.Id, out var id) ? id : 0,
                Name = c.Name ?? string.Empty
            }).ToList()
        };
    }

    public static ViewModel.Anchor ToViewModel(this Anchor model)
    {
        return new ViewModel.Anchor
        {
            Id = model.Id,
            Enabled = model.Enabled,
            Name = model.Name,
            Community = model.Community,
            CommunityId = model.CommunityId,
            Certificate = !string.IsNullOrEmpty(model.Certificate)
                ? X509Certificate2.CreateFromPem(model.Certificate)
                : null,
            Thumbprint = model.Thumbprint,
            BeginDate = model.BeginDate,
            EndDate = model.EndDate,
            Intermediates = model.Intermediates?.Select(i => i.ToViewModel()).ToList()
                ?? new List<ViewModel.IntermediateCertificate>()
        };
    }

    public static Anchor ToModel(this ViewModel.Anchor vm)
    {
        return new Anchor
        {
            Id = vm.Id,
            Enabled = vm.Enabled,
            Name = vm.Name ?? string.Empty,
            Community = vm.Community,
            CommunityId = vm.CommunityId,
            Certificate = vm.Certificate?.ToPemFormat() ?? string.Empty,
            Thumbprint = vm.Thumbprint ?? string.Empty,
            BeginDate = vm.BeginDate ?? DateTime.MinValue,
            EndDate = vm.EndDate ?? DateTime.MinValue
        };
    }

    public static ViewModel.IntermediateCertificate ToViewModel(this Intermediate model)
    {
        return new ViewModel.IntermediateCertificate
        {
            Id = model.Id,
            Enabled = model.Enabled,
            Name = model.Name,
            Certificate = !string.IsNullOrEmpty(model.Certificate)
                ? X509Certificate2.CreateFromPem(model.Certificate)
                : null,
            Thumbprint = model.Thumbprint,
            BeginDate = model.BeginDate,
            EndDate = model.EndDate
        };
    }

    public static Intermediate ToModel(this ViewModel.IntermediateCertificate vm)
    {
        return new Intermediate
        {
            Id = vm.Id,
            Enabled = vm.Enabled,
            Name = vm.Name ?? string.Empty,
            Certificate = vm.Certificate?.ToPemFormat() ?? string.Empty,
            Thumbprint = vm.Thumbprint ?? string.Empty,
            BeginDate = vm.BeginDate ?? DateTime.MinValue,
            EndDate = vm.EndDate ?? DateTime.MinValue
        };
    }

    public static ViewModel.Certification ToViewModel(this Certification model)
    {
        return new ViewModel.Certification
        {
            Id = model.Id.ToString(),
            Name = model.Name
        };
    }

    public static ViewModel.IssuedCertificate ToViewModel(this IssuedCertificate model)
    {
        return new ViewModel.IssuedCertificate
        {
            Enabled = true,
            Name = model.Thumbprint,
            Community = model.Community,
            Certificate = model.Certificate,
            BeginDate = model.Certificate.NotBefore,
            EndDate = model.Certificate.NotAfter
        };
    }

    public static ICollection<ViewModel.Community> ToViewModels(this IEnumerable<Community> models)
    {
        return models.Select(m => m.ToViewModel()).ToList();
    }

    public static ICollection<ViewModel.IntermediateCertificate> ToViewModels(this IEnumerable<Intermediate> models)
    {
        return models.Select(m => m.ToViewModel()).ToList();
    }
}
