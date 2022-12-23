namespace Udap.Server.Entities;

public class UdapClient : Duende.IdentityServer.EntityFramework.Entities.Client
{
    public ICollection<UdapClientSecrets>? UdapClientSecrets { get; set; }
}