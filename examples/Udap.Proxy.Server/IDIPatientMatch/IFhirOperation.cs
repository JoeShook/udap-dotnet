using Hl7.Fhir.Model;


namespace Udap.Proxy.Server.IDIPatientMatch;

public interface IFhirOperation
{
    string Name { get; }
    string Description { get; }
    OperationDefinition GetDefinition();
    Task<Resource> ExecuteAsync(OperationContext context, CancellationToken cancellationToken);
}