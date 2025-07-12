using Hl7.Fhir.Model;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OperationContext
{
    public HttpContext HttpContext { get; set; }
    public Parameters Parameters { get; set; }
}