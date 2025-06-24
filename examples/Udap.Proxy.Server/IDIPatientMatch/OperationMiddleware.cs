using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using T = System.Threading.Tasks;

namespace Udap.Proxy.Server.IDIPatientMatch;

public class OperationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly Dictionary<string, IFhirOperation> _operations;

    public OperationMiddleware(RequestDelegate next, IEnumerable<IFhirOperation> operations)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _operations = operations.ToDictionary(op => op.Name, op => op);
    }

    public async T.Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;

        if (path != null &&
            (path.Equals("/fhir/r4/Patient/$match", StringComparison.OrdinalIgnoreCase) ||
             path.Equals("/fhir/r4/Patient/$idi-match", StringComparison.OrdinalIgnoreCase)))
        {
            var operationName = path.Split('/').Last();
            if (_operations.TryGetValue(operationName, out var operation))
            {
                // Parse the request body as FHIR Parameters
                var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
                var parameters = new FhirJsonParser().Parse<Parameters>(requestBody);

                var opContext = new OperationContext
                {
                    HttpContext = context,
                    Parameters = parameters
                };

                // Execute the operation
                var result = await operation.ExecuteAsync(opContext, context.RequestAborted);

                // Serialize and return the result
                context.Response.ContentType = "application/fhir+json";
                var json = await new FhirJsonSerializer().SerializeToStringAsync(result);
                await context.Response.WriteAsync(json);
                return;
            }
        }

        // Forward non-operation requests to the next middleware (YARP)
        await _next(context);
    }
}
