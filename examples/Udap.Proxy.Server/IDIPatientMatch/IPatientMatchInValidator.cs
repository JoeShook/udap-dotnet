using Hl7.Fhir.Model;

public interface IPatientMatchInValidator
{
    Task<OperationOutcome?> Validate(Parameters parameters);
}