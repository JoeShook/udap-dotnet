using Hl7.Fhir.Model;

public interface IIdiPatientMatchInValidator
{
    Task<OperationOutcome?> Validate(Parameters parameters);
}