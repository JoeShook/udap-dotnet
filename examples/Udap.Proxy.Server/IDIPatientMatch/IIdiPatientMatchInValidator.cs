using Hl7.Fhir.Model;

public interface IIdiPatientMatchInValidator
{
    OperationOutcome? Validate(Parameters parameters);
}