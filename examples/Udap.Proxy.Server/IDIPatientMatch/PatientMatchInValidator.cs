using Firely.Fhir.Validation;
using Hl7.Fhir.Model;
using Udap.Proxy.Server.IDIPatientMatch;

public class PatientMatchInValidator : IPatientMatchInValidator
{
    private readonly IIdiPatientRules _idiPatientRules;
    private readonly Validator _fhirProfileValidator;

    public PatientMatchInValidator(
        IIdiPatientRules idiPatientRules,
        Validator fhirProfileValidator)
    {
        _idiPatientRules = idiPatientRules;
        _fhirProfileValidator = fhirProfileValidator;
    }

    public async Task<OperationOutcome?> Validate(Parameters parameters)
    {
        var outcome = _fhirProfileValidator.Validate(
            parameters, 
            "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" 
        );

        if (outcome.Errors > 0)
        {
            return outcome;
        }

        var inputPatient = parameters.Parameter.FirstOrDefault(p => p.Name == "resource")?.Resource;
        var patient = inputPatient as Patient;
        
        var (isValid, error) = _idiPatientRules.ValidatePatientProfile(patient);
        if (!isValid)
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Invalid,
                        Diagnostics = error
                    }
                }
            };
        }

        return null; // No issues, valid
    }
}