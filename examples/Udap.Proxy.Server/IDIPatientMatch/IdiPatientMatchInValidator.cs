using Firely.Fhir.Validation;
using Hl7.Fhir.Model;
using Udap.Proxy.Server.IDIPatientMatch;

public class IdiPatientMatchInValidator : IPatientMatchInValidator
{
    private readonly IIdiPatientRules _idiPatientRules;
    private readonly Validator _fhirProfileValidator;

    public IdiPatientMatchInValidator(
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

        var inputPatient = parameters.Parameter.FirstOrDefault(p => p.Name == "patient")?.Resource;
        var patient = inputPatient as Patient;

        if (patient == null)
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Invalid,
                        Diagnostics = "Cannot find a Patient resource in the parameter named 'resource'."
                    }
                }
            };
        }

        var patientProfiles = patient.Meta?.Profile ?? new List<string>();
        if (!patientProfiles.Any(p => Constants.IdiPatientProfiles.ValidProfiles.Contains(p)))
        {
            return new OperationOutcome
            {
                Issue = new List<OperationOutcome.IssueComponent>
                {
                    new OperationOutcome.IssueComponent
                    {
                        Severity = OperationOutcome.IssueSeverity.Error,
                        Code = OperationOutcome.IssueType.Invalid,
                        Diagnostics = "Input patient must conform to one of the IDI-Patient profiles." +
                                      "<br>https://build.fhir.org/ig/HL7/fhir-identity-matching-ig/artifacts.html#structures-resource-profiles"
                    }
                }
            };
        }

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