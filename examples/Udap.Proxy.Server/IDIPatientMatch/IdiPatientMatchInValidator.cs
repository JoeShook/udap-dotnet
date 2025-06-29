using Firely.Fhir.Packages;
using Firely.Fhir.Validation;
using Hl7.Fhir.Model;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using Udap.Proxy.Server.IDIPatientMatch;

public class IdiPatientMatchInValidator : IIdiPatientMatchInValidator
{
    private readonly IIdiPatientRules _idiPatientRules;
    private readonly Validator _fhirProfileValidator;

    public IdiPatientMatchInValidator(IIdiPatientRules idiPatientRules)
    {
        _idiPatientRules = idiPatientRules;

        IAsyncResourceResolver packageSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.r4b.core-4.3.0.tgz");
        var coreSource = new CachedResolver(packageSource);
        var coreSnapshot = new SnapshotSource(coreSource);
        var terminologySource = new LocalTerminologyService(coreSnapshot);
        IAsyncResourceResolver idiSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.us.identity-matching-2.0.0-ballot.tgz");
        var source = new MultiResolver(idiSource, coreSnapshot);
        var settings = new ValidationSettings { ConformanceResourceResolver = source };
        _fhirProfileValidator = new Validator(source, terminologySource, null, settings);
    }

    public OperationOutcome? Validate(Parameters parameters)
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