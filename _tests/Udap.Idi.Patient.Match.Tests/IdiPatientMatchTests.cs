using Firely.Fhir.Packages;
using Firely.Fhir.Validation;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Specification.Source;
using Hl7.Fhir.Specification.Terminology;
using System.Text.Json;
using Xunit.Abstractions;
using Task = System.Threading.Tasks.Task;

namespace Udap.Idi.Patient.Match.Tests;

public class IdiPatientMatchTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public IdiPatientMatchTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    /// <summary>
    /// experimenter test
    /// </summary>
    [Fact]
    public void ValidateInParameters()
    {
        // var packageSource = new DirectorySource(@"IDIPatientMatch/packages/hl7.fhir.r4b.core-4.3.0.tgz", new DirectorySourceSettings { IncludeSubDirectories = true });
        IAsyncResourceResolver packageSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.r4b.core-4.3.0.tgz");
        //IAsyncResourceResolver packageSource = FhirPackageSource.CreateCorePackageSource(ModelInfo.ModelInspector, FhirRelease.R4B, "https://packages.simplifier.net");

        var coreSource = new CachedResolver(packageSource);
        var coreSnapshot = new SnapshotSource(coreSource);
        var terminologySource = new LocalTerminologyService(coreSnapshot);

        // Load the FHIR package
        IAsyncResourceResolver idiSource = new FhirPackageSource(ModelInfo.ModelInspector, @"IDIPatientMatch/packages/hl7.fhir.us.identity-matching-2.0.0-ballot.tgz");

        var source = new MultiResolver(idiSource, coreSnapshot);

        var settings = new ValidationSettings { ConformanceResourceResolver = source };
        // Create a validator
        var validator = new Validator(source, terminologySource, null, settings);

        // Load the Parameter resource to be validated
        var json = File.ReadAllText("testdata/idi-match-in-parameters.json");
        var parser = new FhirJsonParser();
        var parameterResource = parser.Parse<Parameters>(json);

        // Validate the resource
        var result = validator.Validate(parameterResource);

        // Output the validation results
        if (result.Success)
        {
            _testOutputHelper.WriteLine("Validation succeeded!");
        }
        else
        {
            _testOutputHelper.WriteLine("Validation failed:");
            foreach (var issue in result.Issue)
            {
                _testOutputHelper.WriteLine($"- {issue.Severity}: {issue.Details.Text}");
            }
        }
    }

    [Fact (Skip = "Build the Country codes")]
    public async Task GetCountryCodes()
    {
        var client = new FhirClient("https://tx.fhir.org/r4");
        var expanded = await client.ExpandValueSetAsync(new Uri("http://hl7.org/fhir/ValueSet/iso3166-1-3"));

        var codes = expanded.Expansion.Contains
            .Select(c => c.Code)
            .Distinct()
            .ToList();

        await File.WriteAllTextAsync("iso3166-1-alpha3-codes.json", JsonSerializer.Serialize(codes, new JsonSerializerOptions { WriteIndented = true }));

        // Print a few codes
        foreach (var code in codes.Take(10))
        {
            _testOutputHelper.WriteLine(code);
        }
    }

}