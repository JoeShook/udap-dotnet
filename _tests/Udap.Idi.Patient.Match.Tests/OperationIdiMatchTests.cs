using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Microsoft.AspNetCore.Http;
using Udap.Proxy.Server.IDIPatientMatch;
using Xunit.Abstractions;
using T = System.Threading.Tasks;

namespace Udap.Idi.Patient.Match.Tests;

public class OperationIdiMatchTests : IClassFixture<OperationIdiMatchFixture>
{
    private readonly OperationIdiMatchFixture _fixture;
    private readonly ITestOutputHelper _output;

    public OperationIdiMatchTests(OperationIdiMatchFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    /// <summary>
    /// Simple valid test
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async T.Task ExecuteAsync_ValidatesJsonFile()
    {
        // Load Parameters resource from JSON
        var json = File.ReadAllText("testdata/idi-match-in-parameters.json");
        var parameters = new FhirJsonParser().Parse<Parameters>(json);

        // Prepare OperationContext
        var context = new OperationContext
        {
            HttpContext = new DefaultHttpContext(),
            Parameters = parameters
        };

        // Act
        var result = await _fixture.OpIdiMatch.ExecuteAsync(context, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        // Add more asserts as needed based on expected result type
    }

    [Theory]
    [MemberData(nameof(PatientTestCases))]
    public async T.Task ExecuteAsync_ValidatesPatient_PositiveAndNegative(
        Parameters parameters, 
        bool expectedSuccess, 
        string? expectedErrorSubstring,
        string? expectedDiagnosticsSubstring)
    {
        var context = new OperationContext
        {
            HttpContext = new DefaultHttpContext(),
            Parameters = parameters
        };

        _fixture.SetupRequestServices(context.HttpContext);

        // Act
        var result = await _fixture.OpIdiMatch.ExecuteAsync(context, CancellationToken.None);

        // Assert
        if (expectedSuccess)
        {
            try
            {
                Assert.IsNotType<OperationOutcome>(result);
            }
            catch (Exception)
            {
                _output.WriteLine("Result (unexpected OperationOutcome):");
                _output.WriteLine(await new FhirJsonSerializer(new SerializerSettings(){Pretty = true}).SerializeToStringAsync(result));
                throw;
            }
        }
        else
        {
            try
            {
                var outcome = Assert.IsType<OperationOutcome>(result);
                if (expectedErrorSubstring != null)
                {
                    Assert.Contains(expectedErrorSubstring, string.Join(" ", outcome.Issue.Select(i => i.Details.Text)));
                }
                if (expectedDiagnosticsSubstring != null)
                {
                    Assert.Contains(expectedDiagnosticsSubstring, string.Join(" ", outcome.Issue.Select(i => i.Diagnostics)));
                }
            }
            catch (Exception)
            {
                _output.WriteLine("Result (expected OperationOutcome, but got):");
                _output.WriteLine(await new FhirJsonSerializer(new SerializerSettings() { Pretty = true }).SerializeToStringAsync(result));
                throw;
            }
        }
    }

    [Theory]
    [MemberData(nameof(PatientTestCases))]
    public async T.Task IdiPatientMatchInValidator_ValidatesPatient_PositiveAndNegative(
        Parameters parameters,
        bool expectedSuccess,
        string? expectedErrorSubstring,
        string? expectedDiagnosticsSubstring)
    {
        // Act
        var outcome = _fixture.IdiPatientMatchInValidator.Validate(parameters);

        // Assert
        if (expectedSuccess)
        {
            try
            {
                Assert.Null(outcome);
            }
            catch (Exception)
            {
                _output.WriteLine("Validator returned unexpected OperationOutcome:");
                _output.WriteLine("Result (unexpected OperationOutcome):");
                _output.WriteLine(await new FhirJsonSerializer(new SerializerSettings() { Pretty = true }).SerializeToStringAsync(outcome));
                throw;
            }
        }
        else
        {
            try
            {
                Assert.NotNull(outcome);
                if (expectedErrorSubstring != null)
                {
                    Assert.Contains(expectedErrorSubstring, string.Join(" ", outcome.Issue.Select(i => i.Details.Text)));
                }
                if (expectedDiagnosticsSubstring != null)
                {
                    Assert.Contains(expectedDiagnosticsSubstring, string.Join(" ", outcome.Issue.Select(i => i.Diagnostics)));
                }
            }
            catch (Exception)
            {
                _output.WriteLine("Result (expected OperationOutcome, but got):");
                _output.WriteLine(await new FhirJsonSerializer(new SerializerSettings() { Pretty = true }).SerializeToStringAsync(outcome));
                throw;
            }
        }
    }

    public static IEnumerable<object[]> PatientTestCases()
    {
        // Positive test: valid Parameters with Patient
        yield return new object[]
        {
            new Parameters
            {
                Meta = new Meta
                {
                    Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" }
                },
                Parameter = new List<Parameters.ParameterComponent>
                {
                    new Parameters.ParameterComponent
                    {
                        Name = "patient",
                        Resource = new Hl7.Fhir.Model.Patient
                        {
                            Name = new List<HumanName> { new HumanName { Family = "Patient", Given = new[] { "Max" } } },
                            BirthDate = "1992-05-17",
                            Meta = new Meta
                            {
                                Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient-L1" }
                            },
                            Identifier = new List<Identifier>
                            {
                                new Identifier
                                {
                                    Type = new CodeableConcept
                                    {
                                        Coding = new List<Coding>
                                        {
                                            new Coding
                                            {
                                                System = "http://terminology.hl7.org/CodeSystem/v2-0203",
                                                Code = "PPN"
                                            }
                                        }
                                    },
                                    System = "http://hl7.org/fhir/sid/passport-AUS",
                                    Value = "1234-234-1243-12345678901"
                                }
                            }
                        }
                    }
                }
            },
            true, // expectedSuccess
            null,  // expectedErrorSubstring
            null  // expectedDiagnostics
        };

        // Negative test: given or family name missing
        yield return new object[]
        {
            new Parameters
            {
                // Meta = new Meta
                // {
                //     Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" }
                // },
                Parameter = new List<Parameters.ParameterComponent>
                {
                    new Parameters.ParameterComponent
                    {
                        Name = "patient",
                        Resource = new Hl7.Fhir.Model.Patient
                        {
                            Name = new List<HumanName> { new HumanName { Text = "joe shook"} },
                            BirthDate = "1992-05-17",
                            Meta = new Meta
                            {
                                Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient" }
                            }
                        }
                    }
                }
            },
            false, // expectedSuccess
            "Either the given or family name SHALL be present",  // expectedErrorSubstring
            null  // expectedDiagnostics
        };

        // Negative test: missing patient resource
        yield return new object[]
        {
            new Parameters
            {
                Meta = new Meta
                {
                    Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" }
                },
                Parameter = new List<Parameters.ParameterComponent>()
            },
            false, // expectedSuccess
            "Instance count is 0, which is not within the specified cardinality of 1..1", // expectedErrorSubstring
            null  // expectedDiagnostics
        };

        // Negative test: missing patient profile
        yield return new object[]
        {
            new Parameters
            {
                Meta = new Meta
                {
                    Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" }
                },
                Parameter = new List<Parameters.ParameterComponent>
                {
                    new Parameters.ParameterComponent
                    {
                        Name = "patient",
                        Resource = new Hl7.Fhir.Model.Patient
                        {
                            Name = new List<HumanName> { new HumanName { Family = "Patient", Given = new[] { "Max" } } },
                            BirthDate = "1992-05-17",
                            Identifier = new List<Identifier>
                            {
                                new Identifier
                                {
                                    Type = new CodeableConcept
                                    {
                                        Coding = new List<Coding>
                                        {
                                            new Coding
                                            {
                                                System = "http://terminology.hl7.org/CodeSystem/v2-0203",
                                                Code = "PPN"
                                            }
                                        }
                                    },
                                    System = "http://hl7.org/fhir/sid/passport-AUS",
                                    Value = "1234-234-1243-12345678901"
                                }
                            }
                        }
                        // No Meta.Profile
                    }
                }
            },
            false, // expectedSuccess
            null, // expectedErrorSubstring
            "Input patient must conform to one of the IDI-Patient profiles"  // expectedDiagnostics
        };

        // Negative test: missing patient profile
        yield return new object[]
        {
            new Parameters
            {
                Meta = new Meta
                {
                    Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/idi-match-input-parameters" }
                },
                Parameter = new List<Parameters.ParameterComponent>
                {
                    new Parameters.ParameterComponent
                    {
                        Name = "patient",
                        Resource = new Hl7.Fhir.Model.Patient
                        {
                            Name = new List<HumanName> { new HumanName { Family = "Patient", Given = new[] { "Max" } } },
                            BirthDate = "1992-05-17",
                            Meta = new Meta
                            {
                                Profile = new[] { "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient-L1" }
                            }
                        }
                        // No Meta.Profile
                    }
                }
            },
            false, // expectedSuccess
            "Instance failed constraint idi-L1", // expectedErrorSubstring
            null  // expectedDiagnostics
        };

        // Add more cases as needed...
    }
}