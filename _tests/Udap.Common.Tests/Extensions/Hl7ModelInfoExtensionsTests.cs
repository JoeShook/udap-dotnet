#region (c) 2024 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using Udap.Common.Extensions;
using Xunit;

namespace Udap.Common.Tests.Extensions;
public class Hl7ModelInfoExtensionsTests
{
    readonly Func<string, bool> treatmentSpecification = r => r is "Patient" or "AllergyIntolerance" or "Condition" or "Encounter";

    [Fact]
    public void Test()
    {
        var v1Scopes = Hl7ModelInfoExtensions.BuildHl7FhirV1Scopes(new List<string>() { "patient", "user" }, treatmentSpecification);
        Assert.Contains("patient/Patient.read", v1Scopes);

        var v2Scopes = Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification);
        Assert.Contains("patient/Patient.r", v2Scopes);
        Assert.Contains("patient/Patient.rs", v2Scopes);

        var v2ScopesCruds = Hl7ModelInfoExtensions.BuildHl7FhirV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification, "cruds");
        Assert.Contains("patient/Patient.cruds", v2ScopesCruds);
        Assert.Contains("patient/Patient.rs", v2ScopesCruds);

        var v1AndV2Scopes = Hl7ModelInfoExtensions.BuildHl7FhirV1AndV2Scopes(new List<string>() { "patient", "user" }, treatmentSpecification, "read", "cruds");
        Assert.Contains("patient/Patient.cruds", v1AndV2Scopes);
        Assert.Contains("patient/Patient.rs", v1AndV2Scopes);
        Assert.Contains("patient/Patient.read", v1AndV2Scopes);
        Assert.Contains("user/Patient.cruds", v1AndV2Scopes);
        Assert.Contains("user/Patient.rs", v1AndV2Scopes);
        Assert.Contains("user/Patient.read", v1AndV2Scopes);

        var userScopes = Hl7ModelInfoExtensions.BuildHl7FhirV1AndV2Scopes("user", treatmentSpecification, "read", "cruds");
        Assert.Contains("user/Patient.cruds", userScopes);
        Assert.Contains("user/Patient.rs", userScopes);
        Assert.Contains("user/Patient.read", userScopes);

    }
}
