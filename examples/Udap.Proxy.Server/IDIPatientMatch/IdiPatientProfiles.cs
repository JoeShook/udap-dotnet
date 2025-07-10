namespace Udap.Proxy.Server.IDIPatientMatch
{
    public static class Constants
    {
        public static class IdiPatientProfiles
        {
            public const string IdiPatient = "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient";
            public const string IdiPatientL0 = "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient-L0";
            public const string IdiPatientL1 = "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient-L1";
            public const string IdiPatientL2 = "http://hl7.org/fhir/us/identity-matching/StructureDefinition/IDI-Patient-L2";

            public static readonly HashSet<string> ValidProfiles = new()
            {
                IdiPatient,
                IdiPatientL0,
                IdiPatientL1,
                IdiPatientL2
            };
        }
    }
}
