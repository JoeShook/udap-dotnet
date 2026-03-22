#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Udap.Tefca.Model;

/// <summary>
/// Constants specific to the TEFCA trust community profile.
/// See SOP: Facilitated FHIR Implementation and SOP: Exchange Purposes (XPs).
/// </summary>
public static class TefcaConstants
{
    public static class UdapAuthorizationExtensions
    {
        /// <summary>
        /// TEFCA IAS Authorization Extension Object key name.
        /// </summary>
        public const string TEFCAIAS = "tefca-ias";

        /// <summary>
        /// TEFCA SMART Authorization Extension Object key name.
        /// </summary>
        public const string TEFCASMART = "tefca_smart";
    }

    public static class TEFCAIASAuthorizationExtension
    {
        public const string Version = "version";
        public const string PurposeOfUse = "purpose_of_use";
        public const string PurposeOfUseCode = "T-IAS";
        public const string UserInformation = "user_information";
        public const string PatientInformation = "patient_information";
        public const string IalVetted = "ial_vetted";
        public const string ConsentPolicy = "consent_policy";
        public const string ConsentReference = "consent_reference";
        public const string IdToken = "id_token";
    }

    public static class TEFCASMARTAuthorizationExtension
    {
        public const string Version = "version";
        public const string PurposeOfUse = "purpose_of_use";
        public const string ConsentPolicy = "consent_policy";
        public const string ConsentReference = "consent_reference";
        public const string IdToken = "id_token";
    }

    /// <summary>
    /// TEFCA Exchange Purpose (XP) codes OID: 2.16.840.1.113883.3.7204.1.5.2.1
    /// </summary>
    public static class ExchangePurposeCodes
    {
        public const string Oid = "2.16.840.1.113883.3.7204.1.5.2.1";

        public const string Treatment = "T-TREAT";
        public const string TefcaRequiredTreatment = "T-TRTMNT";
        public const string Payment = "T-PYMNT";
        public const string HealthCareOperations = "T-HCO";
        public const string CareCoordination = "T-HCO-CC";
        public const string HedisReporting = "T-HCO-HED";
        public const string QualityMeasureReporting = "T-HCO-QM";
        public const string PublicHealth = "T-PH";
        public const string ElectronicCaseReporting = "T-PH-ECR";
        public const string ElectronicLabReporting = "T-PH-ELR";
        public const string IndividualAccessServices = "T-IAS";
        public const string GovernmentBenefitsDetermination = "T-GOVDTRM";
    }

    /// <summary>
    /// TEFCA certification constants.
    /// See SOP: Facilitated FHIR Implementation Section 6.11 Registration #6.
    /// </summary>
    public static class Certification
    {
        public const string BasicAppCertificationUri = "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification";
        public const string BasicAppCertificationName = "TEFCA Basic App Certification";
        public const string ExchangePurposes = "exchange_purposes";
        public const string HomeCommunityId = "home_community_id";
    }

    /// <summary>
    /// TEFCA community URI used in UDAP metadata discovery.
    /// </summary>
    public const string CommunityUri = "urn:oid:2.16.840.1.113883.3.7204.1.5";
}
