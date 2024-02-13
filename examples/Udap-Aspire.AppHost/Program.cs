var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.FhirLabsApi>("fhirlabsapi");

builder.AddProject<Projects.Udap_Auth_Server>("udap-auth-server");

builder.AddProject<Projects.Udap_Certificates_Server>("udap-certificates-server")
    .WithLaunchProfile("http");

builder.AddProject<Projects.Udap_Identity_Provider>("udap-identity-provider");

builder.AddProject<Projects.Udap_Identity_Provider_2>("udap-identity-provider-2");

builder.Build().Run();
