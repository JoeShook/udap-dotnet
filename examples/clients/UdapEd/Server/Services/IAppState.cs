﻿#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Specialized;
using IdentityModel.Client;
using Udap.Model.Registration;
using UdapEd.Shared.Model;
using UdapEd.Shared.Model.Discovery;

namespace UdapEd.Server.Services;

public interface IAppState
{
    string BaseUrl { get; }
    
    string Community { get; }

    OrderedDictionary BaseUrls { get; set; }

    public MetadataVerificationModel? MetadataVerificationModel { get; }

    RawSoftwareStatementAndHeader? SoftwareStatementBeforeEncoding { get; }

    UdapRegisterRequest? UdapRegistrationRequest { get; }
    Oauth2FlowEnum Oauth2Flow { get; }

    RegistrationDocument? RegistrationDocument { get; }


    UdapClientCredentialsTokenRequestModel? ClientCredentialsTokenRequest { get; }

    CertificateStatusViewModel? ClientCertificateInfo { get; }

    UdapAuthorizationCodeTokenRequestModel? AuthorizationCodeTokenRequest { get; }

    AccessCodeRequestResult? AccessCodeRequestResult { get;  }

    LoginCallBackResult? LoginCallBackResult { get;  }

    TokenResponseModel? AccessTokens { get;  }

    ClientStatus Status { get; }

    AuthorizationCodeRequest?AuthorizationCodeRequest { get; }
}