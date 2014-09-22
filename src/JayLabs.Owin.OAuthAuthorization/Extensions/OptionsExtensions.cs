using System;
using System.Collections.Generic;
using System.Text;
using JayLabs.Owin.OAuthAuthorization.Tokens;
using Microsoft.Owin.Security.Jwt;

namespace JayLabs.Owin.OAuthAuthorization.Extensions
{

    public static class OptionsExtensions
    {
       public static IIssuerSecurityTokenProvider CreateKeyIssuerSecurityTokenProvider(this IJwtOptions options)
       {
           var symmetricKeyBytes = Encoding.UTF8.GetBytes(options.JwtSigningKeyAsUtf8);
           var symmetricKeyAsBase64 = Convert.ToBase64String(symmetricKeyBytes);

           return new SymmetricKeyIssuerSecurityTokenProvider(
               options.Issuer, symmetricKeyAsBase64);
       }

       public static JwtBearerAuthenticationOptions CreateJwtBearerAuthenticationOptions(this IJwtOptions options)
       {
           var providers = new[]
                            {
                                options.CreateKeyIssuerSecurityTokenProvider()
                            };

           return options.CreateJwtBearerAuthenticationOptions(jwtOptions => providers);
       }

       public static JwtBearerAuthenticationOptions CreateJwtBearerAuthenticationOptions(this IJwtOptions options, Func<IJwtOptions, IEnumerable<IIssuerSecurityTokenProvider>> providersFunc)
       {
            return new JwtBearerAuthenticationOptions
            {
                AllowedAudiences = new List<string> { options.Audience },
                IssuerSecurityTokenProviders =providersFunc(options)
            };
        }
    }
}