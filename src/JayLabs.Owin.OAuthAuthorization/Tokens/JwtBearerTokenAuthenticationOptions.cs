using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Owin.Security.Jwt;

namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public class JwtBearerTokenAuthenticationOptions
    {
        readonly JwtBearerAuthenticationOptions _jwtBearerOptions;
        readonly JwtOptions _jwtOptions;

        public JwtBearerTokenAuthenticationOptions(JwtOptions jwtOptions)
        {
            if (jwtOptions == null)
            {
                throw new ArgumentNullException("jwtOptions");
            }

            byte[] symmetricKeyBytes = Encoding.UTF8.GetBytes(jwtOptions.JwtSigningKeyAsUtf8);
            string symmetricKeyAsBase64 = Convert.ToBase64String(symmetricKeyBytes);

            var symmetricKeyIssuerSecurityTokenProvider = new SymmetricKeyIssuerSecurityTokenProvider(
                jwtOptions.Issuer, symmetricKeyAsBase64);

            var providers = new IIssuerSecurityTokenProvider[]
                            {
                                symmetricKeyIssuerSecurityTokenProvider
                            };

            _jwtBearerOptions = new JwtBearerAuthenticationOptions
            {
                AllowedAudiences = new List<string> { jwtOptions.Audience },
                IssuerSecurityTokenProviders = providers
            };

            _jwtOptions = jwtOptions;
        }

        public JwtBearerAuthenticationOptions JwtBearerOptions
        {
            get { return _jwtBearerOptions; }
        }

        public JwtOptions JwtOptions
        {
            get { return _jwtOptions; }
        }

        public JwtFormat JwtFormat
        {
            get
            {
                return new JwtFormat(JwtBearerOptions.AllowedAudiences, JwtBearerOptions.IssuerSecurityTokenProviders);
            }
        }
    }
}