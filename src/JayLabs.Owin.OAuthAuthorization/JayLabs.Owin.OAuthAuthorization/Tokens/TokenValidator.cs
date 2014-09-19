using System;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel.Security.Tokens;
using System.Text;

namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public class TokenValidator
    {
        public ClaimsPrincipal Validate(string jwtTokenAsBase64, IJwtOptions options)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            string keyAsUtf8 = options.JwtSigningKeyAsUtf8;

            byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyAsUtf8);

            SecurityToken signingToken = new BinarySecretSecurityToken(keyAsBytes);
            var tokenValidationParameters = new TokenValidationParameters
                                            {
                                                IssuerSigningToken = signingToken,
                                                ValidAudience = options.Audience,
                                                ValidIssuer = options.Issuer
                                            };
            ClaimsPrincipal principal;
            try
            {
                SecurityToken validatedToken;
                principal = tokenHandler.ValidateToken(jwtTokenAsBase64, tokenValidationParameters,
                    out validatedToken);
            }
            catch (Exception ex)
            {
                Debug.Write(ex, "error");
                principal = new ClaimsPrincipal(new ClaimsIdentity(authenticationType:""));
            }

            return principal;
        }
    }
}