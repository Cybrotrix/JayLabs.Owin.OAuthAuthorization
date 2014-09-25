using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using Microsoft.Owin.Security.OAuth;

namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public static class JwtTokenHelper
    {
        const string HmacSha256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

        public static SecurityTokenDescriptor CreateSecurityTokenDescriptor(IEnumerable<Claim> claims, JwtOptions options)
        {
            string keyAsUtf8 =  options.JwtSigningKeyAsUtf8;

            byte[] keyAsBytes = Encoding.UTF8.GetBytes(keyAsUtf8);

            var claimsIdentity = new ClaimsIdentity(claims,
                OAuthDefaults.AuthenticationType);

            var descriptor = new SecurityTokenDescriptor()
                             {
                                 SigningCredentials = new SigningCredentials(
                                     new InMemorySymmetricSecurityKey(keyAsBytes),
                                     HmacSha256,
                                     Sha256),
                                 Subject = claimsIdentity,
                                 TokenIssuerName = options.Issuer,
                                 AppliesToAddress = options.Audience
                             };
            return descriptor;
        }

        public static string CreateTokenAsBase64(this SecurityTokenDescriptor securityTokenDescriptor)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            SecurityToken securityToken = tokenHandler.CreateToken(securityTokenDescriptor);
            string token = tokenHandler.WriteToken(securityToken);

            string tokenAsBase64 = token;

            return tokenAsBase64;
        }
    }

   
}