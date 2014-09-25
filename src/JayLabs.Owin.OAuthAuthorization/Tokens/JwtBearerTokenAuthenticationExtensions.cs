using System;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace JayLabs.Owin.OAuthAuthorization.Tokens
{
    public static class JwtBearerTokenAuthenticationExtensions
    {
        public static IAppBuilder UseJwtBearerAuthenticationWithTokenProvider(this IAppBuilder app,
            JwtBearerTokenAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            JwtFormat jwtFormat;
            if (options.JwtBearerOptions.TokenValidationParameters != null)
            {
                jwtFormat = new JwtFormat(options.JwtBearerOptions.TokenValidationParameters);
            }
            else
            {
                jwtFormat = new JwtFormat(options.JwtBearerOptions.AllowedAudiences, options.JwtBearerOptions.IssuerSecurityTokenProviders);
            }
            if (options.JwtBearerOptions.TokenHandler != null)
            {
                jwtFormat.TokenHandler = options.JwtBearerOptions.TokenHandler;
            }

            var bearerOptions = new OAuthBearerAuthenticationOptions
            {
                Realm = options.JwtBearerOptions.Realm,
                Provider = options.JwtBearerOptions.Provider,
                AccessTokenFormat = jwtFormat,
                AuthenticationMode = options.JwtBearerOptions.AuthenticationMode,
                AuthenticationType = options.JwtBearerOptions.AuthenticationType,
                Description = options.JwtBearerOptions.Description
            };

            bearerOptions.AccessTokenProvider = new JwtBearerTokenProvider(options.JwtOptions);

            app.UseOAuthBearerAuthentication(bearerOptions);

            return app;
        }
    }
}