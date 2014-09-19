
#Jaylib.Owin.OAuthAuthorization

Provides a Custom OAuth Provider for Implicit Grant. Allowing usage of the included ClaimAuthorize attribute.

Authentication is made by other middleware like OpenIdConnect.

##Usage

    [ClaimAuthorize(CustomClaims.CanChangeAddress)]

### Setup

The Custom provider is used with the OAuthAutorizationServer.

	app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
    {
        AccessTokenFormat =
            new JwtFormat(jwtOptions.Audience,
            symmetricKeyIssuerSecurityTokenProvider),
        ApplicationCanDisplayErrors = true,
        Provider = new CustomOAuthProvider(providerOptions, jwtOptions), 
        AuthorizeEndpointPath = new PathString("/authorize"),
        AllowInsecureHttp = _appConfiguration.AllowInsecureHttp
    });

The provider options allow you issue custom claims and set scope.
	
	new CustomProviderOptions
	               {
	                   SupportedScope = "YourScope",
	                   TransformPrincipal =
	                       principal =>
	                       {
	                           var claims = new List<Claim>();
	
	                           List<Claim> userIdentityTokens =
	                               principal.Claims
	                                   .Where(claim =>
	                                       claim.Type == ClaimTypes.Name || claim.Type == ClaimTypes.NameIdentifier ||
	                                       claim.Type == JwtRegisteredClaimNames.UniqueName ||
	                                       claim.Type == JwtRegisteredClaimNames.Email)
	                                   .ToList();
	
	                           claims.AddRange(userIdentityTokens);
	                           claims.Add(new Claim(CustomClaims.IsCustom, "true"));                  
	
	                           return Task.FromResult(new ClaimsIdentity(claims, "YourAuthType"));
	                       }
	               };
	

The is also utlilities to ease openId configuration, with consent page support.


    var openIdConnectOptions = new OpenIdConnectAuthenticationOptions
                               {
                                   ClientId = _appConfiguration.OpenIdClientId,
                                   Authority = _appConfiguration.OpenIdAuthority,
                                   CallbackPath = new PathString("/openid"),
                                   Notifications = new OpenIdConnectAuthenticationNotifications()
                                                   {
                                                       AuthorizationCodeReceived = async 
                                                           authorizationCodeReceived => await
                                                           new ExternalAuthenticationCompleteHandler(jwtOptions)
                                                           .HandleAsync(authorizationCodeReceived, 																			ConsentBuilder.BuildConsentPageAsync)
                                                   },
                                   AuthenticationMode = AuthenticationMode.Active
                               };

    app.UseOpenIdConnectAuthentication(openIdConnectOptions);


#Blog post:

# Securing Web API end points using OAuth 2.0 and JSON Web Tokens

In this post we're going to create some simple end points using ASP.NET Web Api using OWIN, that we going to secure using a custom claims attribute. We will issue a JSON Web Token, JWT, containing user claims, that the client will use when calling the API.
We're going to due this from sratch, not via any of the templates (SPA, Web API).  

### Scenario
We have a JavaScript web client that should be able to talk to our API. The API requires all requests to be authenticated.

There are many options for securing our Api. 

We could use a static API key distributed to every client. However, a static API key is not ideal for our use case, since it would be easy for anyone to get the API key in clear text from the client. Instead we have to get an API key per client user. 

We could implement a custom API key solution, but why implement a custom one when there are standards like OAuth 2.0. OAuth 2.0 is an authorization framework that allows us to issue and consume tokens in standardized and interoperable way.

In the templates for SPA or Web API there are a lot of helper classes to get you up and running with ***authentication*** from a mix of providers. In our case we also have different levels of privileges for the resource endpoints. Thus we also have need for ***authorization***. This could be achived by using claims-based authorization.

- We want our resource endpoints to configured to authorize through claims.

The next question is how to decide what set of privilege a user has. And how does the client get the claims? The first step is to identify the user.

- We want users to be able to authenticate with OpenID Connect providers like Google or Azure AD. 

Since it is a JavaScript client application, OAuth 2.0 implicit flow is suitable.

#### The Scenario flow

The client makes an access token request, using OAuth 2.0 by navigating with the user agent (web browser).

A request looks like this:

		GET https://apiserver.com/authorize?grant_type=access_token&...

When our server recevies the request access token request we first have to ensure the user to be authenticated via an identity provider. Here we start an authentication flow with OpenID Connect which redirects the user agent to the identity provider and eventually the user agent will make request to our callback URI containing a signed JWT containing the identity claims for the user. 

		GET https://apiserver.com/

When we have the identity of the user we show a user consent HTML page asking the user to confirm authorization for the client to use our API. If the user accepts the request, the user-agent is redirected to the original OAuth request with an additional JWT attached, which we have created by wrapping the original OpenID Connect JWT. Other ways of transferring the identity to ourselves for later use is to use cookies. This should be considered an implementation detail.

Now we are back in the access token request and we know the identity of the user. Here we decide what claims are to be issued to the client based on the identity claims and some ruleset. 

With a set of claims we create a signed JWT containing the identity of the user and additional claims. 

Our server responds the client by sending a redirect response to the user agent based on the redirect_uri the client provided in the first place, now with an access token attached in the fragment part of the URI. 

> *Note* implicit vs explicit
In this simple scenario we're using the implicit grant flow, to keep it simple. You may want a an authorization server with full support for all OAuth 2.0 flows, like server to server and the ability to renew tokens and validate them form the issuer.
[See Implicit flow AKA the client flow](http://techblog.hybris.com/2012/06/05/oauth2-the-implicit-flow-aka-as-the-client-side-flow/) or the oAuth 2.0 specification [specification](http://tools.ietf.org/html/rfc6749#section-4.2).

### Claims authorization

We're going to create an attribute for authorization. In this post we're not going to use an Authorization Server or the "correct" OAuth2 flow for Authorization.
The claims used will be issued by our application upon authentication.

    [ClaimAuthorize(CustomClaims.CanChangeAddress)]

### OWIN Startup

To support this scenario we're going to utilize serveral middleware components. Let's list them in order we need to configure them in our startup class, and their corresponding nuget packages.

- CORS (Microsoft.Owin.Cors)

	`app.UseCors(...)`

The resource endpoint needs to be configured for Cors.


- OAuthAuthorizationServer (Microsoft.Owin.Security.OAuth)
	
	`app.UseOAuthAuthorizationServer(...)`

Used to setup our custom authz server provider. Details in next section.

- JWT Bearer Authentication (Microsoft.Owin.Security.Jwt)

    `app.UseJwtBearerAuthentication(jwtOptions);`

Used for accepting bearer token and setting the IClaimsPrincipal according to the token.

- OpenIdConnect (Microsoft.Owin.Security.OpenIdConnect)

    `app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);`

Used to configure or authentication provider, ex Azure AD or Google.

The core parts for our implementation is around OpenIdConnect and the OAuthAuthorizationServer. Let's focus on them next.

### OWIN OAuthAuthorizationServer Middleware

To use OAuth for authorization we can utilize the *UseOAuthAuthorizationServer* provided by the OAuth middleware.
We're going to use a custom authorization provider.

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AccessTokenFormat =
                    new JwtFormat(jwtOptions.Audience,
                    symmetricKeyIssuerSecurityTokenProvider),
                ApplicationCanDisplayErrors = true,
                Provider = new CustomOAuthProvider(JayLibOptionsHelper.CreateOptions(), jwtOptions), 
                AuthorizeEndpointPath = new PathString("/authorize"),
                AllowInsecureHttp = _appConfiguration.AllowInsecureHttp
            });

#### Custom Provider

The provider is responsible for validating authentication, authorization and redirects in the authorization flow.
This is the main part of our custom authorization implementation.


  	public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        readonly CustomProviderOptions _options;
        private readonly IJwtOptions _jwtOptions;

        public CustomOAuthProvider(CustomProviderOptions options, IJwtOptions jwtOptions)
        {
            _options = options;
            _jwtOptions = jwtOptions;
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            Uri uri;
            if (Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out uri))
            {
                context.Validated();

                return Task.FromResult(0);
            }
            return base.ValidateClientRedirectUri(context);
        }

        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            string uri = context.Request.Uri.ToString();

            CheckScope(context, _options.SupportedScope);

            if (context.IsRequestCompleted)
            {
                return;
            }

            string externalWrappedJwtTokenAsBase64 = context.Request.Query.Get(_jwtOptions.JwtTokenHeader);

            if (string.IsNullOrWhiteSpace(externalWrappedJwtTokenAsBase64))
            {
                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = uri});
                return;
            }
            var tokenValidator = new TokenValidator();
            ClaimsPrincipal principal = tokenValidator.Validate(externalWrappedJwtTokenAsBase64, _jwtOptions);

            if (!principal.Identity.IsAuthenticated)
            {
                string trimmed = uri.Replace(externalWrappedJwtTokenAsBase64, "");

                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = trimmed});
            }
            else
            {
                ClaimsIdentity claimsIdentity = await _options.TransformPrincipal(principal);

                if (!claimsIdentity.Claims.Any())
                {
                    WriteUnauthorizedResponse(context);

                    return;
                }

                string appJwtTokenAsBase64 =
                    JwtTokenHelper.CreateSecurityTokenDescriptor(claimsIdentity.Claims, _jwtOptions).CreateTokenAsBase64();
                    
                var builder = new UriBuilder(context.AuthorizeRequest.RedirectUri);

                const string tokenType = "bearer";
                builder.Fragment = string.Format("access_token={0}&token_type={1}&state={2}&scope={3}",
                    Uri.EscapeDataString(appJwtTokenAsBase64), Uri.EscapeDataString(tokenType),
                    Uri.EscapeDataString(context.AuthorizeRequest.State),
                    Uri.EscapeDataString(_options.SupportedScope));

                string redirectUri = builder.Uri.ToString();

                context.Response.Redirect(redirectUri);
                context.RequestCompleted();
            }
        }

        static void WriteUnauthorizedResponse(OAuthAuthorizeEndpointContext context)
        {
            context.Response.StatusCode = 401;

            using (var writer = new StreamWriter(context.Response.Body))
            {
                var data = new {status = "error", message = "unauthorized"};

                string json = JsonConvert.SerializeObject(data);

                writer.WriteLine(json);
            }
            context.RequestCompleted();
        }

        static void CheckScope(OAuthAuthorizeEndpointContext context, string supportedScope)
        {
            if (Enumerable.Any<string>(context.AuthorizeRequest.Scope) &&
                !Enumerable.Any<string>(context.AuthorizeRequest.Scope, scope => scope.Equals(supportedScope)))
            {
                context.Response.StatusCode = 400;

                using (var writer = new StreamWriter(context.Response.Body))
                {
                    var data =
                        new
                        {
                            status = "error",
                            message =
                                string.Format("only {0} scope is supported", supportedScope)
                        };

                    string json = JsonConvert.SerializeObject(data);

                    writer.WriteLine(json);
                }
                context.RequestCompleted();
            }
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters.Get("client_id")))
            {
                return base.ValidateClientAuthentication(context);
            }
            return Task.FromResult(0);
        }
    }

The *AuthorizeEndpoint* method is central here. The flow described in the scenario section is implemented here.
We're checking the scope, if not valid we return 400 and complete the request.
Then we check for an external token (if the user is authenticated), if not we used the challange method in the middleware. If the user is authenticated we transform (add our custom claims) and sign the token.

To get a user authenticated, we configure the OpenIdConnect Middleware - up next.

### OWIN OpenIdConnect Middleware

Since we're using OWIN, we could use the OpenIdConnect middleware package.
The middleware is configured in the OWIN startup class. Ex with Azure AD;

 		var openIdConnectAuthenticationOptions = new OpenIdConnectAuthenticationOptions
            {
                ClientId =
                    "XXXX-XXXX-XXXX",
                Authority =
                    "https://login.windows.net/XXXXXXXXX.onmicrosoft.com",
                CallbackPath =
                    new PathString("/openid"),
                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    AuthorizationCodeReceived =
                        authorizationCodeReceived =>
                            new ExternalAuthenticationCompleteHandler()
                                .HandleAsync(authorizationCodeReceived)
                },
            };
            app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);

            app.SetDefaultSignInAsAuthenticationType(OpenIdConnectAuthenticationDefaults.AuthenticationType);

*Note* that the ExternalAuthenticationCompleteHandler is a custom class we're going to use to provision claims.

##### AuthorizationCodeReceived

I the *AuthorizationCodeReceived* action we use a custom handler. The handler redirects to our authoriztion end point with the authentication token, when we recieved the users consent. To keep the handler clean we've broken out the token handling to a helper class (see below).

	public class ExternalAuthenticationCompleteHandler
    {
        private readonly IJwtOptions _options;

        public ExternalAuthenticationCompleteHandler(IJwtOptions options)
        {
            _options = options;
        }

        public async Task HandleAsync(AuthorizationCodeReceivedNotification authorizationCodeReceived, Func<IOwinResponse, string, Task> createConsent)
        {
            string tokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(authorizationCodeReceived.JwtSecurityToken.Claims, _options).CreateTokenAsBase64();

            authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri +=
                string.Format("&{0}={1}", _options.JwtTokenHeader, tokenAsBase64);

            await createConsent(authorizationCodeReceived.Response, authorizationCodeReceived.AuthenticationTicket.Properties.RedirectUri);

            authorizationCodeReceived.HandleResponse();
        }
    }


##### JwtTokenHelper

I the *JwtTokenHelper* we use our sign the JwtSecurityToken using the 
[JwtSecurityTokenHandler](http://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.jwtsecuritytokenhandler(v=vs.114).aspx)


	public static class JwtTokenHelper
    {
        const string HmacSha256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        const string Sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";

        public static SecurityTokenDescriptor CreateSecurityTokenDescriptor(IEnumerable<Claim> claims, IJwtOptions options)
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


> By using the OpenIdConnect middleware for *authentication* and the OAuth middleware together with a CustomProvider and a Custom handler, we have got the core parts for issuing our own token containing claims.


### ClaimAuthorizeAttribute

To authorize against claims we use a custom attribute. We then could use this much like the Authorization attribute, but against our claims.

    [ClaimAuthorize(CustomClaims.CanChangeAddress)]

The custom attribute inherites from AuthorizaAttribute.

 	public class ClaimAuthorizeAttribute : AuthorizeAttribute
    {
        readonly List<string> _claimTypes =new List<string>();  
        public ClaimAuthorizeAttribute(string requiredClaimType, params string[] requiredClaimTypes)
        {
            _claimTypes.Add(requiredClaimType);
            if (requiredClaimTypes != null)
            {
                _claimTypes.AddRange(requiredClaimTypes);
            }
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            ClaimsPrincipal claimsPrincipal = actionContext.Request.GetOwinContext().Authentication.User;

            if (claimsPrincipal == null || !claimsPrincipal.Identity.IsAuthenticated)
            {
                return false;
            }

            var hasAllClaims =
                _claimTypes.All(
                    type =>
                        claimsPrincipal.HasClaim(
                            claim => claim.Type.Equals(type, StringComparison.InvariantCultureIgnoreCase)));

            return hasAllClaims;
        }
    }

??? Both string and params ???

We get the current principal from the OwinContext.
Here we check if the uses is authenticated, and then is the ClaimsPrinciapal has to requied claim.

### Resource endpoints

All resource endpoint should be secured by checking claims via our custom attribute. If the client doesn't have a valid token, is should respond with a 401, to tell the client to get a token. All resource endpoints could also be configured for Cors.

### Conclusion

In this post we explored what needs to be done for moving form the pure authentication scenarios offen seen in the templates, towards authorization via OAuth. We implemented the OAuth Implicit Grant flow, by using the OAuth Middleware writing our own OAuthProvider and ClaimsAuthorize attribute. It might seem as much custom code, but it's few core parts, that might be reused. Our server is also one step closer to a future scenario with federated authorization trough a exteranal authorization server.

Our scenario is catered for a javascript app, but also works with app using AuthenticationBroker and alike. But we havn't implemeted the flow ([Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1)) for server to server scenarios. This would be next step to explore...

Enjoy!

### Resources

- [http://pfelix.wordpress.com/2012/11/27/json-web-tokens-and-the-new-jwtsecuritytokenhandler-class/](http://pfelix.wordpress.com/2012/11/27/json-web-tokens-and-the-new-jwtsecuritytokenhandler-class/)
- [http://engineering.talis.com/articles/elegant-api-auth-angular-js/](http://engineering.talis.com/articles/elegant-api-auth-angular-js/)
- [http://blogs.msdn.com/b/webdev/archive/2013/09/20/understanding-security-features-in-spa-template.aspx](http://blogs.msdn.com/b/webdev/archive/2013/09/20/understanding-security-features-in-spa-template.aspx)
- [https://auth0.com/blog/2014/01/27/ten-things-you-should-know-about-tokens-and-cookies/](https://auth0.com/blog/2014/01/27/ten-things-you-should-know-about-tokens-and-cookies/)
- [http://leastprivilege.com/2014/03/24/the-web-api-v2-oauth2-authorization-server-middlewareis-it-worth-it/](http://leastprivilege.com/2014/03/24/the-web-api-v2-oauth2-authorization-server-middlewareis-it-worth-it/)


