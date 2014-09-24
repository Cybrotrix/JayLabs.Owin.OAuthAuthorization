# Securing Web API end points using Claims, OAuth 2.0 and JSON Web Tokens

In this post we're going to create some simple end points using ASP.NET Web Api with [OWIN](http://owin.org/), that we going to secure using a custom claims attribute. We will issue a [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html), JWT, containing user claims, that the client will use when calling the API.
We're going to due this from sratch, not via any of the templates (SPA, Web Api).  

### Scenario
We have a JavaScript web client that should be able to talk to our API. The API requires all requests to be authenticated.

There are many options for securing our Api. 

We could use a static API key distributed to every client. However, a static API key is not ideal for our use case, since it would be easy for anyone to get the API key in clear text from the client. Instead we have to get an API key per client user. 

We could implement a custom API key solution, but why implement a custom one when there are standards like OAuth 2.0. OAuth 2.0 is an authorization framework that allows us to issue and consume tokens in standardized and interoperable way.

In the templates for SPA or Web Api there are a lot of helper classes to get you up and running with ***authentication*** from a mix of providers. In our case we also have different levels of privileges for the resource endpoints. Thus we also have need for ***authorization***. This could be achived by using claims-based authorization.

- We want our resource endpoints to configured to authorize through claims.

The next question is how to decide what set of privilege a user has. And how does the client get the claims? The first step is to identify the user.

- We want users to be able to authenticate with OpenID Connect providers like Google or Azure AD. 

Since it is a JavaScript client application, [OAuth 2.0 implicit grant](http://tools.ietf.org/html/rfc6749#section-4.2) flow is suitable.

#### The Scenario flow

The client makes an access token request, using OAuth 2.0 by navigating with the user agent (web browser).

A request looks like this:

		GET https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html

When our server recevies the access token request we first have to ensure the user to be authenticated via an identity provider. Here we start an authentication flow with OpenID Connect which redirects the user agent to the identity provider. Eventually the user agent will make a request to our callback URI, https://myapiserver.com/openid, containing a signed JWT with the identity claims for the user. 

		POST https://apiserver.com/openid

When we have the identity of the user we show a user consent HTML page asking the user to confirm authorization for the client to use our API. At the final stage of authentication, we issue a redirect to our consent page. If the user accepts the grant request, the user-agent makes a request to the original OAuth request URI with an additional JWT and a consent answer attached. The JWT is created by wrapping the original OpenID Connect JWT. Other ways of transferring the identity to ourselves for later use is to use cookies. This should be considered an implementation detail.

        GET https://apiserver.com/consent/consent?redirectUri={0}&consentParamName=consentAnswer
        
        where {0} is the original authorization URI (https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html)

        POST https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html

        request body:

        consentAnswer=accepted&jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215aXNzdWVyLmNvbSIsImV4cCI6MTQxMTQ3MzQ3OCwiaWF0IjoxNDExNDczNDc4LCJqdGkiOiJpZDEyMzQ1NiIsInR5cCI6IkpXVCJ9.CLjy_BDRIcYyWOQWZ3nJXWAEGpGLNSzgB5qjkrtZKJA

Now we are back in the access token request and we know the identity of the user and we have a consent answer. Here we decide what claims are to be issued to the client based on the identity claims and some ruleset. 

With a set of claims we create a signed JWT containing the identity of the user and additional claims to be used when authenticating API calls. 

Our server responds the client by sending a redirect response to the user agent based on the redirect_uri the client provided in the first place, now with an access token attached in the fragment part of the URI. 

        GET https://myapiclient.com/clientCallbackPage.html#access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215aXNzdWVyLmNvbSIsImV4cCI6MTQxMTQ3MzQ3OCwiaWF0IjoxNDExNDczNDc4LCJqdGkiOiJpZDEyMzQ1NjciLCJ0eXAiOiJKV1QifQ.DkNPec7pVe2HfyeaJvJZ8M2rIDC89kvDgfY_xZQtFBw&state=xyz&token_type=jwt

> *Note* implicit vs explicit
In this simple scenario we're using the implicit grant flow, to keep it simple. You may want a an authorization server with full support for all OAuth 2.0 flows, like server to server and the ability to renew tokens and validate them form the issuer.
[See Implicit flow AKA the client flow](http://techblog.hybris.com/2012/06/05/oauth2-the-implicit-flow-aka-as-the-client-side-flow/) or the oAuth 2.0 specification [specification](http://tools.ietf.org/html/rfc6749#section-4.2).

The full source code for the solution presented in this post could be found @ [GitHub](https://github.com/jayway/JayLabs.Owin.OAuthAuthorization).
The solution is also avalibe as a [nuget package](http://www.nuget.org/packages/JayLabs.Owin.OAuthAuthorization/).

Let's take a look at the main parts.

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
        Provider = new CustomOAuthProvider(providerOptions), 
        AuthorizeEndpointPath = new PathString("/authorize"),
        AllowInsecureHttp = _appConfiguration.AllowInsecureHttp
    });

> Note that we're using two sets of custom options - *JwtOptions* and *ProviderOptions*. We also set the AllowInsecureHttp form our *appConfiguration*
> 
#### CustomOAuthProvider

The provider is responsible for validating authentication, authorization and redirects in the authorization flow.
This is the main part of our custom authorization implementation.

	    public class CustomOAuthProvider : OAuthAuthorizationServerProvider

Our Custom provider inherits from *OAuthAuthorizationServerProvider*. And takes our *provider options*.


        public CustomOAuthProvider(CustomProviderOptions options)

It then overides two methods form the base *OAuthAuthorizationServerProvider* class. *ValidateClientRedirectUri* and AuthorizeEndpoint*.

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

            if (string.IsNullOrWhiteSpace(_options.JwtOptions.SupportedScope))
            {
                Error(context, OAuthImplicitFlowError.ServerError, "no supported scope defined");
                return;
            }

            if (!HasSupportedScope(context, _options.JwtOptions.SupportedScope))
            {
                string errorDescription = string.Format("only {0} scope is supported",
                    _options.JwtOptions.SupportedScope);
                Error(context, OAuthImplicitFlowError.Scope, errorDescription);
                return;
            }

            string rawJwt = await TryGetRawJwtTokenAsync(context);

            if (string.IsNullOrWhiteSpace(rawJwt))
            {
                context.OwinContext.Authentication.Challenge(new AuthenticationProperties {RedirectUri = uri});
                return;
            }

            var tokenValidator = new TokenValidator();
            ClaimsPrincipal principal = tokenValidator.Validate(rawJwt, _options.JwtOptions);

            if (!principal.Identity.IsAuthenticated)
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "unauthorized user, unauthenticated");
                return;
            }

            ClaimsIdentity claimsIdentity = await _options.TransformPrincipal(principal);

            if (!claimsIdentity.Claims.Any())
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "unauthorized user");
                return;
            }

            ConsentAnswer consentAnswer = await TryGetConsentAnswerAsync(context.Request);

            if (consentAnswer == ConsentAnswer.Rejected)
            {
                Error(context, OAuthImplicitFlowError.AccessDenied, "resource owner denied request");
                return;
            }

            if (consentAnswer == ConsentAnswer.Missing)
            {
                Error(context, OAuthImplicitFlowError.ServerError,
                    "missing consent answer");
                return;
            }


            if (!(consentAnswer == ConsentAnswer.Accepted || consentAnswer == ConsentAnswer.Implicit))
            {
                Error(context, OAuthImplicitFlowError.ServerError,
                    string.Format("invalid consent answer '{0}'", consentAnswer.Display));
                return;
            }

            string appJwtTokenAsBase64 =
                JwtTokenHelper.CreateSecurityTokenDescriptor(claimsIdentity.Claims, _options.JwtOptions)
                    .CreateTokenAsBase64();

            var builder = new UriBuilder(context.AuthorizeRequest.RedirectUri);

            const string tokenType = "bearer";

            var fragmentStringBuilder = new StringBuilder();

            fragmentStringBuilder.AppendFormat("access_token={0}&token_type={1}&state={2}&scope={3}",
                Uri.EscapeDataString(appJwtTokenAsBase64), Uri.EscapeDataString(tokenType),
                Uri.EscapeDataString(context.AuthorizeRequest.State ?? ""),
                Uri.EscapeDataString(_options.JwtOptions.SupportedScope));

            if (consentAnswer == ConsentAnswer.Implicit)
            {
                fragmentStringBuilder.AppendFormat("&consent_type={0}", Uri.EscapeDataString(consentAnswer.Invariant));
            }

            builder.Fragment = fragmentStringBuilder.ToString();

            string redirectUri = builder.Uri.ToString();

            context.Response.Redirect(redirectUri);
            context.RequestCompleted();
        }

The *AuthorizeEndpoint* method is central here. The flow described in the scenario section is implemented here.
We're checking the scope, if not valid we return 400 and complete the request.
Then we check for an external token (if the user is authenticated), if not we used the challange method in the middleware. If the user is authenticated we transform (add our custom claims) and sign the token.

Let's take a look on the options (*JwtOptions* and *ProviderOptions*) the provider needs.

##### Options

The provider options allow you issue custom claims and set scope.
	
    var handleConsentOptions = new HandleConsentOptions(consentParameterName:"consentAnswer");

    var jwtOptions = new JwtOptions {
        JwtSigningKeyAsUtf8 = "your key",
        Issuer = "your issuer name",
        Audience, "your oauth audience (uri)",
        JwtTokenParameterName = "jwt_token",
        SupportedScope = "Your scope"
    }

	new CustomProviderOptions(jwtOptions, handleConsentOptions)
	        {
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
The provider aids you with the setup of authorization, letting you issue own claims, in a JWT token based on the JWTOptions.

To get a user authenticated, we configure the OpenIdConnect Middleware - up next.

### OWIN OpenIdConnect Middleware

Since we're using OWIN, we could use the OpenIdConnect middleware package.
The middleware is configured in the OWIN startup class. Ex with Azure AD;

            var openIdConnectOptions = new OpenIdConnectAuthenticationOptions
                                       {
                                           ClientId = _appConfiguration.OpenIdClientId,
                                           Authority = _appConfiguration.OpenIdAuthority,
                                           CallbackPath = new PathString("/openid"),
                                           Notifications = notifications,
                                           AuthenticationMode = AuthenticationMode.Active
                                       };

            app.UseOpenIdConnectAuthentication(openIdConnectOptions);

> Note that the we create the *notfications* to handle consent.

#### CreateConsentOptions

This is a utlilitiy to ease OpenID Connect configuration, with consent page support.

            var createConsentOptions = new CreateConsentOptions
                                       {
                                           CreateConsentAsync = (response, redirectUri) =>
                                           {
                                               var consentUrl = new Uri(string.Format("/consent?redirectUri={0}&consentParamName={1}",
                                                   Uri.EscapeDataString(redirectUri.ToString()), 
                                                   Uri.EscapeDataString(customProviderOptions.HandleConsentOptions.ConsentParameterName)),      UriKind.Relative);

                                               response.Redirect(consentUrl.ToString());

                                               return Task.FromResult(0);
                                           }
                                       };

            var consentBuilder = new ConsentBuilder(createConsentOptions, customProviderOptions.HandleConsentOptions, jwtOptions);

            var notifications = new OpenIdConnectAuthenticationNotifications
                                {
                                    AuthorizationCodeReceived = consentBuilder.HandleOpenIdAuthorizationCodeAsync
                                }


By default, there is an implicit consent if no implementation is provided by setting CreateConsentAsync. In this case we redirect to a consent view that will POST the consent result back to the authorization URI.

> The *notifications* is the used in the OpenIdConnectAuthorizationOptions, shown in the OpenIdConnect middleware section(above)

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

We get the current principal from the OwinContext.
Here we check if the uses is authenticated, and then is the ClaimsPrinciapal has to requied claim.

### Resource endpoints

All resource endpoint should be secured by checking claims via our custom attribute. If the client doesn't have a valid token, is should respond with a 401, to tell the client to get a token. All resource endpoints could also be configured for CORS.

### Conclusion

In this post we explored what needs to be done for moving form the pure authentication scenarios offen seen in the templates, towards authorization via OAuth. We implemented the OAuth Implicit Grant flow, by using the OAuth Middleware writing our own OAuthProvider and ClaimsAuthorize attribute. It might seem as much custom code, but it's few core parts, that might be reused. Our server is also one step closer to a future scenario with federated authorization trough a exteranal authorization server.

Our scenario is catered for a javascript app, but also works with app using AuthenticationBroker and alike. But we havn't implemeted the flow ([Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1)) for server to server scenarios. This would be next step to explore...

Full source code @ [https://github.com/jayway/JayLabs.Owin.OAuthAuthorization](GitHub)
The [nuget package](http://www.nuget.org/packages/JayLabs.Owin.OAuthAuthorization/).


Enjoy!

### Resources

- [http://pfelix.wordpress.com/2012/11/27/json-web-tokens-and-the-new-jwtsecuritytokenhandler-class/](http://pfelix.wordpress.com/2012/11/27/json-web-tokens-and-the-new-jwtsecuritytokenhandler-class/)
- [http://engineering.talis.com/articles/elegant-api-auth-angular-js/](http://engineering.talis.com/articles/elegant-api-auth-angular-js/)
- [http://blogs.msdn.com/b/webdev/archive/2013/09/20/understanding-security-features-in-spa-template.aspx](http://blogs.msdn.com/b/webdev/archive/2013/09/20/understanding-security-features-in-spa-template.aspx)
- [https://auth0.com/blog/2014/01/27/ten-things-you-should-know-about-tokens-and-cookies/](https://auth0.com/blog/2014/01/27/ten-things-you-should-know-about-tokens-and-cookies/)
- [http://leastprivilege.com/2014/03/24/the-web-api-v2-oauth2-authorization-server-middlewareis-it-worth-it/](http://leastprivilege.com/2014/03/24/the-web-api-v2-oauth2-authorization-server-middlewareis-it-worth-it/)


