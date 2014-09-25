# Securing ASP.NET Web API endpoints - Using OWIN, OAuth 2.0 and Claims

In this post we're going to create some simple endpoints using ASP.NET Web API, [OWIN](http://owin.org/) and OAuth 2.0. To secure Controller endpoints we are using a custom claims attribute. We will issue a [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html), JWT, containing claims, that the client will use when calling the API.

OAuth 2.0 specifies four roles, Resource Owner, Client, Resource Server and Authorization Server. In our solution we combine the two latter roles in one single server. Other solutions separate these roles allowing the same Authorization Server to be used by multiple applications.

We're going to implement OAuth 2.0 without using any of the default templates (SPA, Web API).

### Scenario
We have a JavaScript web client that should be able to talk to our API. The API requires all requests to be authorized.

There are many options for securing our API. 

We could use a static API key distributed to every client. However, a static API key is not ideal for our use case, since it would be easy for anyone to get hold of the API key in clear text from the client. Instead we have to get an API key per client user. 

We could implement a custom API key solution, but why implement a custom one when there are standards like OAuth 2.0. OAuth 2.0 is an authorization framework that allows us to issue and consume tokens in standardized and interoperable manner.

In the templates for SPA or Web API there are a lot of helper classes to get you up and running with ***authentication*** from a mix of providers. In our case we also have different levels of privileges for the resource endpoints. Thus we also have need for ***authorization***. This could be achived by using claims-based authorization.

- We want our resource endpoints to be configured to authorize through claims.

The next question is how to decide what set of privileges a user has. And how does the client get the claims? The first step is to identify the user.

- We want users to be able to authenticate with OpenID Connect providers like Google or Azure AD. 

Since it is a JavaScript client application, [OAuth 2.0 implicit grant](http://tools.ietf.org/html/rfc6749#section-4.2) flow is suitable.

#### The authorization flow start

The client makes an access token request, using OAuth 2.0 by navigating with the user agent (web browser).

A request looks like this:

	GET https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html

> Note that with OAuth, the client specifies its callback endpoint uri by setting the redirect_uri query parameter. This is where the authorization flow will end.

#### The authentication flow

When our server receive the access token request we first have to ensure the user to be authenticated via an identity provider. Here we start an authentication flow with OpenID Connect which redirects the user agent to the identity provider. Eventually the user agent will make a request to the API servers OpenID Connect callback URI, https://myapiserver.com/openid, containing a signed JWT with the identity claims for the user. 

	POST https://myapiserver.com/openid

> This ends the authentication flow. However we have to get back to the authorization flow with the provided identity.

#### Contiunation of authorization flow

After retrieving the OpenID Connect JWT, another JWT is created by our implementation by wrapping the original OpenID Connect JWT. This makes it possible to verify that we are the issuer of the wrapped token. Other ways of transferring the identity to ourselves for later use could be using cookies. This should be considered an implementation detail.

When we have the identity of the user we show a user consent HTML page asking the user to confirm authorization for the client to use our API. 

At the final stage of authentication, we issue a redirect to our consent page. If the user accepts the grant request, the user-agent makes a request to the original OAuth request URI with an additional JWT and a consent answer attached. 

	GET https://myapiserver.com/consent/consent?redirectUri={0}&consentParamName=consentAnswer
        
where {0} is the original authorization URI:

	(https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html)

The user submits the HTML form with the consent answer:

    POST https://myapiserver.com/authorize?response_type=token&client_id=myClientId&state=xyz&scope=MyAppScope&redirect_uri=https://myapiclient.com/clientCallbackPage.html

POST request body:

	consentAnswer=accepted&jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215aXNzdWVyLmNvbSIsImV4cCI6MTQxMTQ3MzQ3OCwiaWF0IjoxNDExNDczN	Dc4LCJqdGkiOiJpZDEyMzQ1NiIsInR5cCI6IkpXVCJ9.CLjy_BDRIcYyWOQWZ3nJXWAEGpGLNSzgB5qjkrtZKJA

Now we are back in the access token request and we know the identity of the user and we have a consent answer. Here we decide what claims are to be issued to the client based on the identity claims and a ruleset. 

With a set of claims we create a signed JWT containing the identity of the user and additional claims to be used when authorizing API calls. 

Our server responds the client by sending a redirect response to the user agent based on the redirect_uri the client provided in the first place, now with an access token attached in the fragment part of the URI. 

	GET https://myapiclient.com/clientCallbackPage.html#access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215aXNzdWVyLmNvbSIsImV4cCI6MTQxMTQ3MzQ3OCwiaWF0IjoxNDExNDczNDc4LCJqdGkiOiJpZDEyMzQ1NjciLCJ0eXAiOiJKV1QifQ.DkNPec7pVe2HfyeaJvJZ8M2rIDC89kvDgfY_xZQtFBw&state=xyz&token_type=jwt&scope=MyAppScope

> *Note* implicit vs explicit
In this scenario we're using the implicit grant flow, to keep it simple. You may want a an authorization server with full support for all OAuth 2.0 flows, like server to server and the ability to renew tokens and validate them from the issuer.
[See Implicit flow AKA the client flow](http://techblog.hybris.com/2012/06/05/oauth2-the-implicit-flow-aka-as-the-client-side-flow/) or the OAuth 2.0 specification [specification](http://tools.ietf.org/html/rfc6749#section-4.2).

The full source code for the solution presented in this post could be found @ [GitHub](https://github.com/jayway/JayLabs.Owin.OAuthAuthorization).
The solution is also avaliable as a [NuGet package](http://www.nuget.org/packages/JayLabs.Owin.OAuthAuthorization/).

Let's take a look at the main parts of the implementation.

### Claims authorization

We're going to create an attribute for authorization to be used in our Web API controllers. 

    [ClaimAuthorize(CustomClaims.CanChangeAddress)]

### OWIN startup

To support this scenario we're going to utilize several middleware components. Let's list them and their corresponding NuGet packages.

- CORS (Microsoft.Owin.Cors)

	`app.UseCors(...)`

The resource endpoint needs to be configured for CORS.

- OAuthAuthorizationServer (Microsoft.Owin.Security.OAuth)
	
	`app.UseOAuthAuthorizationServer(...)`

Used to setup our custom authorization server provider. Details in next section.

- JWT Bearer Authentication (Microsoft.Owin.Security.Jwt)

    `app.UseJwtBearerAuthentication(jwtOptions);`

Used for accepting bearer token and setting the IClaimsPrincipal according to the token.

- OpenIdConnect (Microsoft.Owin.Security.OpenIdConnect)

    `app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);`

Used to configure our authentication provider, ex Azure AD or Google.

The core parts for our implementation is around OpenIdConnect and the OAuthAuthorizationServer. Let's focus on them next.

### OWIN OAuthAuthorizationServer middleware

To use OAuth for authorization we can utilize the *UseOAuthAuthorizationServer* provided by the OAuth middleware.
We're going to use a custom authorization provider.

	app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
    {
        AccessTokenFormat =
            new JwtFormat(jwtOptions.Audience,
            symmetricKeyIssuerSecurityTokenProvider),
        ApplicationCanDisplayErrors = true,
        Provider = new CustomOAuthProvider(providerOptions), 
        AuthorizeEndpointPath = new PathString("/authorize")
    });

> Note that we're using two sets of custom options - *jwtOptions* and *providerOptions*. 
 
#### CustomOAuthProvider

The provider is responsible for issuing access tokens.
This is the main part of our custom authorization implementation.

	    public class CustomOAuthProvider : OAuthAuthorizationServerProvider

Our custom provider inherits from *OAuthAuthorizationServerProvider*. And takes our *CustomProviderOptions*.


        public CustomOAuthProvider(CustomProviderOptions options)

It then overides two methods form the base *OAuthAuthorizationServerProvider* class. *ValidateClientRedirectUri* and *AuthorizeEndpoint*.

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
We're checking the scope, if not valid we return an OAuth error in the fragment part and complete the request.
Then we check for an external token (if the user is authenticated), if not, we use the challenge method in the authentication middleware. If the user is authenticated we transform (add our custom claims) and sign the token.

Let's take a look on the options (*JwtOptions* and *CustomProviderOptions*) the provider needs.

##### Options

The provider options allow you to transform claims.
	
    var handleConsentOptions = new HandleConsentOptions(consentParameterName:"consentAnswer");

    var jwtOptions = new JwtOptions {
        JwtSigningKeyAsUtf8 = "your key",
        Issuer = "your issuer name",
        Audience, "your oauth audience",
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
The provider aids you with the setup of authorization, letting you issue own claims, in a JWT token based on the JwtOptions.

To get a user authenticated, we configure the OpenID Connect middleware - up next.

### OpenID Connect OWIN middleware

Since we're using OWIN, we could use the OpenID Connect middleware package.
The middleware is configured in the OWIN startup class. Eg. with Azure AD;

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

This is a utlility to hook-up when authentication is done, with consent page support.

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


By default, there is an implicit consent if no implementation is provided by setting CreateConsentAsync. In this case we redirect to a consent view that will allow the user to POST the consent result back to the authorization URI.

> The *notifications* is the used in the OpenIdConnectAuthorizationOptions, shown in the OpenIdConnect middleware section(above)

### Resource endpoints

All resource endpoints should be secured by checking claims via our custom attribute. If the client doesn't have a valid token, the API responds with a 401, to tell the client to get a token. All resource endpoints could also be configured for CORS.

### Conclusion

In this post we explored what needs to be done for moving from the pure authentication scenarios often seen in the templates, towards authorization via OAuth 2.0. We implemented the OAuth 2.0 Implicit Grant flow, by using the OAuth 2.0 middleware writing our own OAuthProvider and ClaimsAuthorize attribute. It might seem as if there is a lot of custom code, but there are few core parts, that might be reused. Our server is also one step closer to a future scenario with federated authorization through an exteranal authorization server.

Our scenario is catered for a JavaScript app, but also works with apps using WebAuthenticationBroker and alike. But we have not implemented the flow ([Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1)) for server to server scenarios. This would be the next step to explore...

Full source code @ [https://github.com/jayway/JayLabs.Owin.OAuthAuthorization](GitHub)
The [NuGet package](http://www.nuget.org/packages/JayLabs.Owin.OAuthAuthorization/).

Also check out Dominick Baier's [blog](http://leastprivilege.com/) and the projects IdentityServer and AuthorizationServer by [Thinktecture](http://thinktecture.github.io/).

Enjoy!