
#Jaylib.Owin.OAuthAuthorization

Provides a Custom OAuth Provider for Implicit Grant. Allowing usage of the included ClaimAuthorize attribute.

Authentication is made by other middleware like OpenID Connect.

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
        Provider = new CustomOAuthProvider(providerOptions), 
        AuthorizeEndpointPath = new PathString("/authorize"),
        AllowInsecureHttp = _appConfiguration.AllowInsecureHttp
    });

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
	

There is also utlilities to ease OpenID Connect configuration, with consent page support.

By default, there is an implicit consent if no implementation is provided by setting CreateConsentAsync. In this case we redirect to a consent view that will POST the consent result back to the authorization URI.

    var createConsentOptions = new CreateConsentOptions
            {
                CreateConsentAsync = (response, redirectUri) =>
                {
                    var consentUrl = new Uri(string.Format("/consent?redirectUri={0}&consentParamName={1}",
                        Uri.EscapeDataString(redirectUri.ToString()), 
                        Uri.EscapeDataString(customProviderOptions.HandleConsentOptions.ConsentParameterName)), UriKind.Relative);

                    response.Redirect(consentUrl.ToString());

                    return Task.FromResult(0);
                }
            };

    var notifications = new OpenIdConnectAuthenticationNotifications
            {
                AuthorizationCodeReceived = consentBuilder.HandleOpenIdAuthorizationCodeAsync
            };

    var openIdConnectOptions = new OpenIdConnectAuthenticationOptions
            {
                ClientId = _appConfiguration.OpenIdClientId,
                Authority = _appConfiguration.OpenIdAuthority,
                CallbackPath = new PathString("/openid"),
                Notifications = notifications,
                AuthenticationMode = AuthenticationMode.Active
            };

    app.UseOpenIdConnectAuthentication(openIdConnectOptions);


