# POC.OIDCAuthenticationAndAPIsSecurity
This sample API authentication code doesn’t issue tokens. It validates access tokens issued by an Identity Provider (IdP). Works with Azure AD / Azure AD B2C / Auth0 / Okta / Keycloak, etc.

Files: 
Program.cs - configured the builder services here. 
appsettings.json - added three types of authentication modes
.csproj file - manually added package references. 


Unit testing instructions: 
Build sucessfully and test the solution with following steps: 

(1.0) Obtain an access token from your IdP (via Postman OAuth2, CLI, or a client app).

(2.0) Call GET /profile with Authorization: Bearer <access_token>.

(3.0) The API validates the token via the IdP’s OIDC discovery and enforces the api.read scope.

Notes:

• For Azure AD, register an App (API) and expose a scope like api.read. Use that Application ID URI as Audience.

• For Azure AD B2C, the Authority will be the B2C policy endpoint; the flow is similar (same JwtBearer handler).

• With Auth0/Okta, ensure that API identifier (audience) matches what the token’s aud claim contains.
