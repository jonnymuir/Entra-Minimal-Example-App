# Entra Minimal Example App

This repository serves as a minimal reproducible example (MRE) for handling specific challenges in ASP.NET MVC applications using Microsoft Entra ID (formerly Azure AD) and the Microsoft.Identity.Web package.

## Key Focus Areas

This project demonstrates the solution for two primary configuration issues, both implemented in the current code base:

Correcting Claims Mapping (The Core Fix): Ensuring the standard .NET authorization system ([Authorize(Roles="RoleName")] and User.IsInRole()) correctly recognizes roles issued via the standard OIDC "roles" claim from Entra ID, instead of the default Microsoft-specific claim type URI.

Claims Refresh without Logout: Implementing a method to force a silent re-authentication with Entra ID to pick up new role assignments (e.g., post-registration roles) without forcing the user to fully log out and sign back in.

## Initial Setup and Configuration

1. Project Dependencies

The solution uses the following key NuGet packages:

Microsoft.Identity.Web

Microsoft.Identity.Web.UI

Microsoft.Identity.Web.MicrosoftGraph

2. Role Claim Mapping (Program.cs)

The core fix for User.IsInRole() is applied early in Program.cs:

```
// CRITICAL: Disable default inbound claim mapping (prevents long URI claims)
JwtSecurityTokenHandler.DefaultMapInboundClaims = false; 

// ... inside the service configuration ...
builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration, options =>
    {
        // Ensure the OIDC handler recognizes "roles" from the token
        options.TokenValidationParameters.RoleClaimType = "roles";
        // Also set the name claim for User.Identity.Name
        options.TokenValidationParameters.NameClaimType = "name";
    });
```

3. Entra ID Configuration (appsettings.json)

Easiest practise is to put the required settings into secrets

You will need to set up an ExternalID AzureAD tenant and get the values - make sure it is an ExternalID (the newer version of B2C) tenant, not your main tenant.

Also set up a app registration to get the clientID (also called applicationID)

When you set up the app registration, go to Manage / Authentication and make sure your Web redirect URIs has https://localhost:7050/signin-oidc (or whatever the port your local version is listening on - make sure it is https only too in your launch settings).

Under Implicit grant and hybrid flows, Select the tokens you would like to be issued by the authorization endpoint. Select both options (Access Tokens and ID Tokens).

Then go to App roles and create one called LinkedMembers.

Next we need to setup a registration (sign in) user flow. This is done back at the AD Tenant / External Identities page. Under Self-service sign-up, you will see a User Flows options. Create one (I've called mine ExternalID_1_signup_signin). Choose Email with password as your identify provider. Here would be where we could add extra user attributes to collect if need be. Probably don't need too much as will do that in a seperate registration step when we want to add the LinkedMember role.

Then under the "use" menu select applications and add our application from the app registrations.

The setting you'll need from all that are the instance name followed by .ciamlogin.com - this is minimalexample in my case. It is the primary domain for the tenant. I think you might also be able to use the tenantID here (needs checking)

TenantId is the AD TenantId - you can also use the full domain name.

ClientId is from the app registration.

```
# Set Instance
dotnet user-secrets set "AzureAd:Instance" "https://minimalexample.ciamlogin.com/"

# Set TenantId
dotnet user-secrets set "AzureAd:TenantId" "minimalexample.onmicrosoft.com"

# Set ClientId
dotnet user-secrets set "AzureAd:ClientId" "aa63d422-a6f1-47ae-b2de-745f1755ed38"

# Set the most sensitive value: ClientSecret (or CertificateThumbprint)
dotnet user-secrets set "AzureAd:ClientSecret" "[Your-Client-Secret]"
```



```
"AzureAd": {
    "Instance": "https://minimalexample.ciamlogin.com/",
    "TenantId": "minimalexample.onmicrosoft.com",
    "ClientId": "aa63d422-a6f1-47ae-b2de-745f1755ed38",
    "CallbackPath": "/signin-oidc"
  },
```

## Claims Refresh Implementation

The claims refresh logic is implemented in the LinkingController within the LinkAndRefreshClaims action.

Logic (LinkingController.cs)

```
// ... inside LinkAndRefreshClaims() action ...
var properties = new AuthenticationProperties();

// The user will be redirected back here after the silent refresh completes.
properties.RedirectUri = Url.Action("Index", "Home"); 

// The CRITICAL OIDC parameter to force Entra ID to check for a fresh session (0 seconds).
properties.Parameters.Add("max_age", "0"); 

return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
```

### Purpose

This sequence forces Entra ID to issue a new ID token (with refreshed claims) while seamlessly maintaining the user's browser session.

⏭️ Next Step: Graph API Integration

The next planned feature for this example is to integrate the Microsoft Graph API into the LinkAndRefreshClaims action to programmatically assign the LinkedMember role before triggering the claims refresh. This will replace the current need for manual role assignment in the Azure Portal.