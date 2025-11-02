# Entra Minimal Example App

This repository serves as a minimal reproducible example (MRE) for handling specific challenges in ASP.NET MVC applications using Microsoft Entra ID (formerly Azure AD) and the Microsoft.Identity.Web package.

## Key Focus Areas

This project demonstrates the solution for two primary configuration issues, both implemented in the current code base:

Correcting Claims Mapping (The Core Fix): Ensuring the standard .NET authorization system ([Authorize(Roles="RoleName")] and User.IsInRole()) correctly recognizes roles issued via the standard OIDC "roles" claim from Entra ID, instead of the default Microsoft-specific claim type URI.

Claims Refresh without Logout: Implementing a method to force a silent re-authentication with Entra ID to pick up new role assignments (e.g., post-registration roles) without forcing the user to fully log out and sign back in.

## Initial Setup and Configuration


### Role Claim Mapping (Program.cs)

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

### Entra ID Configuration 

Easiest practise is to put the required settings into secrets

You will need to set up an ExternalID AzureAD tenant and get the values - make sure it is an ExternalID (the newer version of B2C) tenant, not your main tenant.

Also set up a app registration to get the clientID (also called applicationID)

When you set up the app registration, go to Manage / Authentication and make sure your Web redirect URIs has https://localhost:7050/signin-oidc (or whatever the port your local version is listening on - make sure it is https only too in your launch settings).

Under Implicit grant and hybrid flows, Select the tokens you would like to be issued by the authorization endpoint. Select both options (Access Tokens and ID Tokens).

Then go to App roles and create one called LinkedMember.

Next we need to setup a registration (sign in) user flow. This is done back at the AD Tenant / External Identities page. Under Self-service sign-up, you will see a User Flows options. Create one (I've called mine ExternalID_1_signup_signin). Choose Email with password as your identify provider. Here would be where we could add extra user attributes to collect if need be. Probably don't need too much as will do that in a seperate registration step when we want to add the LinkedMember role.

Then under the "use" menu select applications and add our application from the app registrations.

The setting you'll need from all that are the instance name followed by .ciamlogin.com - this is minimalexample in my case. It is the primary domain for the tenant. I think you might also be able to use the tenantID here (needs checking)

Next you need to set up your app to be able to call Microsoft Graph to add the roles to your newly created user. I've used the same app registration to do this, but in practise it may be better to set up a new one specifically for this purpose.

Create a secret in the app regstration so we can do a none user present authentication to the Graph API. Call it something sensible like MyWebAppLinkingSecret, however it is the value you need.

You then need to go to the API permissions and give the app the graph api permissions needed to link to the role. This is https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All

When you have added the API permission you also need to Grant Admin consent for the application (this is a link button above the permission list)

TenantId is the AD TenantId - you can also use the full domain name.

ClientId is from the app registration.

LinkedMemberRoleID - you'll need to look in the app registration manifest and grab hold of the guid for the LinkedMember role you created above.

ServicePrincipalObjectId - For this example we are using the app registration itself to update the user to a LinkedMember, for this grab the objectid from the app registration overview

ClientSecret - The value of the secret created above

```
# Set Instance
dotnet user-secrets set "AzureAd:Instance" "https://minimalexample.ciamlogin.com/"

# Set TenantId
dotnet user-secrets set "AzureAd:TenantId" "minimalexample.onmicrosoft.com"

# Set ClientId
dotnet user-secrets set "AzureAd:ClientId" "aa63d422-a6f1-47ae-b2de-745f1755ed38"

# Set the ClientId for Setting the Role
dotnet user-secrets set "SetRoleExample:ClientId" "aa63d422-a6f1-47ae-b2de-745f1755ed38"

# Set LinkedMemberRoleID
dotnet user-secrets set "SetRoleExample:LinkedMemberRoleId" "33599fc2-63dc-400d-b29a-2c39b19e13c8"

# Set ServicePrincipalObjectId
dotnet user-secrets set "SetRoleExample:ServicePrincipalObjectId" "a9593b7c-f31e-49d0-8440-04896e88601f"

# Set the most sensitive value: ClientSecret (or CertificateThumbprint)
dotnet user-secrets set "SetRoleExample:ClientSecret" "[Your-Client-Secret]"
```

I.e. we are building up a app settings that looks like this

```
"AzureAd": {
    "Instance": "https://minimalexample.ciamlogin.com/",
    "TenantId": "minimalexample.onmicrosoft.com",
    "ClientId": "aa63d422-a6f1-47ae-b2de-745f1755ed38",
    "CallbackPath": "/signin-oidc"
  },
"SetRoleExample": {
    "ClientId": "aa63d422-a6f1-47ae-b2de-745f1755ed38",
    "LinkedMemberRoleId": "33599fc2-63dc-400d-b29a-2c39b19e13c8",
    "ServicePrincipalObjectId": "a9593b7c-f31e-49d0-8440-04896e88601f",
    "ClientSecret": "[Your-Client-Secret]"
}
```

## Claims Refresh Implementation

The claims refresh logic is implemented in the LinkingController within the LinkAndRefreshClaims action.

We need to do a polling mechanism, because after you add the role (LinkedMember), it can take Entra a few seconds to propogate it, and therefore pick it up as a new role for your logged in member.

Look at the code in LinkingController, it shows an example of how to do this.

We call the Graph API, manually in our case, I wanted to keep it seperate from the authentication of the minimal app. This adds the role.

Then we clear our claims, a do a re-challenge for our login to refresh them. And repeat if neccessary,

### Purpose

This sequence forces Entra ID to issue a new ID token (with refreshed claims) while seamlessly maintaining the user's browser session.

### Live demo

Try it out here:

[Live Demo](https://entra-mre-app-001-gxgqcphjb5btdgg6.uksouth-01.azurewebsites.net)