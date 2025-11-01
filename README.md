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

Ensure your appsettings.json is configured with the necessary Entra ID settings, including a section for the Graph API scope required for the next step:

```
"AzureAd": {
    "Instance": "[https://login.microsoftonline.com/](https://login.microsoftonline.com/)",
    "TenantId": "[Your Tenant ID or 'organizations']",
    "ClientId": "[Your Application Client ID]",
    "ClientSecret": "[Your Client Secret]", // Required for app to get token
    "ClientCapabilities": [ "CP1" ],
    // Scopes needed for the Graph API call (role assignment)
    "CalledApi": {
        "Scopes": "[https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All](https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All)"
    }
},
"EntraAd": {
    // These GUIDs must be populated from your App Registration manifest and Service Principal
    "LinkedMemberRoleId": "YOUR_ACTUAL_ROLE_GUID_HERE", 
    "ServicePrincipalObjectId": "YOUR_ACTUAL_SERVICE_PRINCIPAL_ID" 
}
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