using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Client;

namespace MyMreApp.Controllers;

[Authorize]
public class LinkingController : Controller
{
    // GET: /Linking/Index
    // Displays the page with the status and the button.
    public IActionResult Index()
    {
        // View() will look for Views/Linking/Index.cshtml
        return View();
    }

    // POST: /Linking/LinkAndRefreshClaims
    // Triggers the silent re-authentication flow with Entra ID.
    [HttpPost]
    [ValidateAntiForgeryToken] // Good security practice
    public async Task<IActionResult> LinkAndRefreshClaims()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync();

        if (authenticateResult?.Succeeded != true)
        {
            return Challenge(OpenIdConnectDefaults.AuthenticationScheme);
        }

        var newProperties = new AuthenticationProperties();

        newProperties.RedirectUri = Url.Action("Index", "Home");

        // Set the 'max_age' property in the Parameters collection.
        // This is the OIDC instruction to force a fresh session check.
        newProperties.Parameters.Add("max_age", "0");


        // Challenge the OIDC middleware to re-authenticate with the clean properties.
        return Challenge(newProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}