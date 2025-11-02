using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.Json;
using System.Text;

namespace MyMreApp.Controllers;

[Authorize]
public class LinkingController(IConfiguration configuration) : Controller
{
    // Base URLs
    private const string TOKEN_URL_BASE = "https://login.microsoftonline.com";
    private const string GRAPH_URL_BASE = "https://graph.microsoft.com/v1.0";

    private const int MAX_POLL_ATTEMPTS = 15;
    private const string POLL_ATTEMPTS_KEY = "PollAttempts";

    // HARDCODED VALIDATION VALUES for POC
    private const string VALID_NI_NUMBER = "AB123456C";
    private const string VALID_POLICY_REF = "123456";

    // GET: /Linking/Index
    // Displays the page with the status and the button.
    public IActionResult Index()
    {
        // View() will look for Views/Linking/Index.cshtml
        return View();
    }

    // GET: /Linking/PollingStatus
    // This action displays the current polling status and initiates the next challenge/redirect via JavaScript.
    [HttpGet]
    public IActionResult PollingStatus()
    {
        if (User.IsInRole("LinkedMember"))
        {
            TempData["SuccessMessage"] = "Account successfully linked and permissions updated!";
            return RedirectToAction("Index", "Home");
        }

        int attempts = TempData[POLL_ATTEMPTS_KEY] as int? ?? 1;
        if (attempts >= MAX_POLL_ATTEMPTS)
        {
            TempData["ErrorMessage"] = $"Synchronisation failed: The role was not found after {MAX_POLL_ATTEMPTS} attempts. Please check your setup or try linking again.";
            return RedirectToAction(nameof(Index));
        }

        // Continue polling (Role not yet present, but more attempts allowed)
        TempData.Keep(POLL_ATTEMPTS_KEY);
        ViewData["Attempts"] = attempts;
        ViewData["MaxAttempts"] = MAX_POLL_ATTEMPTS;

        return View();
    }

    // POST: /Linking/ContinuePolling
    // This action performs the OIDC Challenge to force a claims refresh.
    [HttpPost]
    public IActionResult ContinuePolling()
    {
        // Retrieve and increment the attempt count for the *next* round.
        int attempts = (TempData[POLL_ATTEMPTS_KEY] as int? ?? 0) + 1;
        TempData[POLL_ATTEMPTS_KEY] = attempts;

        var newProperties = new AuthenticationProperties();

        // Set the 'max_age' property to '0' to force a fresh session check (claims refresh).
        newProperties.Parameters.Add("max_age", "0");

        // IMPORTANT: The redirect URI points back to the GET action (PollingStatus) 
        // which displays the UI before deciding the next step.
        newProperties.RedirectUri = Url.Action(nameof(PollingStatus));

        // Challenge the OIDC middleware to re-authenticate with the clean properties.
        return Challenge(newProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }
    
    // POST: /Linking/LinkAndRefreshClaims
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LinkAndRefreshClaims(string niNumber, string policyRef)
    {
        // In here we you do your backend logic to work out whether the user can be linked or not.
        // I expect this to be a bigger workflow in a real app, colling information from the user and matching it to the record.

        // For demo purposes, we will do a simple check.
        if (niNumber?.Trim().ToUpper() != VALID_NI_NUMBER || policyRef?.Trim() != VALID_POLICY_REF)
        {
            TempData["ValidationMessage"] = "Verification failed: The NI Number or Policy Reference did not match our records. Please check your details. (Demo requires NI: AB123456C, Ref: 123456)";
            return RedirectToAction(nameof(Index));
        }

        // Collect the info needed to call Graph API to add the role to the member
        string? userId = User.FindFirstValue("oid");
        string? tenantId = configuration["AzureAd:TenantId"];
        string? clientId = configuration["SetRoleExample:ClientId"];
        string? linkedMemberRoleId = configuration["SetRoleExample:LinkedMemberRoleId"];
        string? servicePrincipalId = configuration["SetRoleExample:ServicePrincipalObjectId"];
        string? secret = configuration["SetRoleExample:ClientSecret"];

        if (userId == null)
        {
            return BadRequest("User object ID not found.");
        }

        if (linkedMemberRoleId == null)
        {
            return BadRequest("SetRoleExample:LinkedMemberRoleId not found.");
        }

        if (servicePrincipalId == null)
        {
            return BadRequest("SetRoleExample:ServicePrincipalId not found.");
        }

        if (secret == null)
        {
            return BadRequest("SetRoleExample:ClientSecret not found.");
        }

        if (tenantId == null || clientId == null)
        {
            return BadRequest("AzureAd:TenantId or SetRoleExample:ClientId not found.");
        }

        // POC Logic: Call Graph API to Assign Role - This will be done in reality by a workflow

        using var httpClient = new HttpClient();

        // Step 1: Get the App-Only Access Token
        string accessToken = await GetAccessToken(httpClient, tenantId, clientId, secret);

        if (string.IsNullOrEmpty(accessToken))
        {
            return StatusCode(500, "Authentication to Graph API failed. Check client credentials.");
        }

        // Step 2: Assign the Role using the Access Token
        bool roleAssigned = await AssignAppRoleToUser(
            httpClient, accessToken, userId, servicePrincipalId, linkedMemberRoleId
        );

        if (!roleAssigned)
        {
            return StatusCode(500, "Failed to assign application role. Check API permissions and consent.");
        }

        // Set initial state for the polling loop and redirect to the poller
        // We do this rather than going straight to a refresh of claims to allow for eventual consistency in Entra.
        TempData["StatusMessage"] = "Role assigned. Starting synchronization check.";
        TempData["PollAttempts"] = 0; // Initialize attempts
        
        // Redirect to the polling action to begin the challenge loop
        return RedirectToAction(nameof(PollingStatus));
    }

    /// <summary>
    /// Performs the Client Credentials flow POST request to acquire an App-Only Bearer Token.
    /// </summary>
    private async Task<string> GetAccessToken(
        HttpClient httpClient, string tenantId, string clientId, string secret)
    {
        string tokenUrl = $"{TOKEN_URL_BASE}/{tenantId}/oauth2/v2.0/token";

        // Using FormUrlEncodedContent as it is the standard and most reliable method for this endpoint.
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"),
            new KeyValuePair<string, string>("client_secret", secret),
            new KeyValuePair<string, string>("grant_type", "client_credentials")
        });

        var response = await httpClient.PostAsync(tokenUrl, content);
        string responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            // In a real app, log the error here: responseBody
            return string.Empty;
        }

        using JsonDocument doc = JsonDocument.Parse(responseBody);
        if (doc.RootElement.TryGetProperty("access_token", out JsonElement tokenElement))
        {
            return tokenElement.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    /// <summary>
    /// Uses the acquired Bearer token to POST the AppRoleAssignment payload to the Graph API.
    /// </summary>
    private async Task<bool> AssignAppRoleToUser(
        HttpClient httpClient, string accessToken, string userId, string resourceId, string appRoleId)
    {
        string requestUrl = $"{GRAPH_URL_BASE}/users/{userId}/appRoleAssignments";

        httpClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        // The JSON payload for the Graph API call
        string jsonPayload = JsonSerializer.Serialize(new
        {
            principalId = userId,
            resourceId,
            appRoleId
        });

        var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        var response = await httpClient.PostAsync(requestUrl, content);

        // Success is 201 Created (role was assigned) or 409 Conflict (role was already assigned)
        if (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            return true;
        }
        else
        {
            // In a real app, log the detailed failure here: response.Content.ReadAsStringAsync()
            return false;
        }
    }
}