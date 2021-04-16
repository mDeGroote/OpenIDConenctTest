using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIDConnectAuthentication.Controllers
{
    [Route("[Controller]")]
    public class OpenidController : ControllerBase
    {
        IOpenIddictApplicationManager _openiddictManager;

        public OpenidController(IOpenIddictApplicationManager openIddictApplicationManager)
        {
            _openiddictManager = openIddictApplicationManager;
        }

        [HttpPost]
        public async Task<ActionResult> CreateClient([FromForm] string client_id, [FromForm]string redirect_uri, [FromForm] string[] scopes, [FromForm]string displayname = "")
        {
            string client_secret = "";
            using(var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[32];
                rngCryptoServiceProvider.GetBytes(bytes);

                client_secret = Convert.ToBase64String(bytes);
            }

            if (await _openiddictManager.FindByClientIdAsync(client_id) is null)
            {
                await _openiddictManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = client_id,
                    ClientSecret = client_secret,
                    RedirectUris = { new Uri("https://localhost:44380/signin-oidc") },
                    DisplayName = displayname,
                    Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.ResponseTypes.Code,
                    Permissions.ResponseTypes.IdToken,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.Implicit,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Endpoints.Authorization,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Email,
                }
                });

                return Ok(new { client_secret = client_secret});
            }

            return BadRequest(new { ErrorMessage = "client_id is already in use" });
        }
    }
}
