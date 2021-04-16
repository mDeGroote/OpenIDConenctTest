using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace OpenIDConnectAuthentication
{
    [Route("jwt")]
    [ApiController]
    public class JWTController : ControllerBase
    { 

        [HttpPost("tokens")]
        public async Task<IActionResult> Tokens()
        {
            var request = HttpContext.GetOpenIddictServerRequest();

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            {
                return BadRequest(new { Error_message = "invalid grant_type" });
            }

            var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}
