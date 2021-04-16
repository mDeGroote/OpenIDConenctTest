using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;

namespace OpenIDConnectAuthentication
{
    [Route("authentication")]
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly IJwtService _jwtService;
        private readonly IClaimsMapper _claimsMapper;

        public AuthenticationController(IJwtService jwtService, IClaimsMapper claimsMapper)
        {
            _jwtService = jwtService;
            _claimsMapper = claimsMapper;
        }

        [HttpGet]
        public async Task<IActionResult> Index([FromQuery]Uri redirect_uri, [FromQuery]string state, [FromQuery]string nonce, [FromQuery]string identityprovider, [FromQuery]string client_id, [FromQuery]string scope, [FromQuery]string response_type, [FromQuery] string code_challenge, [FromQuery] string code_challenge_method)
        {
            if (!CheckUri(redirect_uri))
                return BadRequest(new { Errormessage = "redirect_uri is invalid" });

            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (result.Succeeded)
            {
                var claimsPrincipal = result.Principal;

                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else if(HttpContext.User.Identity.IsAuthenticated)
            {
                var request = HttpContext.GetOpenIddictServerRequest();

                var claims = new List<Claim>();

                if (identityprovider == null)
                    identityprovider = User.Claims.First(x => x.Type == "identityProvider").Value;
                else
                    User.Claims.Append(new Claim("identityProvider", identityprovider));

                claims.Add(new Claim(OpenIddictConstants.Claims.Subject, User.Claims.First(x => x.Type == _claimsMapper.GetClaim("Name", identityprovider)).Value).SetDestinations(OpenIddictConstants.Destinations.IdentityToken));
                claims.Add(new Claim("identityProvider", identityprovider).SetDestinations(OpenIddictConstants.Destinations.IdentityToken));                

                var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, "subject", "Roles");
                //for (int i = 1; i <= 100; ++i)
                //{
                //    claimsIdentity.AddClaim(new Claim("roles", "role" + i).SetDestinations(OpenIddictConstants.Destinations.IdentityToken));
                //}
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                claimsPrincipal.SetScopes(request.GetScopes());
                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else
            {
                if (identityprovider == null)
                    return View("~/Views/Authentication/Index.cshtml", new AuthenticationRequest() { ReturnURL = redirect_uri, State = state, Nonce = nonce, Client_id = client_id, Scope = scope, Response_type = response_type, Code_challenge = code_challenge, Code_challenge_method = code_challenge_method });
                else
                    return Challenge(identityprovider);
            }

        }

        [HttpGet]
        [Route("logout")]
        public IActionResult Logout([FromQuery] Uri returnurl)
        {
            if (!CheckUri(returnurl))
                return BadRequest(new { Errormessage = "returnurl is invalid" });

            if (!HttpContext.User.Identity.IsAuthenticated)
                return Redirect(returnurl.AbsoluteUri);

            _jwtService.RevokeRefreshToken(Request.Cookies["refresh_token"]);
            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect(returnurl.AbsoluteUri);
        }

        private bool CheckUri(Uri uri)
        {
            if (uri == null)
                return false;

            try
            {
                if (!uri.IsAbsoluteUri)
                    return false;
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }
    }
}
