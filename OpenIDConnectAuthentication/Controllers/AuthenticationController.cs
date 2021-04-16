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

namespace OpenIDConnectAuthentication
{
    [Route("authentication")]
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly IJwtService _jwtService;

        public AuthenticationController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpGet]
        public IActionResult Index([FromQuery]Uri redirect_uri, [FromQuery]string state, [FromQuery]string nonce)
        {
            if (!CheckUri(redirect_uri))
                return BadRequest(new { Errormessage = "redirect_uri is invalid" });

            if (HttpContext.User.Identity.IsAuthenticated)
                return FinishLogin(redirect_uri, state, nonce, HttpContext.User.Claims.First(x => x.Type == "IdentityProvider").Value);

            return View("~/Views/Authentication/Index.cshtml", new AuthenticationRequest() { ReturnURL = redirect_uri, State = state, Nonce = nonce});
        }

        [HttpGet]
        [Route("{identityprovider}")]
        public IActionResult FinishLogin([FromQuery] Uri returnurl, [FromQuery] string state, [FromQuery]string nonce, string identityprovider)
        {
            if (!CheckUri(returnurl))
                return BadRequest(new { Errormessage = "redirect_uri is invalid" });

            //if user isnt authenticated, let him authenticate with chosen identityprovider
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge(identityprovider);
            }

            //create token for user
            string id_token = _jwtService.CreateJwtToken(returnurl.Host, HttpContext.User.Claims, identityprovider, nonce);

            //use existing refresh_token is user authenticated earlier
            RefreshToken refresh_token = _jwtService.HasExistingRefreshToken(HttpContext.User.Claims);
            if (refresh_token == null)
                refresh_token = _jwtService.CreateRefreshToken(HttpContext.User.Claims, identityprovider);

            var refreshTokenCookieOptions = new CookieOptions();
            refreshTokenCookieOptions.HttpOnly = true;
            refreshTokenCookieOptions.SameSite = SameSiteMode.Lax;

            HttpContext.User.Claims.Append(new System.Security.Claims.Claim("IdentityProvider", identityprovider));
            Response.Cookies.Append("refresh_token", refresh_token.Token, refreshTokenCookieOptions);

            //POST the user to the redirect_uri with the JWT token
            return new ContentResult()
            {
                ContentType = "text/html",
                StatusCode = 200,
                Content = "<html><head><title>Submit This Form</title></head><body onload = \"javascript:document.forms[0].submit()\" ><form method = \"post\" action = \"" + returnurl + "\" ><input type =\"hidden\" name = \"nonce\" value = \"" + nonce + "\"/><input type =\"hidden\" name = \"state\" value = \"" + state + "\"/><input type =\"hidden\" name = \"id_token\" value = \"" + id_token + "\"/></form></body></html>"
            };
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
