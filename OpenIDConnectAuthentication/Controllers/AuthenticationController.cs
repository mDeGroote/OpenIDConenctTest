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
        public IActionResult Index([FromQuery]Uri returnurl)
        {
            if (!CheckUri(returnurl))
                return BadRequest(new { Errormessage = "returnurl is invalid" });

            if (HttpContext.User.Identity.IsAuthenticated)
                return FinishLogin(returnurl, HttpContext.User.Claims.First(x => x.Type == "IdentityProvider").Value);

            return View("~/Views/Authentication/Index.cshtml", returnurl.AbsoluteUri);
        }

        [HttpGet]
        [Route("{identityprovider}")]
        public IActionResult FinishLogin([FromQuery] Uri returnurl, string identityprovider)
        {
            if (!CheckUri(returnurl))
                return BadRequest(new { Errormessage = "returnurl is invalid" });

            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge(identityprovider);
            }

            string access_token = _jwtService.CreateJwtToken(returnurl.Host, HttpContext.User.Claims, identityprovider);


            RefreshToken refresh_token = _jwtService.HasExistingRefreshToken(HttpContext.User.Claims);
            if(refresh_token == null)
                refresh_token = _jwtService.CreateRefreshToken(HttpContext.User.Claims, identityprovider);

            var refreshTokenCookieOptions = new CookieOptions();
            refreshTokenCookieOptions.HttpOnly = true;

            HttpContext.User.Claims.Append(new System.Security.Claims.Claim("IdentityProvider", identityprovider));
            Response.Cookies.Append("access_token", access_token);
            Response.Cookies.Append("refresh_token", refresh_token.Token, refreshTokenCookieOptions);

            return Redirect(returnurl.AbsoluteUri);

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
