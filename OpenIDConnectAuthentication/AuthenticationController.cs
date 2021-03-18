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
    public class AuthenticationController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public AuthenticationController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpGet]
        [Route("login")]
        public IActionResult Login([FromQuery]Uri returnurl)
        {
            if (!returnurl.IsAbsoluteUri)
                return StatusCode(400, new { Errormessage = "return url is invalid"});

            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge("Microsoft");
            }

            string access_token = _jwtService.CreateJwtToken("", HttpContext);
            RefreshToken refresh_token = _jwtService.CreateRefreshToken(HttpContext);
            var cookieoptions = new CookieOptions();
            cookieoptions.HttpOnly = true;

            Response.Cookies.Append("access_token", access_token);
            Response.Cookies.Append("refresh_token", refresh_token.Token, cookieoptions);

            return Redirect(returnurl.AbsoluteUri);
        }

        [HttpGet]
        [Route("logout")]
        public IActionResult Logout([FromQuery] Uri returnurl)
        {
            if (!returnurl.IsAbsoluteUri)
                return StatusCode(400, new { Errormessage = "return url is invalid"});

            if (!HttpContext.User.Identity.IsAuthenticated)
                return Redirect(returnurl.AbsoluteUri);

            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect(returnurl.AbsoluteUri);
        }
    }
}
