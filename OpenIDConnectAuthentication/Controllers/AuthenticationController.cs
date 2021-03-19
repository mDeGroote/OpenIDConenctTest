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
            if (!returnurl.IsAbsoluteUri)
                return StatusCode(400, new { Errormessage = "return url is invalid" });

            if (HttpContext.User.Identity.IsAuthenticated)
                return FinishLogin(new AuthenticationRequest() { ReturnURL = returnurl , IdentityProvider = HttpContext.User.Claims.First(x => x.Type == "IdentityProvider").Value});

            return View("~/Views/Authentication/Index.cshtml", returnurl.AbsoluteUri);
        }

        [HttpGet]
        [Route("loginmicrosoft")]
        public IActionResult MicrosoftLogin([FromQuery] Uri returnurl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated || HttpContext.User.Claims.First(x => x.Type == "IdentityProvider").Value != "Google")
            {
                return Challenge("Microsoft");
            }

            return FinishLogin(new AuthenticationRequest() { ReturnURL = returnurl, IdentityProvider = "Microsoft"});
        }

        [HttpGet]
        [Route("logingoogle")]
        public IActionResult GoogleLogin([FromQuery] Uri returnurl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated || HttpContext.User.Claims.First(x => x.Type == "IdentityProvider").Value != "Google")
            {
                return Challenge("Google");
            }

            return FinishLogin(new AuthenticationRequest() { ReturnURL = returnurl, IdentityProvider = "Google"});
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

        private IActionResult FinishLogin(AuthenticationRequest authenticationRequest)
        {

            string access_token = _jwtService.CreateJwtToken("", HttpContext, authenticationRequest.IdentityProvider);
            RefreshToken refresh_token = _jwtService.CreateRefreshToken(HttpContext, authenticationRequest.IdentityProvider);
            var cookieoptions = new CookieOptions();
            cookieoptions.HttpOnly = true;

            HttpContext.User.Claims.Append(new System.Security.Claims.Claim("IdentityProvider", authenticationRequest.IdentityProvider));
            Response.Cookies.Append("access_token", access_token);
            Response.Cookies.Append("refresh_token", refresh_token.Token, cookieoptions);

            return Redirect(authenticationRequest.ReturnURL.AbsoluteUri);
        }
    }
}
