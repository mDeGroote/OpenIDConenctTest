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

namespace OpenIDConnectAuthentication
{
    [Route("authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        [Route("login")]
        public IActionResult Login([FromQuery]Uri returnurl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge("Microsoft");
            }

            string token = CreateJwtToken(returnurl.Authority);
            Response.Cookies.Append("jwttoken", token);

            return Redirect(returnurl.AbsoluteUri);
        }

        [HttpGet]
        [Route("logout")]
        public IActionResult Logout([FromQuery]Uri returnurl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
                return Redirect(returnurl.AbsoluteUri);

            Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect(returnurl.AbsoluteUri);
        }

        private string CreateJwtToken(string audience)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_configuration["signingkey"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "localhost",
                Audience = audience,
                Expires = DateTime.UtcNow.AddMinutes(15),
                Subject = new System.Security.Claims.ClaimsIdentity(new List<System.Security.Claims.Claim> { HttpContext.User.Claims.First(x => x.Type == "preferred_username") }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
