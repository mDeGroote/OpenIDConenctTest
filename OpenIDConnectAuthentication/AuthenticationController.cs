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

namespace OpenIDConnectAuthentication
{
    [Route("authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        [HttpGet]
        [Route("login")]
        public IActionResult Login([FromQuery]string returnurl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge("Microsoft");
            }

            string token = CreateJwtToken();
            Response.Cookies.Append("jwttoken", token);

            return Redirect(returnurl);
        }

        [HttpGet]
        [Route("logout")]
        [Authorize]
        public async Task Logout()
        {
            await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
        }

        private string CreateJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes("SuperDuberUltraSecretKeyOfPureAwesomness");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "localhost",
                Expires = DateTime.UtcNow.AddMinutes(15),
                Subject = new System.Security.Claims.ClaimsIdentity(new List<System.Security.Claims.Claim> { HttpContext.User.Claims.First(x => x.Type == "preferred_username") }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
