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

namespace OpenIDConnectAuthentication
{
    [Route("account")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        [HttpGet]
        [Route("Login")]
        public IActionResult Login()
        {
            var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties() { RedirectUri = "account/LoginTest" };

            return Challenge(properties, "Microsoft");
        }


        [HttpGet]
        [Route("LoginTest")]
        public IActionResult LoginTest()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwttoken = new SecurityTokenDescriptor
            {
                Issuer = "localhost",
                Subject = new System.Security.Claims.ClaimsIdentity(HttpContext.User.Claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("dojsfhsdjhfkdjshfksdhfkjdhfhsbfhjxs")), SecurityAlgorithms.HmacSha256Signature)
            };

            return Ok(new { token = tokenHandler.WriteToken(tokenHandler.CreateToken(jwttoken)), expiration = jwttoken.Expires });
        }

        [HttpGet]
        [Route("Logout")]
        public async Task Logout()
        {
            await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
