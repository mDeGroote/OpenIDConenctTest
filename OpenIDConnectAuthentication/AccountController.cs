using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;

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
        public string LoginTest()
        {
            StringBuilder sb = new StringBuilder();
            foreach (System.Security.Claims.Claim item in HttpContext.User.Claims)
            {
                sb.Append($"type: {item.Type}, value: {item.Value}, issuer: {item.Issuer} \n");
            }

            sb.Append($"name: {HttpContext.User.Identity.Name} \n");
            return $"{HttpContext.User.Identity.Name} {HttpContext.User.Identity.AuthenticationType} {sb.ToString()}";
        }

        [HttpGet]
        [Route("Logout")]
        public async Task Logout()
        {
            await Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions.SignOutAsync(HttpContext, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
