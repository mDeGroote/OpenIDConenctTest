using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace OpenIDConnectAuthentication
{
    [Route("account")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        [Route("Login")]
        public IActionResult Login()
        {
            string authorizationEndpoint = _configuration["OpenIDConnect:Microsoft:AuthorizationEndPoint"];
            string client_id = _configuration["OpenIDConnect:Microsoft:client_id"];
            string redirect_uri = _configuration["OpenIDConnect:Microsoft:redirect_uri"];
            string response_type = _configuration["OpenIDConnect:Microsoft:response_type"];
            string scope = _configuration["OpenIDConnect:Microsoft:scope"];

            return Redirect($"{authorizationEndpoint}client_id={client_id}&redirect_uri={redirect_uri}&response_type={response_type}&scope={scope}");
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
