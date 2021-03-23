using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication.Controllers
{
    [Route(".well-known/openid-configuration")]
    public class OpenIDConfigurationController : ControllerBase
    {
        [HttpGet]
        public IActionResult Configuration()
        {
            return Ok(new 
            {
                authorization_endpoint = "https://localhost:44336/authentication?",
            });
        }
    }
}
