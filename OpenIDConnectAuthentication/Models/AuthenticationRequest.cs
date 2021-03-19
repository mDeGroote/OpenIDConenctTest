using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public class AuthenticationRequest
    {
        public Uri ReturnURL { get; set; }
        public string IdentityProvider { get; set; }
    }
}
