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
        public string Nonce { get; set; }
        public string State { get; set; }
        public string Client_id { get; set; }
        public string Scope { get; set; }
        public string Response_type { get; set; }
        public string Code_challenge { get; set; }
        public string Code_challenge_method { get; set; }
    }
}
