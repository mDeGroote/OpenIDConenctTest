using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public class TokenPair
    {
        public string id_token { get; set; }
        public string refresh_token { get; set; }

        public TokenPair()
        {

        }

        public TokenPair(string id_token, string refresh_token)
        {
            this.id_token = id_token;
            this.refresh_token = refresh_token;
        }
    }
}
