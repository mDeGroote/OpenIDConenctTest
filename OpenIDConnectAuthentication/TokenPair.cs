using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIDConnectAuthentication
{
    public class TokenPair
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }

        public TokenPair()
        {

        }

        public TokenPair(string access_token, string refresh_token)
        {
            this.access_token = access_token;
            this.refresh_token = refresh_token;
        }
    }
}
