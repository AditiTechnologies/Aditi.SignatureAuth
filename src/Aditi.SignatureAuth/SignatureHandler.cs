using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Aditi.SignatureAuth
{
    public class SignatureHandler : DelegatingHandler
    {
        public SignatureHandler(Func<string, string> keyLookup)
        {
            this.KeyLookup = keyLookup;
        }

        public Func<string, string> KeyLookup { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Signature signature = null;
            try
            {
                // Why do I have to replace "&quot;" with an actual quote? The actual header is correct,
                // but something is doing some sort of XML/HTML entity escaping. Do we need to undo
                // other kinds of escaping?
                signature = Signature.Parse(request.Headers.Authorization.ToString().Replace("&quot;", "\""));
            }
            catch (ArgumentException e)
            {
                return Task.Factory.StartNew(() =>
                    {
                        var response = request.CreateResponse(HttpStatusCode.Unauthorized);
                        response.Content = new StringContent(e.Message);
                        return response;
                    });
            }
            signature.SecretKey = Convert.FromBase64String(KeyLookup(signature.Id));
            if (signature.Mac != signature.ComputeMac())
            {
                return Task.Factory.StartNew(() =>
                {
                    var response = request.CreateResponse(HttpStatusCode.Unauthorized);
                    response.Content = new StringContent("Invalid MAC. Signatures don't match.");
                    return response;
                });
            }
            else if ((DateTimeOffset.UtcNow - signature.Timestamp).Duration() > TimeSpan.FromMinutes(5))
            {
                return Task.Factory.StartNew(() =>
                    {
                        var response = request.CreateResponse(HttpStatusCode.Unauthorized);
                        response.Content = new StringContent("Invalid MAC. Timestamp must be within five minutes of the current time.");
                        return response;
                    });
            }
            else
            {
                request.Properties["tenantId"] = signature.Id;
                return base.SendAsync(request, cancellationToken);
            }
        }
    }
}
