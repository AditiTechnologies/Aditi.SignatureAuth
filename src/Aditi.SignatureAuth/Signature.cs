using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Aditi.SignatureAuth
{
    public class Signature
    {
        public string Id { get; set; }
        public DateTimeOffset Timestamp { get; set; }
        public string Nonce { get; set; }
        public string Mac { get; set; }

        public string StringToSign
        {
            get
            {
                return string.Format(@"id = ""{0}"", nonce = ""{1}:{2}""", Id, Timestamp.Ticks, Nonce);
            }
        }

        public byte [] SecretKey { get; set; }

        public Signature(string id, string base64EncodedSecretKey) : this(id, Convert.FromBase64String(base64EncodedSecretKey)) { }

        public Signature(string id, byte[] secretKey) : this(id)
        {
            this.SecretKey = secretKey;
        }

        public Signature(string id)
        {
            this.Id = id;

            this.Timestamp = DateTimeOffset.UtcNow;

            var b = new byte[8];
            var characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
            var rng = new Random();
            this.Nonce = new string(Enumerable.Range(0, 8).Select(n => characters[rng.Next(characters.Length)]).ToArray());
        }

        public static Signature Parse(string text)
        {
            if (text.Length < 4 || text.Substring(0, 4) != "MAC ")
            {
                throw new ArgumentException(@"Not a valid signature string. Text doesn't start with the string ""MAC "".");
            }

            var components = new NameValueCollection();
            foreach (var pair in text.Substring(4).Split(',').Select(kv => kv.Trim().Split(new char[] { '=' }, 2)))
            {
                if (pair.Length != 2)
                {
                    throw new ArgumentException(@"Invalid Signature String.  Malformed '=' pairs");
                }
                components[pair[0].Trim()] = pair[1].Trim(' ', '"');
            }

            var requiredParameters = new string[] { "id", "nonce", "mac" };
            foreach (var parameter in requiredParameters)
            {
                if (components[parameter] == null)
                {
                    throw new ArgumentException(string.Format(@"Signature string is missing the required parameter ""{0}"".", parameter));
                }
            }

            if (components.Count != requiredParameters.Length)
            {
                throw new ArgumentException(string.Format(@"Signature string is invalid. It contains extra parameters. Expected parameters are: {0}.", string.Join(", ", requiredParameters)));
            }

            var split = components["nonce"].Split(new char [] { ':' }, 2);
            long ticks;

            if (split.Length != 2 || !long.TryParse(split[0], out ticks))
            {
                throw new ArgumentException(@"Nonce is in an invalid format. Nonce should be in the form <timestamp expressed as 100-nanoseconds intervals since 12:00 January 1st, 0001 UTC>:<random string>.");
            }

            return new Signature(components["id"]) { Timestamp = new DateTimeOffset(ticks, TimeSpan.Zero), Nonce = split[1], Mac = components["mac"] };
        }

        public string ComputeMac()
        {
            return Convert.ToBase64String(new HMACSHA256(SecretKey).ComputeHash(ASCIIEncoding.ASCII.GetBytes(StringToSign)));
        }

        public override string ToString()
        {
            return string.Format(@"MAC {0}, mac = ""{1}""", StringToSign, ComputeMac());
        }
    }
}
