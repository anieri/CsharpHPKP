using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CSharpHPKP {

    public interface IStorage {
        Header Lookup(string host);
        void Add(string host, Header h);
    }

    public class HPKP {

        IStorage storage;

        public HPKP(IStorage storage) {
            this.storage = storage;
        }

        public void Request(Uri uri, Action<Stream> action) {
            var host = uri.Host;
            var scheme = uri.Scheme;

            if (scheme != "https") {
                return;
            }

            var h = this.storage.Lookup(host);
            if (h != null) {
                var request = (HttpWebRequest) WebRequest.Create(uri);

                var certv2 = new X509Certificate2(request.ServicePoint.Certificate);
                string cn = certv2.Issuer;
                string cedate = certv2.GetExpirationDateString();
                string cpub = certv2.GetPublicKeyString();

                bool validPin = false;
                // FIXME: is this correct? how to get intermidiate certs?
                var peerPin = HPKP.fingerprint(certv2);
                if (h.Matches(peerPin)) {
                    validPin = true;
                }
                if (!validPin) {
                    return;
                }
                return;
            }
        }

        public static string fingerprint(X509Certificate2 cert) {
            Byte[] hashBytes;
            using (var hasher = new SHA256Managed()) {
                hashBytes = hasher.ComputeHash(cert.RawData);
            }
            return hashBytes.Aggregate(String.Empty, (str, hashByte) => str + hashByte.ToString("x2"));
        }
    }
}
