using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CSharpHPKP {

    public interface IStorage {
        Header Lookup(string host);
        void Add(string host, Header h);
    }

    public class HPKP {

        private IStorage storage;

        public HPKP(IStorage storage) {
            this.storage = storage;
        }

        public void DoRequest(Uri uri, Action<Stream> sendRequest, Action<Stream> readResponse) {
            var host = uri.Host;
            var scheme = uri.Scheme;

            if (scheme != "https") {
                throw new Exception("Expected https scheme");
            }

            var h = this.storage.Lookup(host);
            if (h == null) {
                throw new Exception("Host not found: " + host);
            }

            ServicePoint sp = ServicePointManager.FindServicePoint(uri);
            WebRequest request = WebRequest.Create(uri);
            request.Proxy = null;
            request.Credentials = CredentialCache.DefaultCredentials;

            ServicePointManager.ServerCertificateValidationCallback +=
                new RemoteCertificateValidationCallback(h.ValidateServerCertificate);

            if (sendRequest != null) {
                using (var stream = request.GetRequestStream()) {
                    sendRequest(stream);
                }
            }

            HttpWebResponse response = (HttpWebResponse) request.GetResponse();
            using (Stream dataStream = response.GetResponseStream()) {
                if (readResponse != null) {
                    readResponse(dataStream);
                }
            }
        }
    }
}
