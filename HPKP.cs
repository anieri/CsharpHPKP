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

        public T DoRequest<T>(Uri uri, string method, Action<Stream> sendRequest, Func<HttpWebResponse, T> readResponse) {
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
            request.Method = method;
            request.Credentials = CredentialCache.DefaultCredentials;

            ServicePointManager.ServerCertificateValidationCallback +=
                new RemoteCertificateValidationCallback(h.ValidateServerCertificate);

            if (sendRequest != null) {
                using (var stream = request.GetRequestStream()) {
                    sendRequest(stream);
                }
            }

            HttpWebResponse response = (HttpWebResponse) request.GetResponse();
            if (readResponse != null) {
                return readResponse(response);
            }
            return default(T);
        }
    }
}
