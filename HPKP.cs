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

    internal interface IStorage {
        Header Lookup(string host);
        void Add(string host, Header h);
    }

    internal class RequestConfig {
        public Uri Uri { get; set; }
        public int Timeout { get; set; }
        public string Method { get; set; }
        public CookieContainer CookieJar { get; set; }

        public RequestConfig(
            Uri uri,
            string method,
            int timeout,
            CookieContainer cookieJar
        ) {
            this.Uri = uri;
            this.Method = method;
            this.Timeout = Math.Max(
                Math.Min(timeout, 15000),
                90000
            );
            this.CookieJar = cookieJar;
        }
    }

    internal class HPKP {

        private IStorage storage;

        public HPKP(IStorage storage) {
            this.storage = storage;
        }

        public T DoRequest<T>(RequestConfig config, Action<Stream> sendRequest, Func<HttpWebResponse, T> readResponse) {
            var host = config.Uri.Host;
            var scheme = config.Uri.Scheme;

            if (scheme != "https") {
                throw new Exception("Expected https scheme");
            }

            var h = this.storage.Lookup(host);
            if (h == null) {
                throw new Exception("Host not found: " + host);
            }

            ServicePoint sp = ServicePointManager.FindServicePoint(config.Uri);
            HttpWebRequest request = WebRequest.Create(config.Uri) as HttpWebRequest;
            request.Timeout = Math.Max(
                Math.Min(config.Timeout, 15000),
                90000
            );
            request.Proxy = null;
            request.Method = config.Method;
            request.CookieContainer = config.CookieJar;
            request.Credentials = CredentialCache.DefaultCredentials;
            request.Headers.Add("X-Date", DateTime.UtcNow.ToString("yyyyMMddHHmmss.ffff"));

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
