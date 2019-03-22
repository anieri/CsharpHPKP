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
        Header Lookup(String host);
        void Add(String host, Header h);
    }

    internal class RequestConfig {
        public Uri Uri { get; set; }
        public String Method { get; set; }
        public CookieContainer CookieJar { get; set; }
        public Int64 ContentLength { get; set; }
        public IWebProxy ProxySettings { get; set; }
        public Dictionary<String, String> Headers { get; set; }

        private Int32 timeout = 15000;
        public Int32 Timeout {
            get {
                return this.timeout;
            }
            set {
                this.timeout = Math.Max(
                    Math.Min(value, 15000),
                    90000
                );
            }
        }
    }

    internal class HPKP {

        private IStorage storage;

        public HPKP(IStorage storage) {
            this.storage = storage;
        }

        public T DoRequest<T>(RequestConfig config, Action<Stream> sendRequest, Func<HttpWebResponse, T> readResponse, Boolean shouldHandleError = false) {
            String host = config.Uri.Host;
            String scheme = config.Uri.Scheme;

            if (scheme != "https") {
                throw new Exception("Expected https scheme");
            }

            Header h = this.storage.Lookup(host);
            if (h == null) {
                throw new Exception("Host not found: " + host);
            }

            ServicePoint sp = ServicePointManager.FindServicePoint(config.Uri);
            HttpWebRequest request = WebRequest.Create(config.Uri) as HttpWebRequest;
            request.Timeout = Math.Min(
                Math.Max(config.Timeout, 15000),
                90000
            );
            request.Proxy = config.ProxySettings;
            request.Method = config.Method;
            request.CookieContainer = config.CookieJar;
            request.Credentials = CredentialCache.DefaultCredentials;
            request.Headers.Add("x-date", DateTime.UtcNow.ToString("yyyyMMddHHmmss.ffff"));
            foreach (KeyValuePair<String, String> header in config.Headers) {
                if ("x-date" == header.Key?.ToLowerInvariant().Trim()) {
                    continue;
                }
                request.Headers.Add(header.Key, header.Value);
            }
            if (config.ContentLength > 0) {
                request.ContentLength = config.ContentLength;
            }

            ServicePointManager.ServerCertificateValidationCallback +=
                new RemoteCertificateValidationCallback(h.ValidateServerCertificate);

            try {
                if (sendRequest != null) {
                    using (Stream stream = request.GetRequestStream()) {
                        sendRequest(stream);
                    }
                }

                using (HttpWebResponse response = (HttpWebResponse) request.GetResponse()) {
                    if (readResponse != null) {
                        return readResponse(response);
                    }
                }

            } catch (WebException e) {
                if (!shouldHandleError || e.Response == null || readResponse == null) {
                    throw e;
                }
                return readResponse((HttpWebResponse) e.Response);
            }

            return default(T);
        }
    }
}
