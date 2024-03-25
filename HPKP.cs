using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;

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

        public RequestConfig Merge(RequestConfig other) { 
            if (other == null) {
                return this;
            }
        
            return new RequestConfig { 
                Uri = other.Uri ?? this.Uri,
                Method = other.Method ?? this.Method,
                CookieJar = other.CookieJar ?? this.CookieJar,
                ProxySettings = other.ProxySettings ?? this.ProxySettings,
                Headers = other.Headers ?? this.Headers,
                ContentLength = (other.ContentLength == 0) ? this.ContentLength : other.ContentLength,
                Timeout = (other.Timeout == 0 || other.Timeout == 15000) ? this.Timeout : other.Timeout,
            };
        }
    }

    internal class HPKP {

        private readonly IStorage storage;

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
            
            var request = WebRequest.Create(config.Uri) as HttpWebRequest;
            request.Timeout = Math.Min(
                Math.Max(config.Timeout, 15000),
                90000
            );
            request.Proxy = config.ProxySettings;
            request.Method = config.Method;
            request.CookieContainer = config.CookieJar;
            request.Credentials = CredentialCache.DefaultCredentials;
            request.Headers.Add("x-date", DateTime.UtcNow.ToString("yyyyMMddHHmmss.ffff"));
            if (config.Headers != null && config.Headers.Count > 0) {
                foreach (KeyValuePair<String, String> header in config.Headers) {
                    if ("x-date" == header.Key?.ToLowerInvariant().Trim()) {
                        continue;
                    }
                    request.Headers.Add(header.Key, header.Value);
                }
            }
            if (config.ContentLength > 0) {
                request.ContentLength = config.ContentLength;
            }

            request.ServerCertificateValidationCallback +=
                new RemoteCertificateValidationCallback(h.ValidateServerCertificate);

            try {
                if (sendRequest != null) {
                    using (Stream stream = request.GetRequestStream()) {
                        sendRequest(stream);
                    }
                }

                using (var response = (HttpWebResponse) request.GetResponse()) {
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
