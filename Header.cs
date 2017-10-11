using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CSharpHPKP {
    public class Header {

        public Int64 Created;
        public Int64 MaxAge;
        public bool IncludeSubDomains;
        public bool Permanent;
        public List<string> Sha256Pins;
        public string ReportURI;

        public bool Matches(string pin) {
            foreach (string p in this.Sha256Pins) {
                if (p == pin) {
                    return true; ;
                }
            }
            return false; ;
        }

        internal bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        ) {
            foreach (var c in chain.ChainElements) {
                var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
                var cert = certParser.ReadCertificate(c.Certificate.RawData);
                var certStruct = cert.CertificateStructure;
                var peerPin = Header.fingerprint(certStruct);
                if (this.Matches(peerPin)) {
                    return true;
                }
            }
            return false;
        }

        private static string fingerprint(Org.BouncyCastle.Asn1.X509.X509CertificateStructure certStruct) {
            Byte[] hashBytes;
            using (var hasher = new System.Security.Cryptography.SHA256Managed()) {
                hashBytes = hasher.ComputeHash(certStruct.SubjectPublicKeyInfo.GetDerEncoded());
            }
            return hashBytes.Aggregate(String.Empty, (str, hashByte) => str + hashByte.ToString("x2"));
        }

        internal static Header ParseHeader(HttpWebResponse resp) {
            if (resp == null) {
                return null;
            }
            var pins = resp.Headers.GetValues("Public-Key-Pins");
            if (pins == null || pins.Length == 0) {
                return null;
            }

            return Header.populate(new Header(), pins[0]);
        }

        internal static Header Copy(Header h) {
            Header r = new Header();
            r.Created = h.Created;
            r.MaxAge = h.MaxAge;
            r.IncludeSubDomains = h.IncludeSubDomains;
            r.Permanent = h.Permanent;
            r.ReportURI = h.ReportURI;
            r.Sha256Pins = new List<string>();
            foreach (var pin in h.Sha256Pins) {
                r.Sha256Pins.Add(pin);
            }
            return r;
        }

        private static Header populate(Header h, string v) {
            h.Sha256Pins = new List<string>();

            foreach (string f in v.Split(';')) {
                string field = f.Trim();

                int i = field.IndexOf("pin-sha256");
                if (i >= 0) {
                    h.Sha256Pins.Add(field.Substring(i + 12));
                    continue;
                }

                i = field.IndexOf("report-uri");
                if (i >= 0) {
                    h.ReportURI = field.Substring(i + 12);
                    continue;
                }

                i = field.IndexOf("max-age=");
                if (i >= 0) {
                    try {
                        var ma = Int64.Parse(field.Substring(i + 8));
                        h.MaxAge = ma;
                    } catch (Exception) {
                        continue;
                    }
                }

                if (field.Contains("includeSubDomains")) {
                    h.IncludeSubDomains = true;
                    continue;
                }
            }

            h.Created = (Int64) DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            return h;
        }

    }
}
