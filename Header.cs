using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;

namespace CSharpHPKP {
    internal class Header {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(Header));

        public Int64 Created;
        public Int64 MaxAge;
        public Boolean IncludeSubDomains;
        public Boolean Permanent;
        public List<String> Sha256Pins;
        public String ReportURI;

        internal Header() { }

        internal Header(Header h) {
            this.Created = h.Created;
            this.MaxAge = h.MaxAge;
            this.IncludeSubDomains = h.IncludeSubDomains;
            this.Permanent = h.Permanent;
            this.ReportURI = h.ReportURI;
            this.Sha256Pins = new List<String>();
            foreach (String pin in h.Sha256Pins) {
                this.Sha256Pins.Add(pin);
            }
        }

        public Boolean Matches(String pin) {
            foreach (String p in this.Sha256Pins) {
                if (p.Equals(pin)) {
                    return true;
                }
            }
            return false;
        }

        internal Boolean ValidateServerCertificate(
            Object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        ) {
            log.Info("Validating certificate");
            var foundPins = new List<String>();
            foreach (X509ChainElement c in chain.ChainElements) {
                var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
                Org.BouncyCastle.X509.X509Certificate cert = certParser.ReadCertificate(c.Certificate.RawData);
                Org.BouncyCastle.Asn1.X509.X509CertificateStructure certStruct = cert.CertificateStructure;
                String peerPin = Fingerprint(certStruct);
                log.Info("Peer pin: " + peerPin);

                foundPins.Add(peerPin);
                if (this.Matches(peerPin)) {
                    return true;
                }
            }
            return false;
        }

        private static String Fingerprint(Org.BouncyCastle.Asn1.X509.X509CertificateStructure certStruct) {
            Byte[] hashBytes;
            using (var hasher = new System.Security.Cryptography.SHA256Managed()) {
                hashBytes = hasher.ComputeHash(certStruct.SubjectPublicKeyInfo.GetDerEncoded());
            }
            return Convert.ToBase64String(hashBytes);
        }

        internal static Header ParseHeader(HttpWebResponse resp) {
            if (resp == null) {
                return null;
            }
            String[] pins = resp.Headers.GetValues("Public-Key-Pins");
            if (pins == null || pins.Length == 0) {
                return null;
            }

            return Header.Populate(new Header(), pins[0]);
        }

        private static Header Populate(Header h, String v) {
            h.Sha256Pins = new List<String>();

            foreach (String f in v.Split(';')) {
                String field = f.Trim();

                Int32 i = field.IndexOf("pin-sha256");
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
                        Int64 ma = Int64.Parse(field.Substring(i + 8));
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
