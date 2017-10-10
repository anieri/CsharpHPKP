using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
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

        public static Header ParseHeader(HttpWebResponse resp) {
            if (resp == null) {
                return null;
            }
            var pins = resp.Headers.GetValues("Public-Key-Pins");
            if (pins == null || pins.Length == 0) {
                return null;
            }

            return Header.populate(new Header(), pins[0]);
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
