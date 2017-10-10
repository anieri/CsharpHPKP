using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CSharpHPKP {
    class MemStorage {

        private Dictionary<string, Header> domains;
        private Mutex mu;

        public MemStorage() {
            this.domains = new Dictionary<string, Header>();
            this.mu = new Mutex();
        }

        public Header Lookup(string host) {
            this.mu.WaitOne();

            var d = this.domains[host];
            if (d != null) {
                this.mu.ReleaseMutex();
                return Header.Copy(d);
            }

            var l = host.Length;
            while (l > 0) {
                var i = host.IndexOf(".");
                if (i > 0) {
                    host = host.Substring(i + 1);
                    d = this.domains[host];
                    if (d != null) {
                        if (d.IncludeSubDomains) {
                            this.mu.ReleaseMutex();
                            return Header.Copy(d);
                        }
                    }
                    l = host.Length;
                } else {
                    break;
                }
            }

            this.mu.ReleaseMutex();
            return null;
        }

        public void Add(string host, Header d) {
            this.mu.WaitOne();

            if (this.domains == null) {
                this.domains = new Dictionary<string, Header>();
            }

            if (d.MaxAge == 0 && !d.Permanent) {
                var check = this.domains[host];
                if (check != null) {
                    if (!check.Permanent) {
                        this.domains.Remove(host);
                    }
                }
            } else {
                this.domains[host] = d;
            }
            this.mu.ReleaseMutex();
        }
    }
}
