using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CSharpHPKP {

    internal class MemStorage : IStorage {

        private Dictionary<String, Header> domains;
        private readonly Mutex mu;

        public MemStorage() {
            this.domains = new Dictionary<String, Header>();
            this.mu = new Mutex();
        }

        public Header Lookup(String host) {
            this.mu.WaitOne();

            if (this.domains.TryGetValue(host, out Header d)) {
                this.mu.ReleaseMutex();
                return new Header(d);
            }

            Int32 l = host.Length;
            while (l > 0) {
                Int32 i = host.IndexOf(".");
                if (i > 0) {
                    host = host.Substring(i + 1);
                    if (this.domains.TryGetValue(host, out d)) {
                        if (d.IncludeSubDomains) {
                            this.mu.ReleaseMutex();
                            return new Header(d);
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

        public void Add(String host, Header d) {
            this.mu.WaitOne();

            if (this.domains == null) {
                this.domains = new Dictionary<String, Header>();
            }

            if (d.MaxAge == 0 && !d.Permanent) {
                if (this.domains.TryGetValue(host, out Header h)) {
                    if (!h.Permanent) {
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
