using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace CSharpHPKP {
    [Serializable]
    internal class HPKPNotFoundException : Exception {
        private readonly List<String> Expected;
        private readonly List<String> Found;

        public HPKPNotFoundException(List<String> expectedPins, List<String> foundPins) {
            this.Expected = expectedPins;
            this.Found = foundPins;
        }

        public override String Message => this.ToString();

        public override String ToString() => JsonConvert.SerializeObject(new Helper(this.Expected, this.Found));
    }

    internal class Helper {
        public List<String> Expected { get; set; }
        public List<String> Found { get; set; }

        public Helper(List<String> expected, List<String> found) {
            this.Expected = expected;
            this.Found = found;
        }
    }
}