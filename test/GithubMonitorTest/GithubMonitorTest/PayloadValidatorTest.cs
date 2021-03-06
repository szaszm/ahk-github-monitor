using System.Text;
using Ahk.GitHub.Monitor;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GithubMonitorTest
{
    [TestClass]
    public class PayloadValidatorTest
    {
        private const string Key = "testSecret";

        [TestMethod]
        public void ValidSecret()
        {
            Assert.IsTrue(PayloadValidator.IsSignatureValid(Encoding.ASCII.GetBytes("testString"),
                "sha1=17776af870091664d05e1a90e22f3cfb181b5411", Key));
        }

        [TestMethod]
        public void InvalidSecretFails()
        {
            Assert.IsFalse(PayloadValidator.IsSignatureValid(Encoding.ASCII.GetBytes("testString"),
                "sha1=17776af870091664d05e1a90e22f3cfb181b5411", "InvalidKey"));
        }

        [TestMethod]
        public void InvalidSignatureFails()
        {
            Assert.IsFalse(PayloadValidator.IsSignatureValid(Encoding.ASCII.GetBytes("testString"),
                "sha1=ab776af870091664d05e1a90e22f3cfb181b54cd", Key));
        }

    }
}
