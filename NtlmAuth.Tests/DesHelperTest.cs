using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class DesHelperTest
    {
        [TestMethod]
        public void TestEncryptAndDecrypt()
        {
            var key = Encoding.ASCII.GetBytes("12345678");
            var content = Encoding.ASCII.GetBytes("12345678");

            var cipheredData = DesHelper.Encrypt(content, key);
            var nonCipheredData = DesHelper.Decrypt(cipheredData, key);

            Assert.IsTrue(nonCipheredData.SequenceEqual(content));
        }
    }
}
