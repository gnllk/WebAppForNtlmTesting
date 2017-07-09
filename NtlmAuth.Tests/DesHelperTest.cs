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
            var content = "12345678";

            var cipheredData = DesHelper.Encrypt(Encoding.ASCII.GetBytes(content), key);

            var nonCipheredData = DesHelper.Decrypt(cipheredData, key);

            var result = Encoding.ASCII.GetString(nonCipheredData);

            Assert.AreEqual(result, content);
        }
    }
}
