using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class LmResponseTest
    {
        [TestMethod]
        public void TestCreateLmResponse()
        {
            var hexResponse = "c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56";
            var responseData = HexHelper.HexToBytes(hexResponse);
            var password = Encoding.ASCII.GetBytes("SECRET01");
            var challenge = HexHelper.HexToBytes("0123456789abcdef");
            var response = new LmResponse(responseData, challenge, password);

            Assert.IsTrue(response.Validate());
        }
    }
}