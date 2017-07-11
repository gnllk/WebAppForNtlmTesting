using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmResponsesTest
    {
        [TestMethod]
        public void TestGetLmResponse()
        {
            var hexLmExpectRes = "c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56";
            var password = "SecREt01";
            var challenge = "0123456789abcdef".HexToBytes();
            var response = NtlmResponses.GetLmResponse(password, challenge);
            var hexLmActualRes = response.BytesToHex().ToLowerInvariant();

            Assert.AreEqual(hexLmExpectRes, hexLmActualRes);
        }

        [TestMethod]
        public void TestGetNtlmResponse()
        {
            var hexLmExpectRes = "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6";
            var password = "SecREt01";
            var challenge = "0123456789abcdef".HexToBytes();
            var response = NtlmResponses.GetNtlmResponse(password, challenge);
            var hexLmActualRes = response.BytesToHex().ToLowerInvariant();

            Assert.AreEqual(hexLmExpectRes, hexLmActualRes);
        }

        [TestMethod]
        public void TestGetNtlmV2Response()
        {
            var hexExpectRes = "cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000";
            var targetInformation = "02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000".HexToBytes();
            var target = "DOMAIN";
            var userName = "user";
            var password = "SecREt01";
            var challenge = "0123456789abcdef".HexToBytes();
            var clientNonce = "ffffff0011223344".HexToBytes();
            var timestamp = "0090d336b734c301".HexToBytes();
            var response = NtlmResponses.GetNtlmV2Response(target, userName, password,
                targetInformation, challenge, clientNonce, timestamp);

            var hexActualRes = response.BytesToHex().ToLowerInvariant();

            Assert.AreEqual(hexExpectRes, hexActualRes);
        }
    }
}
