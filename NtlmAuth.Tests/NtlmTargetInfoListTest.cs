using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmTargetInfoListTest
    {
        [TestMethod]
        public void TestNtlmTargetInfoList()
        {
            var originHex = "02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000";
            var info = NtlmTargetInfoList.Parse(originHex.HexToBytes(), Encoding.Unicode);

            Assert.IsTrue(info.Count == 5);

            Assert.IsTrue(info[0].TargetInfoType == TargetInfoType.DomainName);
            Assert.IsTrue(info[0].TargetContent == "DOMAIN");

            Assert.IsTrue(info[1].TargetInfoType == TargetInfoType.ServerName);
            Assert.IsTrue(info[1].TargetContent == "SERVER");

            Assert.IsTrue(info[2].TargetInfoType == TargetInfoType.DnsDomainName);
            Assert.IsTrue(info[2].TargetContent == "domain.com");

            Assert.IsTrue(info[3].TargetInfoType == TargetInfoType.FQDN);
            Assert.IsTrue(info[3].TargetContent == "server.domain.com");

            Assert.IsTrue(info[4].TargetInfoType == TargetInfoType.Terminator);
            Assert.IsTrue(info[4].TargetContent == null);
        }
    }
}
