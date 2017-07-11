using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class HexHelperTest
    {
        [TestMethod]
        public void TestBytesToHex()
        {
            const string expect = "010203FF";
            byte[] origin = { 0x01, 0x02, 0x03, 0xff };
            var actual = origin.BytesToHex();
            Assert.AreEqual(expect, actual);
        }

        [TestMethod]
        public void TestHexToBytes()
        {
            byte[] expect = { 0x01, 0x02, 0x03, 0xff };
            const string origin = "010203FF";
            var actual = origin.HexToBytes();
            Assert.IsTrue(expect.SequenceEqual(actual));
        }
    }
}
