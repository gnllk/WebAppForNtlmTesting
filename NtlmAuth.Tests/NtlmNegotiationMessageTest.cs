using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmNegotiationMessageTest
    {
        [TestMethod]
        public void TestNtlmNegotiationMessageParse()
        {
            const string originHex = "4e544c4d53535000010000000732000006000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e";
            var message1 = NtlmNegotiationMessage.Parse(originHex.HexToBytes());

            Assert.IsTrue(message1.Signature == Constants.Ntlmssp);
            Assert.IsTrue(message1.Type == MessageType.Negotiation);
            Assert.IsTrue(message1.Flags == (MessageFlag.NegotiateUnicode
                | MessageFlag.NegotiateOem
                | MessageFlag.RequestTarget
                | MessageFlag.NegotiateNtlm
                | MessageFlag.NegotiateDomainSupplied
                | MessageFlag.NegotiateWorkstationSupplied));

            Assert.IsTrue(message1.Message.DomainNameLength == 6);
            Assert.IsTrue(message1.Message.DomainNameSpace == 6);
            Assert.IsTrue(message1.Message.DomainNameOffset == 51);

            Assert.IsTrue(message1.Message.HostNameLength == 11);
            Assert.IsTrue(message1.Message.HostNameSpace == 11);
            Assert.IsTrue(message1.Message.HostNameOffset == 40);

            Assert.IsTrue(message1.Message.OsMajorVersion == 5);
            Assert.IsTrue(message1.Message.OsMinorVersion == 0);
            Assert.IsTrue(message1.Message.OsBuildNumber == 2195);

            Assert.IsTrue(message1.Domain == "DOMAIN");
            Assert.IsTrue(message1.Host == "WORKSTATION");

            var actualHex = message1.ToBytes().BytesToHex();

            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TestNtlmNegotiationMessageCreate()
        {
            const string originHex = "4e544c4d53535000010000000732000006000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e";
            var message1Struct = new NegotiationMessageStruct
            {
                Signature = Constants.NtlmsspBytes,
                Type = MessageType.Negotiation,
                Flags = MessageFlag.NegotiateUnicode
                        | MessageFlag.NegotiateOem
                        | MessageFlag.RequestTarget
                        | MessageFlag.NegotiateNtlm
                        | MessageFlag.NegotiateDomainSupplied
                        | MessageFlag.NegotiateWorkstationSupplied,
                OsMajorVersion = 5,
                OsMinorVersion = 0,
                OsBuildNumber = 2195,
                OsReserved = 251658240
            };

            var message1 = new NtlmNegotiationMessage(message1Struct, "DOMAIN", "WORKSTATION");

            Assert.IsTrue(message1.Signature == Constants.Ntlmssp);
            Assert.IsTrue(message1.Type == MessageType.Negotiation);
            Assert.IsTrue(message1.Flags == (MessageFlag.NegotiateUnicode
                | MessageFlag.NegotiateOem
                | MessageFlag.RequestTarget
                | MessageFlag.NegotiateNtlm
                | MessageFlag.NegotiateDomainSupplied
                | MessageFlag.NegotiateWorkstationSupplied));

            Assert.IsTrue(message1.Message.DomainNameLength == 6);
            Assert.IsTrue(message1.Message.DomainNameSpace == 6);
            Assert.IsTrue(message1.Message.DomainNameOffset == 51);

            Assert.IsTrue(message1.Message.HostNameLength == 11);
            Assert.IsTrue(message1.Message.HostNameSpace == 11);
            Assert.IsTrue(message1.Message.HostNameOffset == 40);

            Assert.IsTrue(message1.Message.OsMajorVersion == 5);
            Assert.IsTrue(message1.Message.OsMinorVersion == 0);
            Assert.IsTrue(message1.Message.OsBuildNumber == 2195);

            Assert.IsTrue(message1.Domain == "DOMAIN");
            Assert.IsTrue(message1.Host == "WORKSTATION");

            var actualHex = message1.ToBytes().BytesToHex();

            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
