using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmAuthenticationMessageTest
    {
        [TestMethod]
        public void TestParseNtlmAuthenticationMessage()
        {
            const string originHex = "4e544c4d5353500003000000180018006a00000018001800820000000c000c0040000000080008004c0000001600160054000000000000009a0000000102000044004f004d00410049004e00750073006500720057004f0052004b00530054004100540049004f004e00c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6";
            var message = NtlmAuthenticationMessage.Parse(originHex.HexToBytes());

            Assert.IsTrue(message.Signature == Constants.Ntlmssp);
            Assert.IsTrue(message.Type == MessageType.Authentication);
            Assert.IsTrue(message.Flags == (MessageFlag.NegotiateUnicode
                | MessageFlag.NegotiateNtlm));

            Assert.IsTrue(message.Message.TargetNameLength == 12);
            Assert.IsTrue(message.Message.TargetNameSpace == 12);
            Assert.IsTrue(message.Message.TargetNameOffset == 64);
            Assert.IsTrue(message.TargetName == "DOMAIN");

            Assert.IsTrue(message.Message.UserNameLength == 8);
            Assert.IsTrue(message.Message.UserNameSpace == 8);
            Assert.IsTrue(message.Message.UserNameOffset == 76);
            Assert.IsTrue(message.UserName == "user");

            Assert.IsTrue(message.Message.HostNameLength == 22);
            Assert.IsTrue(message.Message.HostNameSpace == 22);
            Assert.IsTrue(message.Message.HostNameOffset == 84);
            Assert.IsTrue(message.HostName == "WORKSTATION");

            Assert.IsTrue(message.Message.LmResponseLength == 24);
            Assert.IsTrue(message.Message.LmResponseSpace == 24);
            Assert.IsTrue(message.Message.LmResponseOffset == 106);

            Assert.IsTrue(message.Message.NtlmResponseLength == 24);
            Assert.IsTrue(message.Message.NtlmResponseSpace == 24);
            Assert.IsTrue(message.Message.NtlmResponseOffset == 130);

            Assert.IsTrue(message.Message.SessionKeyLength == 0);
            Assert.IsTrue(message.Message.SessionKeySpace == 0);
            Assert.IsTrue(message.Message.SessionKeyOffset == 154);

            var actualHex = message.ToBytes().BytesToHex();
            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TestCreateNtlmAuthenticationMessage()
        {
            const string originHex = "4e544c4d5353500003000000180018006a00000018001800820000000c000c0040000000080008004c0000001600160054000000000000009a0000000102000044004f004d00410049004e00750073006500720057004f0052004b00530054004100540049004f004e00c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6";
            var messageStruct = new AuthenticationMessageStruct
            {
                Signature = Constants.NtlmsspBytes,
                Type = MessageType.Authentication,
                Flags = MessageFlag.NegotiateUnicode | MessageFlag.NegotiateNtlm,
            };
            var message = new NtlmAuthenticationMessage(messageStruct)
            {
                TargetName = "DOMAIN",
                UserName = "user",
                HostName = "WORKSTATION",
                LmResponseData = "c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56".HexToBytes(),
                NtlmResponseData = "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6".HexToBytes()
            };

            Assert.IsTrue(message.Message.TargetNameLength == 12);
            Assert.IsTrue(message.Message.TargetNameSpace == 12);
            Assert.IsTrue(message.Message.TargetNameOffset == 64);
            Assert.IsTrue(message.TargetName == "DOMAIN");

            Assert.IsTrue(message.Message.UserNameLength == 8);
            Assert.IsTrue(message.Message.UserNameSpace == 8);
            Assert.IsTrue(message.Message.UserNameOffset == 76);
            Assert.IsTrue(message.UserName == "user");

            Assert.IsTrue(message.Message.HostNameLength == 22);
            Assert.IsTrue(message.Message.HostNameSpace == 22);
            Assert.IsTrue(message.Message.HostNameOffset == 84);
            Assert.IsTrue(message.HostName == "WORKSTATION");

            Assert.IsTrue(message.Message.LmResponseLength == 24);
            Assert.IsTrue(message.Message.LmResponseSpace == 24);
            Assert.IsTrue(message.Message.LmResponseOffset == 106);

            Assert.IsTrue(message.Message.NtlmResponseLength == 24);
            Assert.IsTrue(message.Message.NtlmResponseSpace == 24);
            Assert.IsTrue(message.Message.NtlmResponseOffset == 130);

            Assert.IsTrue(message.Message.SessionKeyLength == 0);
            Assert.IsTrue(message.Message.SessionKeySpace == 0);
            Assert.IsTrue(message.Message.SessionKeyOffset == 154);

            var actualHex = message.ToBytes().BytesToHex();
            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
