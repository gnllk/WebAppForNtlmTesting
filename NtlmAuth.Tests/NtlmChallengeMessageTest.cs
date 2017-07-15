using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmChallengeMessageTest
    {
        [TestMethod]
        public void TestParseNtlmChallengeMessage()
        {
            const string originHex = "4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000";
            var message = NtlmChallengeMessage.Parse(originHex.HexToBytes());

            Assert.IsTrue(message.Signature == Constants.Ntlmssp);
            Assert.IsTrue(message.Type == MessageType.Challenge);
            Assert.IsTrue(message.Flags == (MessageFlag.NegotiateUnicode
                | MessageFlag.NegotiateNtlm
                | MessageFlag.TargetTypeDomain
                | MessageFlag.NegotiateTargetInfo));

            const string challengeHex = "0123456789abcdef";
            Assert.IsTrue(message.Message.Challenge.BytesToHex()
                .Equals(challengeHex, StringComparison.InvariantCultureIgnoreCase));

            Assert.IsTrue(message.Message.TargetNameLength == 12);
            Assert.IsTrue(message.Message.TargetNameSpace == 12);
            Assert.IsTrue(message.Message.TargetNameOffset == 48);

            Assert.IsTrue(message.TargetName == "DOMAIN");

            Assert.IsTrue(message.Message.TargetInfosLength == 98);
            Assert.IsTrue(message.Message.TargetInfosSpace == 98);
            Assert.IsTrue(message.Message.TargetInfosOffset == 60);

            var info = message.TargetInfoList;

            Assert.IsTrue(info.Count == 5);

            Assert.IsTrue(info[0].TargetInfoType == TargetInfoType.DomainName);
            Assert.IsTrue(info[0].TargetContent == "DOMAIN");

            Assert.IsTrue(info[1].TargetInfoType == TargetInfoType.ServerName);
            Assert.IsTrue(info[1].TargetContent == "SERVER");

            Assert.IsTrue(info[2].TargetInfoType == TargetInfoType.DnsDomainName);
            Assert.IsTrue(info[2].TargetContent == "domain.com");

            Assert.IsTrue(info[3].TargetInfoType == TargetInfoType.FullyQualifiedDomainName);
            Assert.IsTrue(info[3].TargetContent == "server.domain.com");

            Assert.IsTrue(info[4].TargetInfoType == TargetInfoType.Terminator);
            Assert.IsTrue(info[4].TargetContent == null);

            var actualHex = message.ToBytes().BytesToHex();

            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TestCreateNtlmChallengeMessage()
        {
            const string originHex = "4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000";
            var messageStruct = new ChallengeMessageStruct
            {
                Signature = Constants.NtlmsspBytes,
                Type = MessageType.Challenge,
                Flags = MessageFlag.NegotiateUnicode
                        | MessageFlag.NegotiateNtlm
                        | MessageFlag.TargetTypeDomain
                        | MessageFlag.NegotiateTargetInfo,
                Challenge = HexHelper.HexToBytes("0123456789abcdef"),
                Context = HexHelper.HexToBytes("0000000000000000")
            };
            var message = new NtlmChallengeMessage(messageStruct, "DOMAIN");
            message.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.DomainName, "DOMAIN", Encoding.Unicode));
            message.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.ServerName, "SERVER", Encoding.Unicode));
            message.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.DnsDomainName, "domain.com", Encoding.Unicode));
            message.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.FullyQualifiedDomainName, "server.domain.com", Encoding.Unicode));
            message.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.Terminator));

            message.Rectify();

            Assert.IsTrue(message.Signature == Constants.Ntlmssp);
            Assert.IsTrue(message.Type == MessageType.Challenge);
            Assert.IsTrue(message.Flags == (MessageFlag.NegotiateUnicode
                | MessageFlag.NegotiateNtlm
                | MessageFlag.TargetTypeDomain
                | MessageFlag.NegotiateTargetInfo));

            const string challengeHex = "0123456789abcdef";
            Assert.IsTrue(message.Message.Challenge.BytesToHex()
                .Equals(challengeHex, StringComparison.InvariantCultureIgnoreCase));

            Assert.IsTrue(message.Message.TargetNameLength == 12);
            Assert.IsTrue(message.Message.TargetNameSpace == 12);
            Assert.IsTrue(message.Message.TargetNameOffset == 48);

            Assert.IsTrue(message.TargetName == "DOMAIN");

            Assert.IsTrue(message.Message.TargetInfosLength == 98);
            Assert.IsTrue(message.Message.TargetInfosSpace == 98);
            Assert.IsTrue(message.Message.TargetInfosOffset == 60);

            var info = message.TargetInfoList;

            Assert.IsTrue(info.Count == 5);

            Assert.IsTrue(info[0].TargetInfoType == TargetInfoType.DomainName);
            Assert.IsTrue(info[0].TargetContent == "DOMAIN");

            Assert.IsTrue(info[1].TargetInfoType == TargetInfoType.ServerName);
            Assert.IsTrue(info[1].TargetContent == "SERVER");

            Assert.IsTrue(info[2].TargetInfoType == TargetInfoType.DnsDomainName);
            Assert.IsTrue(info[2].TargetContent == "domain.com");

            Assert.IsTrue(info[3].TargetInfoType == TargetInfoType.FullyQualifiedDomainName);
            Assert.IsTrue(info[3].TargetContent == "server.domain.com");

            Assert.IsTrue(info[4].TargetInfoType == TargetInfoType.Terminator);
            Assert.IsTrue(info[4].TargetContent == null);

            var actualHex = message.ToBytes().BytesToHex();

            Assert.IsTrue(originHex.Equals(actualHex, StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
