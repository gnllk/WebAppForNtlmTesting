using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmMessageShellTest
    {
        [TestMethod]
        public void TestCreateNegotiationMessageShell()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAvAjAAAADw==");
            var message = new NtlmNegotiationMessage(data);
        }

        [TestMethod]
        public void TestCreateChallengeMessageShell()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAACAAAACAAIADgAAAAFgoqiNDsqUEfiH5QAAAAAAAAAAEAAQABAAAAABgGxHQAAAA9EAFAAQwAyAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQAAAAA=");
            var message = new NtlmChallengeMessage(data);
        }

        [TestMethod]
        public void TestCreateAuthenticationMessageShell()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAADAAAAGAAYAIAAAADqAOoAmAAAAAYABgBYAAAAGgAaAF4AAAAIAAgAeAAAAAAAAACCAQAABYKIogYC8CMAAAAPsyUuXH4iBM3WR8qXl4iSZkwARQBPAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIATABQAEMAMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc6JDjDlappZQyXfOifmWDAQEAAAAAAADK7TsuuPvSAeZKtohXEK4gAAAAAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQYABAAGAAAACAAwADAAAAAAAAAAAAAAAAAwAAA046V6bZCIbNXFgAcnSiWirh3OxjYjNDwEkiay+DYhJQoAEAAAAAAAAAAAAAAAAAAAAAAACQAiAEgAVABUAFAALwBjAG0AbgAuAGsAaQBuAGcALgBjAG8AbQAAAAAAAAAAAAAAAAA=");
            var message = new AuthenticationMessageShell(data);
        }

        [TestMethod]
        public void TestChallengeMessageShell()
        {
            var challengeMessage = new ChallengeMessageStruct
            {
                Flags = AspNetNtlmAuthExtention.SupportedMessageFlag | MessageFlag.TargetTypeDomain,
                Challenge = Encoding.ASCII.GetBytes("12345678"),
                Protocol = Encoding.ASCII.GetBytes("NTLMSSP\0"),
                Type = MessageType.Challenge
            };

            var message = new NtlmChallengeMessage(challengeMessage, "Test",
                new TargetInfoShell(TargetInfoType.DomainName, "pc3", Encoding.Unicode),
                new TargetInfoShell(TargetInfoType.ServerName, "pc3", Encoding.Unicode),
                new TargetInfoShell(TargetInfoType.DnsDomainName, "pc3", Encoding.Unicode),
                new TargetInfoShell(TargetInfoType.FullyQualifiedDomainName, "pc3", Encoding.Unicode),
                new TargetInfoShell(TargetInfoType.Terminator));

            var messageHex = message.ToBytes().BytesToHex();
            var messageData = messageHex.HexToBytes();

            var rebuild = new NtlmChallengeMessage(messageData);

            Assert.IsTrue(rebuild.TargetName == "Test");
            Assert.IsTrue(rebuild.TargetInfoList.Count == 5);
        }

        [TestMethod]
        public void TestTargetInfoShellList()
        {
            var data = "02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000".HexToBytes();
            var info = TargetInfoShellList.Parse(data, Encoding.Unicode);

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
        }
    }
}
