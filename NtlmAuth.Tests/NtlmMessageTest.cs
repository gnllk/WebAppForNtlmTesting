using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NtlmAuth.Tests
{
    [TestClass]
    public class NtlmMessageTest
    {
        [TestMethod]
        public void TestCreateNegotiationMessage()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAvAjAAAADw==");
            var message = new NtlmNegotiateMessage(data);
        }

        [TestMethod]
        public void TestCreateChallengeMessage()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAACAAAACAAIADgAAAAFgoqiNDsqUEfiH5QAAAAAAAAAAEAAQABAAAAABgGxHQAAAA9EAFAAQwAyAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQAAAAA=");
            var message = new NtlmChallengeMessage(data);
        }

        [TestMethod]
        public void TestCreateAuthenticationMessage()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAADAAAAGAAYAIAAAADqAOoAmAAAAAYABgBYAAAAGgAaAF4AAAAIAAgAeAAAAAAAAACCAQAABYKIogYC8CMAAAAPsyUuXH4iBM3WR8qXl4iSZkwARQBPAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIATABQAEMAMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc6JDjDlappZQyXfOifmWDAQEAAAAAAADK7TsuuPvSAeZKtohXEK4gAAAAAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQYABAAGAAAACAAwADAAAAAAAAAAAAAAAAAwAAA046V6bZCIbNXFgAcnSiWirh3OxjYjNDwEkiay+DYhJQoAEAAAAAAAAAAAAAAAAAAAAAAACQAiAEgAVABUAFAALwBjAG0AbgAuAGsAaQBuAGcALgBjAG8AbQAAAAAAAAAAAAAAAAA=");
            var message = new NtlmAuthenticationMessage(data);
        }
    }
}
