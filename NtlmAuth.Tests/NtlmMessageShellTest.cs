using System;
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
            var message = new NegotiationMessageShell(data);
        }

        [TestMethod]
        public void TestCreateChallengeMessageShell()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAACAAAACAAIADgAAAAFgoqiNDsqUEfiH5QAAAAAAAAAAEAAQABAAAAABgGxHQAAAA9EAFAAQwAyAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQAAAAA=");
            var message = new ChallengeMessageShell(data);
        }

        [TestMethod]
        public void TestCreateAuthenticationMessageShell()
        {
            var data = Convert.FromBase64String("TlRMTVNTUAADAAAAGAAYAIAAAADqAOoAmAAAAAYABgBYAAAAGgAaAF4AAAAIAAgAeAAAAAAAAACCAQAABYKIogYC8CMAAAAPsyUuXH4iBM3WR8qXl4iSZkwARQBPAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIATABQAEMAMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACc6JDjDlappZQyXfOifmWDAQEAAAAAAADK7TsuuPvSAeZKtohXEK4gAAAAAAIACABEAFAAQwAyAAEACABEAFAAQwAyAAQACABEAFAAQwAyAAMACABEAFAAQwAyAAcACADK7TsuuPvSAQYABAAGAAAACAAwADAAAAAAAAAAAAAAAAAwAAA046V6bZCIbNXFgAcnSiWirh3OxjYjNDwEkiay+DYhJQoAEAAAAAAAAAAAAAAAAAAAAAAACQAiAEgAVABUAFAALwBjAG0AbgAuAGsAaQBuAGcALgBjAG8AbQAAAAAAAAAAAAAAAAA=");
            var message = new AuthenticationMessageShell(data);
        }
    }
}
