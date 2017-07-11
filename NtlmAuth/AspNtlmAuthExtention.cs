using System;
using System.Net;
using System.Text;
using System.Web;

namespace NtlmAuth
{
    public static class AspNtlmAuthExtention
    {
        public const MessageFlag SupportedMessageFlag =
            MessageFlag.NegotiateUnicode |
            MessageFlag.NegotiateNtlm |
            MessageFlag.TargetTypeDomain |
            MessageFlag.NegotiateTargetInfo |
            MessageFlag.NegotiateAlwaysSign |
            MessageFlag.RequestTarget;

        public static void CheckNtlmAuth(this HttpContext context, string userName, string password, Action<string> log)
        {
            var request = context.Request;
            var auth = request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(auth))
            {
                SendUnauthorized(context);
            }
            else
            {
                if (auth.StartsWith("NTLM"))
                {
                    var base64 = auth.Substring(5);
                    var token = Convert.FromBase64String(base64);
                    if (token[8] == 1)
                    {
                        var message1 = new NegotiationMessageShell(token);

                        log($"Message 1 Flags: {message1.Flags}");
                        log($"Message 1 Domain: {message1.Domain}");
                        log($"Message 1 Host: {message1.Host}");

                        var challengeMessage = new ChallengeMessage
                        {
                            Flags = SupportedMessageFlag & message1.Flags | MessageFlag.TargetTypeDomain,
                            Challenge = Encoding.ASCII.GetBytes("12345678"),
                            Protocol = message1.Message.Protocol,
                            Type = MessageType.Challenge
                        };

                        var message2 = new ChallengeMessageShell(challengeMessage)
                        {
                            TargetName = "Test",
                            TargetInfoDataContent = "Test",
                            TargetInfoType = TargetInfoType.DomainName
                        };

                        log($"Message 2 Flags: {message2.Flags}");
                        log($"Message 2 TargetName: {message2.TargetName}");
                        log($"Message 2 TargetInfo: {message2.TargetInfoDataContent}");

                        SendUnauthorized(context, message2.ToBytes());
                    }
                    else if (token[8] == 3)
                    {
                        var challenge = Encoding.ASCII.GetBytes("12345678");

                        var message3 = new AuthenticationMessageShell(token);
                        var hexExpectNtlmRes = message3.NtlmResponseData.BytesToHex();

                        log($"Message 3 Flags: {message3.Flags}");
                        log($"Message 3 UserName: {message3.UserName}");
                        log($"Message 3 HostName: {message3.HostName}");
                        log($"Message 3 TargetName: {message3.TargetName}");

                        if (message3.UserName.Equals(userName))
                        {
                            if (message3.Message.NtlmResponseLength == 24)
                            {
                                var hexNtlmRes = NtlmResponses.GetNtlmResponse(password, challenge).BytesToHex();
                                if (!hexExpectNtlmRes.Equals(hexNtlmRes, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    SendUnauthorized(context);
                                }
                            }
                            else
                            {
                                var expectHmac = message3.NtlmResponseData.NewCopy(0, 16);
                                var expectBlob = message3.NtlmResponseData.NewCopy(16);
                                var hexExpectHmac = expectHmac.BytesToHex();

                                var actualHmac = NtlmResponses.GetNtlmV2ResponseHash(
                                    message3.TargetName, userName, password, expectBlob, challenge);
                                var hexActualHmac = actualHmac.BytesToHex();

                                if (!hexExpectHmac.Equals(hexActualHmac, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    SendUnauthorized(context);
                                }
                            }
                        }
                        else
                        {
                            SendUnauthorized(context);
                        }
                    }
                }
                else
                {
                    SendUnauthorized(context);
                }
            }
        }

        private static void SendUnauthorized(HttpContext context, byte[] messageBytes = null)
        {
            var base64 = messageBytes == null ? string.Empty : $" {Convert.ToBase64String(messageBytes)}";
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Response.ContentType = "text/html";
            context.Response.CacheControl = "no-cache";
            context.Response.Headers.Add("WWW-Authenticate", "NTLM" + base64);
            context.Response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
            context.ApplicationInstance.CompleteRequest();
        }
    }
}
