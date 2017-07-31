using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Web;

namespace NtlmAuth
{
    public static class AspNetNtlmAuthExtention
    {
        private readonly static Dictionary<string, bool> IsLogonTable = new Dictionary<string, bool>();

        public const MessageFlag SupportedMessageFlag =
            MessageFlag.NegotiateUnicode |
            MessageFlag.NegotiateNtlm |
            MessageFlag.TargetTypeDomain |
            MessageFlag.NegotiateTargetInfo |
            MessageFlag.NegotiateAlwaysSign |
            MessageFlag.RequestTarget;

        private static readonly byte[] Challenge = "0123456789abcdef".HexToBytes();

        private static readonly byte[] ZeroBytes = "0000000000000000".HexToBytes();

        public static void CheckNtlmAuth(this HttpContext context, string userName, string password, Action<string> log)
        {
            MakeIdentity(context);

            if (CheckLogon(context)) return;

            var auth = context.Request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("NTLM"))
            {
                SendUnauthorized(context);
            }
            else
            {
                var base64 = auth.Substring(5); //skip "NTLM "
                var token = Convert.FromBase64String(base64);
                var header = token.ToStruct<MessageHeaderStruct>();

                switch (header.Type)
                {
                    case MessageType.Negotiation:
                        var message1 = NtlmNegotiateMessage.Parse(token);
                        SendChallengeMessage(context, message1, log);
                        break;
                    case MessageType.Authentication:
                        var message3 = new NtlmAuthenticationMessage(token);
                        ValidateAuthMessage(context, userName, password, message3, log);
                        break;
                    default:
                        SendUnauthorized(context);
                        break;
                }
            }
        }

        private static void ValidateAuthMessage(HttpContext context, string userName, string password,
            NtlmAuthenticationMessage authMessage, Action<string> log)
        {
            log($"Message 3 Flags: {authMessage.Flags}");
            log($"Message 3 UserName: {authMessage.UserName}");
            log($"Message 3 HostName: {authMessage.HostName}");
            log($"Message 3 TargetName: {authMessage.TargetName}");

            if (authMessage.UserName.Equals(userName, StringComparison.InvariantCultureIgnoreCase))
            {
                if (authMessage.Message.NtlmResponseLength == 24)
                {
                    ValidateNtlmResponse(context, password, authMessage, Challenge);
                }
                else
                {
                    ValidateNtlmV2Response(context, userName, password, authMessage, Challenge);
                }
            }
            else
            {
                SendUnauthorized(context);
            }
        }

        private static void ValidateNtlmV2Response(HttpContext context, string userName, string password,
            NtlmAuthenticationMessage authMessage, byte[] challenge)
        {
            var expectHmac = authMessage.NtlmResponseData.NewCopy(0, 16);
            var expectBlob = authMessage.NtlmResponseData.NewCopy(16);
            var hexExpectHmac = expectHmac.BytesToHex();

            var actualHmac = NtlmResponses.GetNtlmV2ResponseHash(
                authMessage.TargetName, userName, password, expectBlob, challenge);
            var hexActualHmac = actualHmac.BytesToHex();

            if (!hexExpectHmac.Equals(hexActualHmac, StringComparison.InvariantCultureIgnoreCase))
            {
                SendUnauthorized(context);
            }
            else
            {
                MarkAsLogon(context);
            }
        }

        private static void ValidateNtlmResponse(HttpContext context, string password,
            NtlmAuthenticationMessage authMessage, byte[] challenge)
        {
            var hexExpectNtlmRes = authMessage.NtlmResponseData.BytesToHex();
            var hexNtlmRes = NtlmResponses.GetNtlmResponse(password, challenge).BytesToHex();
            if (!hexExpectNtlmRes.Equals(hexNtlmRes, StringComparison.InvariantCultureIgnoreCase))
            {
                SendUnauthorized(context);
            }
            else
            {
                MarkAsLogon(context);
            }
        }

        private static void SendChallengeMessage(HttpContext context, NtlmNegotiateMessage negotiateMessage,
            Action<string> log)
        {
            if (negotiateMessage == null)
                throw new ArgumentNullException(nameof(negotiateMessage));

            if (log != null)
            {
                log($"Message 1 Flags: {negotiateMessage.Flags}");
                log($"Message 1 Domain: {negotiateMessage.Domain}");
                log($"Message 1 Host: {negotiateMessage.Host}");
            }

            var messageStruct = new ChallengeMessageStruct
            {
                Signature = Constants.NtlmsspBytes,
                Type = MessageType.Challenge,
                Flags = SupportedMessageFlag & negotiateMessage.Flags,
                Challenge = Challenge,
                Context = ZeroBytes
            };

            var message2 = new NtlmChallengeMessage(messageStruct, "DOMAIN");
            message2.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.DomainName, "DOMAIN", Encoding.Unicode));
            message2.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.ServerName, "SERVER", Encoding.Unicode));
            message2.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.DnsDomainName, "domain.com", Encoding.Unicode));
            message2.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.FQDN, "server.domain.com", Encoding.Unicode));
            message2.TargetInfoList.Add(new NtlmTargetInfo(TargetInfoType.Terminator));
            message2.Rectify();

            if (log != null)
            {
                log($"Message 2 Flags: {message2.Flags}");
                log($"Message 2 TargetName: {message2.TargetName}");
            }

            SendUnauthorized(context, message2.ToBytes());
        }

        private static void SendUnauthorized(HttpContext context, byte[] messageBytes = null)
        {
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Response.ContentType = "text/html";
            context.Response.CacheControl = "no-cache";
            if (messageBytes == null || messageBytes.Length == 0)
            {
                context.Response.Headers.Add("WWW-Authenticate", "NTLM");
            }
            else
            {
                context.Response.Headers.Add("WWW-Authenticate", $"NTLM {Convert.ToBase64String(messageBytes)}");
            }
            context.Response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
            context.ApplicationInstance.CompleteRequest();
        }

        private static void MarkAsLogon(HttpContext context)
        {
            if (context.Request.Cookies.Get("identity") == null)
                return;
            var id = context.Request.Cookies.Get("identity").Value.ToString();
            IsLogonTable[id] = true;
        }

        private static bool CheckLogon(HttpContext context)
        {
            if (context.Request.Cookies.Get("identity") == null)
                return false;
            var id = context.Request.Cookies.Get("identity").Value.ToString();
            return IsLogonTable.ContainsKey(id) && IsLogonTable[id];
        }

        private static void MakeIdentity(HttpContext context)
        {
            // this is dangerous key
            if (context.Request.Cookies.Get("identity") == null)
            {
                var identity = Guid.NewGuid().ToString();
                var cookie = new HttpCookie("identity", identity);
                cookie.Expires = DateTime.Now.AddMinutes(3);
                context.Response.Cookies.Add(cookie);
            }
        }
    }
}
