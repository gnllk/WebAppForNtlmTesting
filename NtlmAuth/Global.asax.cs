using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace NtlmAuth
{
    public class Global : HttpApplication
    {
        private const MessageFlag SupportedMessageFlag =
            MessageFlag.NegotiateUnicode |
            MessageFlag.NegotiateNtlm;

        protected void Application_Start(object sender, EventArgs e)
        {

        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            var auth = Request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(auth))
            {
                SendUnauthorized(Response);
            }
            else
            {
                if (auth.StartsWith("Negotiate"))
                {
                    var base64 = auth.Substring(10);
                    var token = Convert.FromBase64String(base64);
                }
                else if (auth.StartsWith("NTLM"))
                {
                    var base64 = auth.Substring(5);
                    var token = Convert.FromBase64String(base64);
                    if (token[8] == 1)
                    {
                        // negotiation message
                        var message1 = new NegotiationMessageShell(token);

                        var challengeMessage = new ChallengeMessage
                        {
                            Flags = SupportedMessageFlag & message1.Flags,
                            Challenge = Encoding.ASCII.GetBytes("12345678"),
                            Protocol = message1.Message.Protocol,
                            Type = MessageType.Challenge
                        };

                        var message2 = new ChallengeMessageShell(challengeMessage)
                        {
                            TargetName = "leo.com",
                            TargetInfoDataContent = "leo.com",
                            TargetInfoType = TargetInfoType.DnsDomainName
                        };

                        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        Response.ContentType = "text/html";
                        Response.Headers.Add("WWW-Authenticate", $"NTLM {Convert.ToBase64String(message2.ToBytes())}");
                        Response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
                    }
                    else if (token[8] == 3)
                    {
                        // message type 3
                        var message3 = new AuthenticationMessageShell(token);

                        var response = new LmResponse(message3.LmResponseData, "12345678", "jackjackjack");
                        //var result = response.Validate();

                        var requestNtmlRes = HexHelper.BytesToHex(message3.NtlmResponseData);

                        var ntlmRes1 = JavaResponses.GetNTLMResponse("jackjackjack", Encoding.ASCII.GetBytes("12345678"));
                        var ntmlHex1 = HexHelper.BytesToHex(ntlmRes1);



                        var challengeMessage = new ChallengeMessage
                        {
                            Flags = SupportedMessageFlag & message3.Flags,
                            Challenge = Encoding.ASCII.GetBytes("12345678"),
                            Protocol = message3.Message.Protocol,
                            Type = MessageType.Challenge
                        };

                        var message2 = new ChallengeMessageShell(challengeMessage)
                        {
                            TargetName = "leo.com",
                            TargetInfoDataContent = "leo.com",
                            TargetInfoType = TargetInfoType.DnsDomainName
                        };


                        var ntlmRes2 = JavaResponses.GetNTLMv2Response("leo.com", "llk", "jackjackjack", message2.GetTargetInfo(), Encoding.ASCII.GetBytes("12345678"), Encoding.ASCII.GetBytes("12345678"));
                        var ntmlHex2 = HexHelper.BytesToHex(ntlmRes2);

                        var ntlmRes3 = JavaResponses.GetNTLM2SessionResponse("jackjackjack", Encoding.ASCII.GetBytes("12345678"), Encoding.ASCII.GetBytes("12345678"));
                        var ntmlHex3 = HexHelper.BytesToHex(ntlmRes2);
                    }
                }
                else
                {
                    SendUnauthorized(Response);
                }
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static void SendUnauthorized(HttpResponse response)
        {
            response.StatusCode = (int)HttpStatusCode.Unauthorized;
            response.ContentType = "text/html";
            response.CacheControl = "no-cache";
            //response.Headers.Add("WWW-Authenticate", "Negotiate");
            response.Headers.Add("WWW-Authenticate", "NTLM");
            response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {

        }

        protected void Application_Error(object sender, EventArgs e)
        {

        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {

        }
    }
}