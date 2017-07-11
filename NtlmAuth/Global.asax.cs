﻿using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using log4net;
using log4net.Config;

namespace NtlmAuth
{
    public class Global : HttpApplication
    {
        private const MessageFlag SupportedMessageFlag =
            MessageFlag.NegotiateUnicode |
            MessageFlag.NegotiateNtlm |
            MessageFlag.TargetTypeDomain |
            MessageFlag.NegotiateTargetInfo
            ;

        private static readonly ILog Log = LogManager.GetLogger(typeof(Global));

        protected void Application_Start(object sender, EventArgs e)
        {
            Log.Info("Application Start");
            XmlConfigurator.Configure();
        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            Log.Info("Application BeginRequest");
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

                        Log.Info($"Message 1 Flags: {message1.Flags}");
                        Log.Info($"Message 1 Domain: {message1.Domain}");
                        Log.Info($"Message 1 Host: {message1.Host}");

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

                        Log.Info($"Message 2 Flags: {message2.Flags}");
                        Log.Info($"Message 2 TargetName: {message2.TargetName}");
                        Log.Info($"Message 2 TargetInfo: {message2.TargetInfoDataContent}");

                        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        Response.ContentType = "text/html";
                        Response.Headers.Add("WWW-Authenticate", $"NTLM {Convert.ToBase64String(message2.ToBytes())}");
                        Response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
                    }
                    else if (token[8] == 3)
                    {
                        var userName = "tom";
                        var password = "123456";
                        var challenge = Encoding.ASCII.GetBytes("12345678");

                        var message3 = new AuthenticationMessageShell(token);
                        var hexExpectNtlmRes = message3.NtlmResponseData.BytesToHex();

                        Log.Info($"Message 3 Flags: {message3.Flags}");
                        Log.Info($"Message 3 UserName: {message3.UserName}");
                        Log.Info($"Message 3 HostName: {message3.HostName}");
                        Log.Info($"Message 3 TargetName: {message3.TargetName}");

                        if (message3.Message.NtlmResponseLength == 24)
                        {
                            var hexNtlmRes = NtlmResponses.GetNtlmResponse(password, challenge).BytesToHex();
                            if (!hexExpectNtlmRes.Equals(hexNtlmRes, StringComparison.InvariantCultureIgnoreCase))
                            {
                                SendUnauthorized(Response);
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
                                SendUnauthorized(Response);
                            }
                        }
                    }
                }
                else
                {
                    SendUnauthorized(Response);
                }
            }
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