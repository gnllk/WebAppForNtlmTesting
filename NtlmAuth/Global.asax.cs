using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Web;

namespace NtlmAuth
{
    public class Global : HttpApplication
    {

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
                        // message type 1
                        var size = Marshal.SizeOf(typeof(NegotiationMessage));
                        var msgPtr = Marshal.AllocHGlobal(size);
                        Marshal.Copy(token, 0, msgPtr, size);
                        var message = Marshal.PtrToStructure<NegotiationMessage>(msgPtr);
                        Marshal.FreeHGlobal(msgPtr);

                        // testing
                        var ddd = new NegotiationMessageShell(message, token);

                        var size2 = Marshal.SizeOf(typeof(ChallengeMessage));
                        var msgType2 = new ChallengeMessage
                        {
                            Flags = message.Flags,
                            Nonce = Encoding.ASCII.GetBytes("23jdk5jU"),
                            Protocol = message.Protocol,
                            Type = 2,
                            MessageLength = size2,
                            FillZero = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 }
                        };

                        var msgPtr2 = Marshal.AllocHGlobal(size2);
                        Marshal.StructureToPtr(msgType2, msgPtr2, true);
                        var bytes2 = new byte[size2];
                        Marshal.Copy(msgPtr2, bytes2, 0, size2);
                        Marshal.FreeHGlobal(msgPtr2);

                        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        Response.ContentType = "text/html";
                        Response.Headers.Add("WWW-Authenticate", $"NTLM {Convert.ToBase64String(bytes2)}");
                        Response.Write(Encoding.ASCII.GetBytes("Unauthorized"));
                    }
                    else if (token[8] == 3)
                    {
                        // message type 3
                        var size = Marshal.SizeOf(typeof(AuthenticationMessage));
                        var msgPtr = Marshal.AllocHGlobal(size);
                        Marshal.Copy(token, 0, msgPtr, size);
                        var message = Marshal.PtrToStructure<AuthenticationMessage>(msgPtr);
                        Marshal.FreeHGlobal(msgPtr);
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