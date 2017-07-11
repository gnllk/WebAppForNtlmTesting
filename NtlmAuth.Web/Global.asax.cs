using System;
using System.Web;
using log4net;
using log4net.Config;

namespace NtlmAuth.Web
{
    public class Global : HttpApplication
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(Global));

        protected void Application_Start(object sender, EventArgs e)
        {
            Log.Info("Application_Start");
            XmlConfigurator.Configure();
        }

        protected void Session_Start(object sender, EventArgs e)
        {
            Log.Info("Session_Start");
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            Log.Info("Application_BeginRequest");
            Context.CheckNtlmAuth("Admin", "123456", Log.Info);
        }


        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            Log.Info("Application_AuthenticateRequest");
        }

        protected void Application_Error(object sender, EventArgs e)
        {
            Log.Info("Application_Error");
        }

        protected void Session_End(object sender, EventArgs e)
        {
            Log.Info("Session_End");
        }

        protected void Application_End(object sender, EventArgs e)
        {
            Log.Info("Application_End");
        }
    }
}