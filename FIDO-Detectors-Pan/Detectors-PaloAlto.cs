using System;
using System.Net;
using System.Threading;
using FIDO_Detector.Fido_Support.API_Endpoints;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.PAN
{
  internal static class DetectorsPaloAlto
  {
    private static readonly Object_Fido_Configs_CouchDB_App.StartupConfigs StartupConfigs = GetConfigs();

    private static void Main(string[] args)
    {
      var fidoTimeout = StartupConfigs.rows[0].value.fidotimout;

      // Create a Timer object that knows to call our DisplayTimeEvent
      // method once every 100 milliseconds.
      var iSleep = Convert.ToInt32(fidoTimeout) * 1000;
      Timer t = new Timer(DetectorStartup, null, 0, iSleep);
      
      // Wait for the user to hit <Enter>
      Console.ReadLine(); ; 
    }

    private static void DetectorStartup(object o)
    {
      RunDetector();
      GC.Collect();
    }

    private static void RunDetector()
    {
      var fidoTimeout = StartupConfigs.rows[0].value.fidotimout; 
      PaloAlto.GetPANJob();
      Console.WriteLine(@"Sleeping for " + Convert.ToString(Convert.ToInt32(fidoTimeout)) + @" seconds.");
    }

    private static Object_Fido_Configs_CouchDB_App.StartupConfigs GetConfigs()
    {
      //Load Fido configs from CouchDB
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs.app_configs.startup_configs;
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Method = @"GET";
      var startupConfigs = new Object_Fido_Configs_CouchDB_App.StartupConfigs();

      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(request, false);
        startupConfigs = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_App.StartupConfigs>(stringreturn);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in fidomain area gathering startup configs:" + e);
      }

      return startupConfigs;
    }
  }
}
