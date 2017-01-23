using System;
using System.Net;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.API_Endpoints
{
  public class API_Endpoints
  {
    public static Object_API_Endpoints.PrimaryConfig PrimaryConfig { get { return ApiConfigClean(); } }

    private static Object_API_Endpoints.API GetApiEndpoints()
    {
      var query = "http://127.0.0.1:5984/fido_api_endpoints/_design/api/_view/endpoints";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new Object_API_Endpoints.API();

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(alertRequest, false);
        if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
        cdbReturn = JsonConvert.DeserializeObject<Object_API_Endpoints.API>(stringreturn);
        return cdbReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }

      return cdbReturn;
    }

    public static Object_API_Endpoints.PrimaryConfig ApiConfigClean()
    {
      var Api = new Object_API_Endpoints.API();

      Api = GetApiEndpoints();

      var api = new Object_API_Endpoints.PrimaryConfig();

      api = Api.rows[0].key.apicall.runtest ? Api.rows[0].key.apicall.test : Api.rows[0].key.apicall.production;
      if (api.globalconfig.ssl) api.host = Api.rows[0].key.apicall.runtest ? @"https://" + Api.rows[0].key.apicall.test.globalconfig.host + @":" + Api.rows[0].key.apicall.test.globalconfig.port + @"/" : @"https://" + Api.rows[0].key.apicall.production.globalconfig.host + @":" + Api.rows[0].key.apicall.production.globalconfig.port + @"/";
      else api.host = Api.rows[0].key.apicall.runtest ? @"http://" + Api.rows[0].key.apicall.test.globalconfig.host + @":" + Api.rows[0].key.apicall.test.globalconfig.port + @"/" : @"http://" + Api.rows[0].key.apicall.production.globalconfig.host + @":" + Api.rows[0].key.apicall.production.globalconfig.port + @"/";
      api.runtest = Api.rows[0].key.apicall.runtest;
      return api;
    }
  }
}
