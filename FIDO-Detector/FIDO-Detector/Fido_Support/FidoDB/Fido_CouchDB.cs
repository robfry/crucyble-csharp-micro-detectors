using System;
using System.Net;
using System.Net.Http;
using System.Text;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.FidoDB
{
  public class Fido_CouchDB
  {

    public string WriteToDBFactory(FidoReturnValues lFidoReturnValues)
    {
      var strJson = SerializeJson.Serialize(lFidoReturnValues);
      //var formatJson = new Fido_CouchDB_Detector();
      //var threat = formatJson.ReturnJson(lFidoReturnValues);
      //WriteThreatToCouchDB(threat);
      var uuid = WriteAlertToCouchDB(strJson, lFidoReturnValues.TimeOccured);
      return uuid;
    }

    private string WriteAlertToCouchDB(string strJson, string strTimeDate)
    {
      Console.WriteLine(@"Writing alert to CouchDB.");
      var uuid = GetUUID();
      var query = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_events_alerts.dbname + "/" + uuid.UUIDS[0];
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (!result.IsSuccessStatusCode) return string.Empty;
        Console.WriteLine(@"Alert written to DB.");
        return uuid.UUIDS[0];
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to CouchDB alert area:" + e);
      }
      return string.Empty;
    }

    private void WriteThreatToCouchDB(string strJson)
    {
      Console.WriteLine(@"Writing threat data to CouchDB.");
      var uuid = GetUUID();
      var query = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_events_alerts + "/" + uuid.UUIDS[0];
        //@"http://127.0.0.1:5984/fido_threatfeeds/" + uuid.UUIDS[0];
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (result.IsSuccessStatusCode)
        {
          Console.WriteLine(@"Threat information written to DB.");
        }
      }

      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to CouchDB threat area:" + e);
      }

    }

    private CouchDBUUID GetUUID()
    {
      var uuid = new CouchDBUUID();
      var request = API_Endpoints.API_Endpoints.PrimaryConfig.host + @"_uuids";
        //@"http://127.0.0.1:5984/_uuids";
      var connection = (HttpWebRequest)WebRequest.Create(request);
      connection.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(connection, false);
        var jsonRet = JsonConvert.DeserializeObject<CouchDBUUID>(stringreturn);
        if (string.IsNullOrEmpty(jsonRet.ToString())) return uuid;
        uuid = jsonRet;
        return uuid;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in GetUUID of CouchDB getting UUID:" + e);
      }


      return uuid;
    }

    private class CouchDBUUID
    {
      [JsonProperty("uuids")]
      internal string[] UUIDS { get; set; }
    }
  }
}
