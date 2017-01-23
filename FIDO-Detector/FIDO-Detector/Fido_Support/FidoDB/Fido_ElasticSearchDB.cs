using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.FidoDB
{
  public class Fido_ElasticSearchDB
  {

    public void WriteToDBFactory(FidoReturnValues lFidoReturnValues)
    {
      var strJson = SerializeJson.Serialize(lFidoReturnValues);
      strJson = strJson.Replace("location", "geoip.coordinates");
      strJson = strJson.Replace("TimeOccured", "@timestamp");
      strJson = strJson.Replace('"' + "Last_contact_time_utc" + '"' + ":" + '"' + '"' + ",", string.Empty);
      var uuid = lFidoReturnValues.AlertID;
      var tempmonth = DateTime.Now.Month;
      string month;
      if (tempmonth.ToString().Length == 1)
      {
        month = @"0" + tempmonth;
      }
      else
      {
        month = tempmonth.ToString();
      }
 
      var index = @"infosecfido" + DateTime.Now.Year + month;
      var type = lFidoReturnValues.CurrentDetector;
      WriteAlertToElasticSearchDB(strJson, index, type, uuid);
    }

    private void WriteAlertToElasticSearchDB(string strJson, string index, string type, string uuid)
    {
      Console.WriteLine(@"Writing entry to ElasticSearch DB.");
      //var query = @"http://127.0.0.1:31311/" + index + "/" + type + "/" + uuid;
      var query = @"http://es_itops.us-west-2.dynprod.netflix.net:7104/" + index + "/" + type + "/" + uuid;
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (result.IsSuccessStatusCode)
        {
          Console.WriteLine(@"Entry written to DB.");
          Thread.Sleep(500);
        }
        else if (result.StatusCode == HttpStatusCode.BadRequest)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to ES:" + " " + query);
        }
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to ES:" + e + " " + query + " " + e.Status);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to ES:" + " " + query);
      }
    }
  }
}
