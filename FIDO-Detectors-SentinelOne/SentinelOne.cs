/*
 *
 *  Copyright 2015 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FIDO_Detector.Director.SysMgmt;
using FIDO_Detector.Fido_Support.API_Endpoints;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.CouchDB;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Objects.SentinelOne;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.SentinelOne
{
  class DetectSentinelOne
  {
    public static void GetSentinelOneAlert()
    {
      Console.WriteLine(@"Gathering alert data from SentinelOne.");
      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs("sentinelone");
      

      Parallel.ForEach(parseConfigs, conf =>
      {
        var request = conf.server + conf.query[0];
        var alertRequest = (HttpWebRequest)WebRequest.Create(request);
        alertRequest.Method = "GET";
        alertRequest.Headers[@"Authorization"] = @"Token " + Base64.Decode(conf.token);

        try
        {
          var getREST = new Fido_Rest_Connection();
          var stringreturn = getREST.RestCall(alertRequest,false);
          if (string.IsNullOrEmpty(stringreturn)) return;
          if (stringreturn == "404")
          {
            GetToken(@"https://netflix.sentinelone.net/web/api/v1.6/users/login");
            return;
          }
          if (stringreturn == "[]\n") return;
          var s1Return = JsonConvert.DeserializeObject<List<Object_SentinelOne_Alert_Class.SentinelOne>>(stringreturn);
          if (s1Return != null)
          {
            ParseSentinelOneAlert(s1Return);
          }
          Console.WriteLine(@"Finished retrieving SentinelOne alerts.");
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in SentinelOne alert area:" + e);
        }
      });

    }

    private static void ParseSentinelOneAlert(List<Object_SentinelOne_Alert_Class.SentinelOne> s1Return)
    {
      //Parallel.ForEach(s1Return, pevent =>
      //{
        foreach (var pevent in s1Return)
        {
          if (pevent.hidden) continue;

          try
          {
            //initialize generic variables for CB values
            var lFidoReturnValues = new FidoReturnValues
            {
              PreviousAlerts = new EventAlerts(),
              SentinelOne = new SentinelOneReturnValues {Alert = pevent},
              CurrentDetector = "sentinelone"
            };
            if (lFidoReturnValues.MalwareType == null)
            {
              lFidoReturnValues.MalwareType = pevent.description;
            }

            lFidoReturnValues.AlertID = pevent.id;
            lFidoReturnValues.TimeOccured = Convert.ToDateTime(pevent.created_date).ToUniversalTime().ToString("s");
            lFidoReturnValues.Hash = new List<string> { pevent.file_id.content_hash };

            if (lFidoReturnValues.Inventory == null)
            {
              lFidoReturnValues.Inventory = new Inventory {SentinelOne = new Object_SentinelOne_Inventory_Class.SentinelOne()};
            }

            var invReturn = new SysMgmt_SentinelOne();
            lFidoReturnValues.Inventory.SentinelOne = invReturn.GetSentinelOneHost(pevent.agent);
            if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.SentinelOne.software_information.os_name))
            {
              lFidoReturnValues.Inventory.PrimInv = "sentinelone";
              lFidoReturnValues.Inventory.SentRunning = "True";
              lFidoReturnValues.Inventory.SentVersion = lFidoReturnValues.Inventory.SentinelOne.agent_version;
              lFidoReturnValues.Inventory.OSName = lFidoReturnValues.Inventory.SentinelOne.software_information.os_name + @" " +lFidoReturnValues.Inventory.SentinelOne.software_information.os_revision;
              lFidoReturnValues.Inventory.Domain = lFidoReturnValues.Inventory.SentinelOne.network_information.domain;
              lFidoReturnValues.Inventory.LastUpdated = lFidoReturnValues.Inventory.SentinelOne.last_active_date;
              lFidoReturnValues.Inventory.Hostname = lFidoReturnValues.Inventory.SentinelOne.network_information.computer_name;
              lFidoReturnValues.Hostname = lFidoReturnValues.Inventory.SentinelOne.network_information.computer_name;
            }

            foreach (var interFace in lFidoReturnValues.Inventory.SentinelOne.network_information.interfaces)
            {
              if (interFace.inet.Count > 0)
              {
                if (interFace.inet != null)
                {
                  if (interFace.inet.Count > 0)
                  {
                    var sIP = interFace.inet[0].ToString();
                    if (sIP.StartsWith("10.") | sIP.StartsWith("192.168.") | sIP.StartsWith("100.") | sIP.StartsWith("172."))
                    {
                      lFidoReturnValues.SrcIP = sIP;
                    }
                  }
                }
              }
            }

            lFidoReturnValues.DstIP = new List<string>();

            if (!PreviousAlerts.GetCouchPreviousHostAlert(lFidoReturnValues.Hash, lFidoReturnValues.Hostname, lFidoReturnValues.SrcIP, lFidoReturnValues.TimeOccured, lFidoReturnValues.DNSName)) continue;

            //Check to see if ID has been processed before
            var isRunDirector = false;
            //lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
            var retAlerts = new Object_CouchDB_AlertID.AlertID();
            retAlerts = PreviousAlerts.GetPreviousAlerts(lFidoReturnValues.AlertID);

            if (retAlerts != null)
            {
              lFidoReturnValues.OldAlerts = retAlerts.rows;
            }

            if (lFidoReturnValues.OldAlerts != null && lFidoReturnValues.OldAlerts.Count > 0)
            {
              isRunDirector = PreviousAlerts.PreviousAlert(lFidoReturnValues, lFidoReturnValues.AlertID, lFidoReturnValues.TimeOccured);
            }

            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR"))
            {
              Console.WriteLine(@"Alert " + lFidoReturnValues.AlertID + @" has already been processed.");
              continue;
            }

            var writeCouch = new Fido_CouchDB();
            var uuid = writeCouch.WriteToDBFactory(lFidoReturnValues);
            var postmsg = new PostRabbit();
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
          }
          catch (Exception e)
          {
            Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in SentinelOne v1 Detector when formatting json:" + e);
          }
        }
      //});
    }

    private static void GetToken(string url)
    {
      var stoken = new RootObject();
      var client = new HttpClient { BaseAddress = new Uri(url) };
      var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent("{\"username\": \"" + Base64.Decode("cmZyeQ==") + "\",\"password\": \"" + Base64.Decode("Q3J1cDI0OTdqZmpmeXR5dCE=") + "\"}", Encoding.UTF8, "application/json") };

      try
      {
        var result = client.SendAsync(request);
        if (result.Result.StatusCode == HttpStatusCode.OK)
        {
          stoken = JsonConvert.DeserializeObject<RootObject>(result.Result.Content.ReadAsStringAsync().Result);
          UpdateToken(stoken.token);
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in SentinelOne request token area:" + e);
      }

      client.Dispose();
      request.Dispose();
    }

    private static void UpdateToken(string stoken)
    {
      var docid = GetDocID();
      var client = new HttpClient();
      var updatedetector = new HttpRequestMessage(HttpMethod.Post, API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_detectors.detectors.update + docid)
      {
        Content =
          new StringContent("{\"/sensor/token\" : \"" + Base64.Encode(stoken) + "\"}",
            Encoding.UTF8,
            "application/json")
      };
      //todo: move docid to db
      var updatesysmgmt = new HttpRequestMessage(HttpMethod.Post, API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_detectors.detectors.update + @"/partialUpdate/482ddabb2a39e7ec5b4386053a7ffc1e")
      {
        Content =
          new StringContent("{\"/configs/token\" : \"" + Base64.Encode(stoken) + "\"}",
            Encoding.UTF8,
            "application/json")
      };

      var updatedetect = client.SendAsync(updatedetector).Result;
      if (updatedetect.IsSuccessStatusCode)
      {
        Console.WriteLine(@"Updated SentinelOne detector token.");
      }

      var updatesys = client.SendAsync(updatesysmgmt).Result;
      if (updatesys.IsSuccessStatusCode)
      {
        Console.WriteLine(@"Updated SentinelOne sysmgmt token.");
      }

    }

    public static string GetDocID()
    {
      var request = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_detectors.detectors.docid + "?key=\"sentinelone\"";
        
        //@"http://127.0.0.1:5984/fido_configs_detectors/_design/detectors/_view/docid?key=" + '"' + "sentinelone" + '"';
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      var docid = string.Empty;
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        if (string.IsNullOrEmpty(stringreturn)) return docid;
        var ret = JsonConvert.DeserializeObject<Token>(stringreturn);
        docid = ret.rows[0].value;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in SentinelOne request token area:" + e);
      }

      return docid;
    }

    public class RootObject
    {
      public string token { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public string value { get; set; }
    }

    public class Token
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }

  }
}
