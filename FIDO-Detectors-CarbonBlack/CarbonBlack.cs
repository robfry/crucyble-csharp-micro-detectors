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
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Text;
using FIDO_Detector.Director.SysMgmt;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.Carbon_Black;
using FIDO_Detector.Fido_Support.Objects.CouchDB;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.CarbonBlack
{
  static class DetectCarbonBlack
  {
    public static void GetCarbonBlackAlert(string parameter, bool isParameter)
    {
      Console.WriteLine(@"Gathering alert data from Carbon Black.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

      var parseConfigs =  Object_Fido_Configs.ParseCouchDetectorConfigs("carbonblack");
      foreach (var conf in parseConfigs)
      //Parallel.ForEach(parseConfigs, conf =>
      {
        var request = conf.server + conf.query[0];
        if (isParameter)
        {
          request = parameter;
        }
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Method = "GET";
        alertRequest.Headers[@"X-Auth-Token"] = Base64.Decode(conf.token);

        try
        {
          var getREST = new Fido_Rest_Connection();
          var stringreturn = getREST.RestCall(alertRequest, false);
          if (stringreturn == "[]" || string.IsNullOrEmpty(stringreturn)) return;
          var cbReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Alert_Class.CarbonBlack>(stringreturn);
          if (cbReturn != null && cbReturn.Total_Results > 0)
          {
            FidoReturnValues lFidoReturnValues;
            if (cbReturn.Total_Results >= 25)
            {
              if (cbReturn.Start > cbReturn.Total_Results) return;
              Console.WriteLine(@"Currently parsing items " + cbReturn.Start + @" to " + (cbReturn.Start + 25) + @" out of " + cbReturn.Total_Results + @" total Carbon Black alerts.");
              lFidoReturnValues = ParseCarbonBlackAlert(cbReturn, conf);
              CloseCarbonBlackAlert(lFidoReturnValues, conf);
              GetCarbonBlackAlert("https://" + alertRequest.RequestUri.Host + "/api/v1/alert?q=&cb.fq.status=Unresolved&sort=alert_severity desc&rows=25&start=" + (cbReturn.Start + 25), true);
            }
            Console.WriteLine(@"Currently parsing items " + cbReturn.Start + @" to " + (cbReturn.Start + 25) + @" out of " + cbReturn.Total_Results + @" total Carbon Black alerts.");
            lFidoReturnValues = ParseCarbonBlackAlert(cbReturn, conf);
            CloseCarbonBlackAlert(lFidoReturnValues, conf);
          }
          Console.WriteLine(@"Finished retrieving CB alerts.");
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black alert area:" + e);
        }
      }//);
    }

    private static FidoReturnValues ParseCarbonBlackAlert(Object_CarbonBlack_Alert_Class.CarbonBlack cbReturn, Object_Fido_Configs_CouchDB_Detectors.Sensor conf)
    {
      var lFidoReturnValues = new FidoReturnValues();
      var writeCouch = new Fido_CouchDB();
      //Parallel.ForEach(cbReturn.Results, pevent =>
      //{
      foreach (var pevent in cbReturn.Results)
      {

        Console.WriteLine(@"Formatting CarbonBlack event for: " + pevent.Hostname + @".");
        try
        {
          //initialize generic variables for CB values
          lFidoReturnValues.PreviousAlerts = new EventAlerts();
          lFidoReturnValues.CB = new CarbonBlackReturnValues {Alert = new CarbonBlackAlert()};

          lFidoReturnValues.CurrentDetector = "carbonblack";
          lFidoReturnValues.CB.Alert.WatchListName = pevent.WatchlistName;
          lFidoReturnValues.CB.Alert.AlertType = pevent.AlertType;
          if (lFidoReturnValues.CB.Alert.WatchListName.Contains("binary") || lFidoReturnValues.CB.Alert.AlertType.Contains("binary"))
          {
            lFidoReturnValues.isBinary = true;
          }

          if (lFidoReturnValues.MalwareType == null && lFidoReturnValues.isBinary)
          {
            lFidoReturnValues.MalwareType = "Malicious file detected.";
          }
          else
          {
            lFidoReturnValues.MalwareType = "Malicious file executed.";
          }

          lFidoReturnValues.CB.Alert.EventID = pevent.UniqueID;
          lFidoReturnValues.AlertID = pevent.UniqueID;
          lFidoReturnValues.CB.Alert.EventTime = Convert.ToDateTime(pevent.CreatedTime).ToUniversalTime().ToString(CultureInfo.InvariantCulture);
          lFidoReturnValues.TimeOccured = Convert.ToDateTime(pevent.CreatedTime).ToUniversalTime().ToString("s");
          //lFidoReturnValues.Hostname = pevent.Hostname;

          lFidoReturnValues.Username = pevent.Username;
          lFidoReturnValues.Hash = new List<string> {pevent.MD5};
          lFidoReturnValues.CB.Alert.MD5Hash = pevent.MD5;
          if (lFidoReturnValues.Inventory == null)
          {
            lFidoReturnValues.Inventory = new Inventory();
            if (lFidoReturnValues.Inventory.CarbonBlack == null)
            {
              lFidoReturnValues.Inventory.CarbonBlack = new Object_CarbonBlack_Inventory_Class.CarbonBlackEntry();
            }
          }
          lFidoReturnValues.Inventory.CarbonBlack = SysMgmt_CarbonBlack.GetCarbonBlackHost(pevent.SensorID.ToString());
          if (lFidoReturnValues.Inventory.CarbonBlack == null) lFidoReturnValues.Inventory.CarbonBlack = SysMgmt_CarbonBlack.GetCarbonBlackHost(pevent.Hostname, null, true);
          if (lFidoReturnValues.Inventory.CarbonBlack == null) goto SkipInventory;
          else
          {
            lFidoReturnValues.Hostname = lFidoReturnValues.Inventory.CarbonBlack.HostName.Split('.')[0];
          }
          if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.CarbonBlack.OSName))
          {
            lFidoReturnValues.Inventory.PrimInv = "carbonblack";
            lFidoReturnValues.Inventory.CBRunning = "True";
            lFidoReturnValues.Inventory.CBVersion = lFidoReturnValues.Inventory.CarbonBlack.ClientVersion;
            lFidoReturnValues.Inventory.OSName = lFidoReturnValues.Inventory.CarbonBlack.OSName.Replace("OSX", "OS X");
            lFidoReturnValues.Inventory.Domain = lFidoReturnValues.Inventory.CarbonBlack.HostDNSName;
            lFidoReturnValues.Inventory.LastUpdated = lFidoReturnValues.Inventory.CarbonBlack.LastCheckinTime.ToLongTimeString();
          }

          SkipInventory:
          if (string.IsNullOrEmpty(pevent.ProcessPath))
          {
            if (string.IsNullOrEmpty(pevent.ProcessPath)) lFidoReturnValues.CB.Alert.ProcessPath = pevent.ObservedFilename[0];
          }
          else
          {
            lFidoReturnValues.CB.Alert.ProcessPath = pevent.ProcessPath;
          }

          if ((pevent.ObservedHosts.HostCount != 0) && (pevent.ObservedHosts.HostCount != null))
          {
            lFidoReturnValues.CB.Alert.HostCount = pevent.ObservedHosts.HostCount.ToString(CultureInfo.InvariantCulture);
          }
          else
          {
            lFidoReturnValues.CB.Alert.HostCount = "0";
          }

          if ((pevent.NetconnCount != 0) && (pevent.NetconnCount != null))
          {
            lFidoReturnValues.CB.Alert.NetConn = pevent.NetconnCount.ToString(CultureInfo.InvariantCulture);
          }
          else
          {
            lFidoReturnValues.CB.Alert.NetConn = "0";
          }

          if (lFidoReturnValues.Inventory.CarbonBlack != null)
          {
            var sFilter = new[] {"|", ","};
            var sIP = lFidoReturnValues.Inventory.CarbonBlack.NetworkAdapters.Split(sFilter, StringSplitOptions.RemoveEmptyEntries);
            if (sIP.Any())
            {
              lFidoReturnValues.SrcIP = sIP[0];
            }
          }

          lFidoReturnValues.DstIP = new List<string>();

          if (!PreviousAlerts.GetCouchPreviousHostAlert(lFidoReturnValues.Hash, lFidoReturnValues.Hostname, lFidoReturnValues.SrcIP, lFidoReturnValues.TimeOccured, lFidoReturnValues.DNSName))
          {
            CloseCarbonBlackAlert(lFidoReturnValues, conf);
            continue;
          }
          

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
            CloseCarbonBlackAlert(lFidoReturnValues, conf);
            continue;
          }
          //todo: build better filetype versus targetted OS, then remove this.
          lFidoReturnValues.IsTargetOS = true;
          
          return lFidoReturnValues;
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black v1 Detector when formatting json:" + e);
        }
      }
      //});

      var uuid = writeCouch.WriteToDBFactory(lFidoReturnValues);
      var postmsg = new PostRabbit();
      postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
      CloseCarbonBlackAlert(lFidoReturnValues, conf);

      return lFidoReturnValues;

    }

    private static void CloseCarbonBlackAlert(FidoReturnValues lFidoReturnValues, Object_Fido_Configs_CouchDB_Detectors.Sensor conf)
    {
      Console.WriteLine(@"Closing CarbonBlack event for: " + lFidoReturnValues.Hostname + @".");
      var query = conf.server + conf.query[1] + lFidoReturnValues.AlertID;
      var client = new HttpClient { BaseAddress = new Uri(query) };
      client.DefaultRequestHeaders.Add("X-Auth-Token", Base64.Decode(conf.token));
      var request = new HttpRequestMessage(HttpMethod.Post, query) { Content = new StringContent("{\"unique_id\": \"" + lFidoReturnValues.AlertID + "\",\"status\": \"Resolved\"}", Encoding.UTF8, "application/json") };

      try
      {
        var result = client.SendAsync(request).Result;
        if (result.IsSuccessStatusCode)
        {
          Console.WriteLine(@"CarbonBlack event closed.");
        }
      }

      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black alert area:" + e);
      }
    }
  }
}
