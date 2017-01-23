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
using System.Net;
using System.Net.Security;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using FIDO_Detector.Fido_Support.DNSLookup;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.CouchDB;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Objects.PaloAlto;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;
using Formatting = Newtonsoft.Json.Formatting;

namespace FIDO.Detectors.PAN
{
  static class PaloAlto
  {
    
    public static void GetPANJob()
    {
      Console.WriteLine(@"Running PAN v1 detector.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs("pan");
      Thread.Sleep(1000);
      var request = string.Empty;
      //foreach (var config in parseConfigs)
      Parallel.ForEach(parseConfigs, conf =>
      {
        request = conf.server + conf.query[0] + "&key=" + Base64.Decode(conf.token);
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Method = "GET";
        try
        {
          var getREST = new Fido_Rest_Connection();
          Thread.Sleep(1000);
          var stringreturn = getREST.RestCall(alertRequest, false);
          if (stringreturn.TrimStart().StartsWith("<"))
          {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(stringreturn);
            stringreturn = JsonConvert.SerializeXmlNode(doc, Formatting.None, true);
          }
          var panReturn = JsonConvert.DeserializeObject<Object_PaloAlto_Class.GetJob>(stringreturn);
          if (string.IsNullOrEmpty(panReturn.Result.Job)) return;
          RunPANJob(panReturn.Result.Job, conf);
          Console.WriteLine(@"Finished processing PAN v1 detector (" + conf.server + @").");
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error",
            "Fido Failed: {0} Exception caught in PAN v1 Detector getting json:" + e);
        }
      });
    }

    public static void RunPANJob(string jobID, Object_Fido_Configs_CouchDB_Detectors.Sensor parseConfigs)
    {
      Console.WriteLine(@"Running PAN job " + jobID + @" for " + parseConfigs.server + @".");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

      var request = parseConfigs.server + parseConfigs.query[1] + "&key=" + Base64.Decode(parseConfigs.token);
      request = request.Replace("%jobid%", jobID);
      //We need to let the PAN finish processing the request before trying to pull the report
      Thread.Sleep(40000);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      //alertRequest.Timeout = 180000;
      alertRequest.Method = "GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);

        if (stringreturn.TrimStart().StartsWith("<"))
        {
          XmlDocument doc = new XmlDocument();
          doc.LoadXml(stringreturn);
          stringreturn = JsonConvert.SerializeXmlNode(doc, Formatting.None, true);
        }
        var panReturn = JsonConvert.DeserializeObject<Object_PaloAlto_Class.PanReturn>(stringreturn);
        if ((panReturn == null) | (panReturn.Result.Log.Logs.Entry == null)) return;
        ParsePan(panReturn);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in PAN v1 Detector getting json:" + e);
      }
    }

    private static void ParsePan(Object_PaloAlto_Class.PanReturn panReturn)
    {
      try
      {
        var i = 0;
        foreach (var entry in panReturn.Result.Log.Logs.Entry)
          //Parallel.ForEach(panReturn.Result.Log.Logs.Entry, entry =>
        {
          i++;
          Console.WriteLine(@"Currently processing alert #" + i);
          Console.WriteLine(@"Processing PAN " + entry.subtype + @" event.");

          if (!entry.SrcIP.StartsWith("69.53.") & !entry.SrcIP.StartsWith("192.173.") &
              !entry.DstIP.StartsWith("69.53.") & !entry.DstIP.StartsWith("192.173."))
          {
            //initialize generic variables for PAN values
            var lFidoReturnValues = new FidoReturnValues();
            if (lFidoReturnValues.PaloAlto == null)
            {
              lFidoReturnValues.PaloAlto = new PaloAltoReturnValues();
            }

            //Convert PAN classifications to more readable values
            lFidoReturnValues.MalwareType = entry.threatid + @"(" + entry.subtype + @")";
            lFidoReturnValues.CurrentDetector = @"pan";
            lFidoReturnValues.PaloAlto.EventID = entry.EventID;
            lFidoReturnValues.AlertID = entry.EventID;
            lFidoReturnValues.TimeOccured = entry.ReceivedTime.ToString("s");
            lFidoReturnValues.Domain = new List<string>();
            var domainreturn = new List<string>();

            if (entry.app == "dns")
            {
              var listRegex = new List<string>();
              listRegex.Add(@"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})");
              listRegex.Add(@":\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})");
              listRegex.Add(@"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})");
              listRegex.Add(@":\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})");
              listRegex.Add(@"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})");
              foreach (var regexentry in listRegex)
              {
                var regex = new Regex(regexentry, RegexOptions.Singleline);
                var regexreturn = regex.Match(entry.threatid);
                if (regexreturn.Success)
                {
                  if (lFidoReturnValues.Domain.Count > 0) lFidoReturnValues.Domain.RemoveAt(0);
                  var newvalue = string.Empty;
                  newvalue = regexreturn.Value;
                  if (regexreturn.Value.Contains(":")) newvalue = regexreturn.Value.Replace(":", string.Empty);
                  lFidoReturnValues.Domain.Add(newvalue);
                  domainreturn = DNSLookup.DoGetHostEntry(newvalue);
                  if (domainreturn.Count > 0) entry.domain = domainreturn[0];
                  lFidoReturnValues.DNSName = newvalue.Replace(".", "(.)");
                }
              }
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
              isRunDirector = PreviousAlerts.PreviousAlert(lFidoReturnValues, lFidoReturnValues.AlertID,
                lFidoReturnValues.TimeOccured);
            }

            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR"))
            {
              Console.WriteLine(@"Alert " + lFidoReturnValues.AlertID + @" has already been processed.");
              continue;
            }

            if (entry.SrcIP.Contains(":") | (entry.DstIP.Contains(":")))
            {
              continue;
            }

            if (entry.SrcIP.StartsWith("10.") | entry.SrcIP.StartsWith("100.") | entry.SrcIP.StartsWith("192.168.") |
                entry.SrcIP.StartsWith("172."))
            {
              lFidoReturnValues.PaloAlto.isDst = true;
            }
            else if (entry.DstIP.StartsWith("10.") | entry.DstIP.StartsWith("100.") | entry.DstIP.StartsWith("192.168.") |
                     entry.DstIP.StartsWith("172."))
            {
              lFidoReturnValues.PaloAlto.isDst = false;
            }
            lFidoReturnValues.DstIP = new List<string>();
            if (lFidoReturnValues.PaloAlto.isDst)
            {
              lFidoReturnValues.SrcIP = entry.SrcIP;
              lFidoReturnValues.DstIP.Add(entry.DstIP);
              lFidoReturnValues.PaloAlto.DstIp = entry.DstIP;
            }
            else
            {
              lFidoReturnValues.SrcIP = entry.DstIP;
              lFidoReturnValues.DstIP.Add(entry.SrcIP);
              lFidoReturnValues.PaloAlto.DstIp = entry.SrcIP;
            }

            if (
              !PreviousAlerts.GetCouchPreviousIPAlert(lFidoReturnValues.Hash, lFidoReturnValues.SrcIP,
                lFidoReturnValues.TimeOccured, lFidoReturnValues.DNSName)) continue;

            if (!string.IsNullOrEmpty(entry.DstUser))
            {
              lFidoReturnValues.PaloAlto.DstUser = entry.DstUser.Replace(@"corp\", string.Empty);
              lFidoReturnValues.Username = entry.DstUser;
            }

            lFidoReturnValues.PaloAlto.EventTime = entry.ReceivedTime.ToString(CultureInfo.InvariantCulture);
            lFidoReturnValues.TimeOccured = entry.ReceivedTime.ToString("s");

            var writeCouch = new Fido_CouchDB();
            var uuid = writeCouch.WriteToDBFactory(lFidoReturnValues);
            var postmsg = new PostRabbit();
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.dhcp.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.geoip.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);

          }
          // });
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in pan Detector parse:" + e);
      }
    }

  }
}
