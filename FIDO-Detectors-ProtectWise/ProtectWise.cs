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
using System.Threading;
using System.Threading.Tasks;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.CouchDB;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Objects.Protectwise;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.ProtectWise
{
  public class DetectProtectWise
  {
    public static void GetProtectWiseEvents(bool Realtime)
    {
      Console.WriteLine(@"Running ProtectWise v1 detector.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs(Realtime ? "protectwise" : "protectwise-retro");

      //foreach (var config in parseConfigs)
      Parallel.ForEach(parseConfigs, config =>
      {
        var getTime = DateTime.Now.ToUniversalTime();
        var timer = config.timer;
        var timeRange = Convert.ToDouble(timer)*-1;
        var oldtime = getTime.AddMinutes(timeRange);
        var currentTime = PreviousAlerts.ToEpochTime(getTime).ToString(CultureInfo.InvariantCulture) + "000";
        var newoldtime = PreviousAlerts.ToEpochTime(oldtime).ToString(CultureInfo.InvariantCulture) + "000";

        var request = config.server +
                      config.query[0].Replace("%currenttime%", currentTime).Replace("%minustime%", newoldtime);
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Method = "GET";
        alertRequest.Headers[@"X-Access-Token"] = Base64.Decode(config.token);
        alertRequest.Method = "GET";

        try
        {
          var getREST = new Fido_Rest_Connection();
          Thread.Sleep(500);
          var stringreturn = getREST.RestCall(alertRequest, false);

          if (stringreturn == null) return;
          var protectwiseReturn = JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Events>(stringreturn);
          if (protectwiseReturn.Events != null)
          {
            ParseProtectWiseEvent(protectwiseReturn);
            if (protectwiseReturn.Count >= 26)
            {
              var hash = protectwiseReturn.NextPage;
              var loopRequest = request + "&nextPage=" + hash;
              hash = GetProtectWiseEventsLoop(loopRequest, config.token);
              while (!string.IsNullOrEmpty(hash))
              {
                loopRequest = request + "&nextPage=" + hash;
                hash = GetProtectWiseEventsLoop(loopRequest, config.token);
              }
            }
          }
          Console.WriteLine(@"Finished processing ProtectWise events detector.");
        }
        catch (WebException e)
        {
          Fido_EventHandler.SendEmail("Fido Error",
            "Fido Failed: {0} Web Exception caught in ProtectWise v1 Detector when getting json:" + e);
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error",
            "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e);
        }
      });
    }

    private static string GetProtectWiseEventsLoop(string request, string apikey)
    {
      Console.WriteLine(@"Looping through ProtectWise results.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var connection = (HttpWebRequest) WebRequest.Create(request);
      connection.Headers[@"X-Access-Token"] = apikey;
      connection.Method = "GET";
      var hash = string.Empty;
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(connection, false);
        if (stringreturn == null) return string.Empty;
        var protectwiseReturn =
          JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Events>(stringreturn);
        if (protectwiseReturn.Events != null)
        {
          hash = protectwiseReturn.NextPage;
          ParseProtectWiseEvent(protectwiseReturn);
        }
        Console.WriteLine(@"Finished processing ProtectWise events detector.");
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Web Exception caught in ProtectWise v1 Detector when getting json:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e);
      }
      return hash;
    }

    private static void ParseProtectWiseEvent(Object_ProtectWise_Threat_ConfigClass.ProtectWise_Events protectWiseReturn)
    {
      //protectWiseReturn.Events = protectWiseReturn.Events.Reverse().ToArray();
      Parallel.ForEach(protectWiseReturn.Events, pevent =>
      {
        Console.WriteLine(@"Gathering ProtectWise observations for event: " + pevent.Message + @".");
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

        var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs("protectwise");
        var request = string.Empty;
        var stringreturn = string.Empty;

        //foreach (var config in parseConfigs)
        Parallel.ForEach(parseConfigs, conf =>
        {
          try
          {
            request = conf.server + conf.query[1] + pevent.Id;
            var alertRequest = (HttpWebRequest) WebRequest.Create(request);
            alertRequest.Headers[@"X-Access-Token"] = Base64.Decode(conf.token);
            alertRequest.Method = "GET";
            var getREST = new Fido_Rest_Connection();
            Thread.Sleep(500);
            stringreturn = getREST.RestCall(alertRequest, false);

            if (string.IsNullOrEmpty(stringreturn)) return;
            var protectwiseReturn =
              JsonConvert.DeserializeObject<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Search_Event>(stringreturn);
            if (protectwiseReturn != null)
            {
              ParseProtectWiseObservation(protectwiseReturn, pevent.Message.Replace("'", ""));
            }
          }
          catch (WebException e)
          {
            Fido_EventHandler.SendEmail("Fido Error",
              "Fido Failed: {0} Web Exception caught in ProtectWise v1 Detector when getting json:" + e);
          }
          catch (Exception e)
          {
            Fido_EventHandler.SendEmail("Fido Error",
              "Fido Failed: {0} Exception caught in ProtectWise v1 Detector when getting json:" + e + " " + stringreturn +
              " " + request);
          }
        });
      });
    }

    private static void ParseProtectWiseObservation(
      Object_ProtectWise_Threat_ConfigClass.ProtectWise_Search_Event protectwiseEvent, string malwareType)
    {
      var lFidoReturnValues = new FidoReturnValues();
      lFidoReturnValues.AlertID = protectwiseEvent.Id;
      lFidoReturnValues.TimeOccured =
        PreviousAlerts.FromEpochTime(protectwiseEvent.Observations[0].EventTime).ToString("s");
      //initialize generic variables for ProtectWise values
      lFidoReturnValues.OldAlerts = new List<Object_CouchDB_AlertID.Row>();
      lFidoReturnValues.ProtectWise = new ProtectWiseReturnValues();
      lFidoReturnValues.ProtectWise.EventDetails = protectwiseEvent;
      lFidoReturnValues.CurrentDetector = "protectwise";
      lFidoReturnValues.ProtectWise.IncidentDetails =
        new List<Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation>();
      lFidoReturnValues.DstIP = new List<string>();
      lFidoReturnValues.ProtectWise.EventID = protectwiseEvent.Id;
      lFidoReturnValues.Url = new List<string>();
      lFidoReturnValues.Domain = new List<string>();
      lFidoReturnValues.ProtectWise.URL = new List<string>();
      lFidoReturnValues.Hash = new List<string>();

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
      var testvar = protectwiseEvent.Observations;
      try
      {
        foreach (var protectWiseObservation in protectwiseEvent.Observations)
        {
          if (protectWiseObservation.Flow == null) continue;
          if (protectWiseObservation.Flow.IP.SrcIP == null | protectWiseObservation.Flow.IP.DstIP == null) continue;
          if ((protectWiseObservation.Flow.IP.DstIP == "0.0.0.0") || (protectWiseObservation.Flow.IP.SrcIP == "0.0.0.0"))
            return;

          if (protectWiseObservation.Flow.IP.SrcIP.StartsWith("2607:fb10") ||
              protectWiseObservation.Flow.IP.DstIP.StartsWith("2607:fb10"))
          {
            Console.Write(@"Source/Destination IP is IPV6, exiting and sending email alert.");
            //Fido_EventHandler.SendEmail(@"Fido Alert", @"IPV6 address found, please login to console and manually check alert. Alert link: https://console.protectwise.com/#killbox/events?id=" + protectWiseObservation.EventID + @"&sid=" + protectWiseObservation.AgentID);

            //Need to write better handling of IPV6 writes to CouchDB.
            //var CloseAlert = new Fido_CouchDB();
            //lFidoReturnValues.AlertID = protectWiseObservation.EventID;
            //CloseAlert.WriteToDBFactory(lFidoReturnValues);
            return;
          }

          if (protectwiseEvent.ThreatSubCategory == "None")
            lFidoReturnValues.MalwareType = protectwiseEvent.Category + " : " + protectwiseEvent.KillChainStage;
          else
            lFidoReturnValues.MalwareType = protectwiseEvent.Category + " : " + protectwiseEvent.ThreatSubCategory +
                                            " (" + protectwiseEvent.KillChainStage + ")";

          string mware;
          if (protectWiseObservation.ThreatSubCategory == "None")
            mware = protectWiseObservation.Category + " : " + protectWiseObservation.KillChainStage;
          else
            mware = protectWiseObservation.Category + " : " + protectWiseObservation.ThreatSubCategory + " (" +
                    protectWiseObservation.KillChainStage + ")";
          if (lFidoReturnValues.MalwareType != mware)
            lFidoReturnValues.MalwareType = lFidoReturnValues.MalwareType + "\r\n" + protectWiseObservation.Category +
                                            " : " + protectWiseObservation.ThreatSubCategory + " (" +
                                            protectWiseObservation.KillChainStage + ")";

          if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR"))
          {
            Console.WriteLine(@"Alert already processed... proceeding to next alert.");
            return;
          }

          if (!string.IsNullOrEmpty(lFidoReturnValues.ProtectWise.EventDetails.Id))
          {
            lFidoReturnValues.ProtectWise.IncidentDetails.Add(protectWiseObservation);

            if (protectWiseObservation.Flow.IP.DstIP.StartsWith("10.") ||
                protectWiseObservation.Flow.IP.DstIP.StartsWith("100.") ||
                protectWiseObservation.Flow.IP.DstIP.StartsWith("192.168.") ||
                protectWiseObservation.Flow.IP.DstIP.StartsWith("2607:fb10"))
            {
              lFidoReturnValues.SrcIP = protectWiseObservation.Flow.IP.DstIP;
              lFidoReturnValues.ProtectWise.DstIP = protectWiseObservation.Flow.IP.SrcIP;
              if (!lFidoReturnValues.DstIP.Contains(protectWiseObservation.Flow.IP.SrcIP))
                lFidoReturnValues.DstIP.Add(protectWiseObservation.Flow.IP.SrcIP);
              if (!lFidoReturnValues.ProtectWise.URL.Contains(protectWiseObservation.Flow.IP.SrcIP))
                lFidoReturnValues.ProtectWise.URL.Add(protectWiseObservation.Flow.IP.SrcIP);
            }
            else
            {
              //Adding in handling of OpenDNS sinkhole addresses
              if (protectWiseObservation.Flow.IP.DstIP.Contains("208.67.220.220") ||
                  protectWiseObservation.Flow.IP.DstIP.Contains("208.67.222.222") ||
                  protectWiseObservation.Flow.IP.DstIP.Contains("146.112.61.104"))
              {
                if (lFidoReturnValues.DstIP.Count == 0)
                  lFidoReturnValues.DstIP.Add(protectWiseObservation.Flow.IP.DstIP);
              }
              else if (!lFidoReturnValues.DstIP.Contains(protectWiseObservation.Flow.IP.DstIP))
                lFidoReturnValues.DstIP.Add(protectWiseObservation.Flow.IP.DstIP);
              lFidoReturnValues.ProtectWise.DstIP = protectWiseObservation.Flow.IP.DstIP;
              lFidoReturnValues.SrcIP = protectWiseObservation.Flow.IP.SrcIP;
              if (!lFidoReturnValues.ProtectWise.URL.Contains(protectWiseObservation.Flow.IP.DstIP))
                lFidoReturnValues.ProtectWise.URL.Add(protectWiseObservation.Flow.IP.DstIP);
            }
          }

          //if (Convert.ToDateTime(lFidoReturnValues.TimeOccured) < DateTime.Now.AddDays(-1)) return;
          lFidoReturnValues.ProtectWise.EventTime =
            PreviousAlerts.FromEpochTime(protectWiseObservation.EventTime).ToString("s");

          if (protectWiseObservation.Data.Ip_Reputation != null)
          {
            lFidoReturnValues = FormatIPReturnValues(lFidoReturnValues, protectWiseObservation);
          }

          if (protectWiseObservation.Data.URL_Reputation != null)
          {
            lFidoReturnValues = FormatURLReturnValues(lFidoReturnValues, protectWiseObservation);
          }

          if (protectWiseObservation.Data.File_Reputation != null)
          {
            lFidoReturnValues = FormatFileReturnValues(lFidoReturnValues, protectWiseObservation);
          }

          if (protectWiseObservation.Data.DNS_Reputation != null)
          {
            lFidoReturnValues = FormatDNSReturnValues(lFidoReturnValues, protectWiseObservation);
          }

          if (protectWiseObservation.Data.IdsEvent != null)
          {
            lFidoReturnValues = FormatIdsReturnValues(lFidoReturnValues, protectWiseObservation);
          }
        }

        var writeCouch = new Fido_CouchDB();
        var uuid = writeCouch.WriteToDBFactory(lFidoReturnValues);
        var postmsg = new PostRabbit();
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.dhcp.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.geoip.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in ProtectWise v1 Detector parsing observations:" + e + @" " + testvar);
      }
    }

    private static FidoReturnValues FormatURLReturnValues(FidoReturnValues lFidoReturnValues, Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation protectWiseObservation)
    {
      try
      {
        var getDomain = protectWiseObservation.Data.URL_Reputation.Url.Split('/');
        lFidoReturnValues.DNSName = getDomain[0].Replace(".", "(.)");

        lFidoReturnValues.Url.Add(protectWiseObservation.Data.URL_Reputation.Url);
        lFidoReturnValues.ProtectWise.URL.Add(protectWiseObservation.Data.URL_Reputation.Url);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise URL processing:" + e);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatDNSReturnValues(FidoReturnValues lFidoReturnValues, Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation protectWiseObservation)
    {
      try
      {
        if (!lFidoReturnValues.Domain.Contains(protectWiseObservation.Data.DNS_Reputation.DNSDomain))
          lFidoReturnValues.Domain.Add(protectWiseObservation.Data.DNS_Reputation.DNSDomain);
        lFidoReturnValues.DNSName = protectWiseObservation.Data.DNS_Reputation.DNSDomain.Replace(".", "(.)");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise DNS processing:" + e);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatIPReturnValues(FidoReturnValues lFidoReturnValues, Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation protectWiseObservation)
    {
      try
      {
        if (!lFidoReturnValues.DstIP.Contains(protectWiseObservation.Data.Ip_Reputation.IP))
          lFidoReturnValues.DstIP.Add(protectWiseObservation.Data.Ip_Reputation.IP);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise IP processing:" + e);
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatIdsReturnValues(FidoReturnValues lFidoReturnValues, Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation protectWiseObservation)
    {
      try
      {
        if (lFidoReturnValues.MalwareType.Contains(protectWiseObservation.Data.IdsEvent.Description))
          return lFidoReturnValues;
        lFidoReturnValues.MalwareType = lFidoReturnValues.MalwareType + "\r\n" +
                                        protectWiseObservation.Data.IdsEvent.Description;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in ProtectWise IDS processing:" + e);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues FormatFileReturnValues(FidoReturnValues lFidoReturnValues, Object_ProtectWise_Threat_ConfigClass.ProtectWise_Observation protectWiseObservation)
    {
      try
      {
        if (!lFidoReturnValues.Hash.Contains(protectWiseObservation.Data.File_Reputation.Hashes.md5))
          lFidoReturnValues.Hash.Add(protectWiseObservation.Data.File_Reputation.Hashes.md5);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in ProtectWise file reputation processing:" + e);
        ;
      }

      return lFidoReturnValues;
    }
  }
}