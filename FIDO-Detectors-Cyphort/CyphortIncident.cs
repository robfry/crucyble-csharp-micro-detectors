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
using System.Threading.Tasks;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.Cyphort;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.Cyphort
{
  public class CyphortIncident
  {
    public void GetCyphortIncident(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Pulling Cyphort incident details.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs("cyphort");
      lFidoReturnValues.Domain = new List<string>();

      Parallel.ForEach(parseConfigs, config =>
      {
        var request = config.server + config.query[1] + Base64.Decode(config.token);
        request = request.Replace("%incidentid%", lFidoReturnValues.Cyphort.IncidentID);
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Method = "GET";

        try
        {
          var getREST = new Fido_Rest_Connection();
          var stringreturn = getREST.RestCall(alertRequest, false);
          if (string.IsNullOrEmpty(stringreturn)) return;
          var cyphortReturn = JsonConvert.DeserializeObject<Object_Cyphort_Class.CyphortIncident>(stringreturn);
          if (cyphortReturn.Incident == null) return;
          lFidoReturnValues.Cyphort.IncidentDetails = new Object_Cyphort_Class.CyphortIncident();
          lFidoReturnValues.Cyphort.IncidentDetails = cyphortReturn;

          if (!string.IsNullOrEmpty(lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_name))
          {
            lFidoReturnValues.DNSName = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_name.Replace(".", "(.)");
            lFidoReturnValues.Domain.Add(lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_name);
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_exploit == "1")
          {
            Fido_EventHandler.SendEmail("Fido Notification", "Fido found new values in json from Cyphort for exploits.");
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_download == "1")
          {
            lFidoReturnValues = FormatDownloadReturnValues(lFidoReturnValues);
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_execution == "1")
          {
            Fido_EventHandler.SendEmail("Fido Notification", "Fido found new values in json from Cyphort for execution.");
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_infection == "1")
          {
            lFidoReturnValues = FormatInfectionReturnValues(lFidoReturnValues);
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_data_theft == "1")
          {
            Fido_EventHandler.SendEmail("Fido Notification",
              "Fido found new values in json from Cyphort for data theft.");
          }

          if (lFidoReturnValues.Cyphort.IncidentDetails.Incident.Has_file_submission == "1")
          {
            Fido_EventHandler.SendEmail("Fido Notification",
              "Fido found new values in json from Cyphort for file submission.");
          }
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error",
            "Fido Failed: {0} Exception caught in cyphort Detector getting json:" + e);
        }
        var writeCouch = new Fido_CouchDB();
        var uuid = writeCouch.WriteToDBFactory(lFidoReturnValues);
        var postmsg = new PostRabbit();
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.dhcp.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
        postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.geoip.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);

      });
    }

    private FidoReturnValues FormatDownloadReturnValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues.Cyphort.DstIP = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_ip;
      lFidoReturnValues.Cyphort.URL = new List<string>();
      lFidoReturnValues.Cyphort.MD5Hash = new List<string>();
      lFidoReturnValues.Cyphort.Domain = new List<string>();

      try
      {
        Parallel.ForEach(lFidoReturnValues.Cyphort.IncidentDetails.Incident.DownloadArray, download =>
        {
          if (!string.IsNullOrEmpty(download.Event_id)) lFidoReturnValues.Cyphort.EventID = download.Event_id;
          //if (!string.IsNullOrEmpty(download.Event_id)) lFidoReturnValues.AlertID = download.Event_id;
          if (!string.IsNullOrEmpty(download.Source_url))
          {
            lFidoReturnValues.Cyphort.URL.Add(download.Source_url);
            lFidoReturnValues.Url = new List<string> {download.Source_url};
          }
          if (!string.IsNullOrEmpty(download.File_md5_string))
          {
            lFidoReturnValues.Cyphort.MD5Hash.Add(download.File_md5_string);
            lFidoReturnValues.Hash = new List<string> {download.File_md5_string};
          }
          if (download.Req_headers != null)
          {
            lFidoReturnValues.Cyphort.Domain.Add(download.Req_headers.Host);
            lFidoReturnValues.DNSName = download.Req_headers.Host.Replace(".", "(.)");
          }
        });
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in cyphort download return:" + e);
      }

      return lFidoReturnValues;
    }

    private FidoReturnValues FormatInfectionReturnValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues.Cyphort.DstIP = lFidoReturnValues.Cyphort.IncidentDetails.Incident.Source_ip;
      lFidoReturnValues.Cyphort.Domain = new List<string>();
      lFidoReturnValues.Cyphort.URL = new List<string>();
      lFidoReturnValues.Cyphort.MD5Hash = new List<string>();

      try
      {
        Parallel.ForEach(lFidoReturnValues.Cyphort.IncidentDetails.Incident.InfectionArray, infection =>
        {
          lFidoReturnValues.Cyphort.EventID = infection.Infection_id;
          //lFidoReturnValues.AlertID = infection.Infection_id;
          lFidoReturnValues.Cyphort.URL.Add(string.Empty);
          lFidoReturnValues.Cyphort.MD5Hash.Add(string.Empty);
          lFidoReturnValues.Cyphort.Domain.Add(infection.Cnc_servers);
          lFidoReturnValues.DNSName = infection.Cnc_servers.Replace(".", "(.)");
        });
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in cyphort infection return:" + e);
      }

      return lFidoReturnValues;
    }
  }
}
