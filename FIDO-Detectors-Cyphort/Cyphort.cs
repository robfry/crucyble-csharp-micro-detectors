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
using System.Net;
using System.Threading.Tasks;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.Cyphort;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.Cyphort
{
  public static class GetCyphort
  {
    //This function will grab the API information and build a query string.
    //Then it will assign the json return to an object. If any of the objects
    //have a value they will be sent to ParseCyphort helper function.
    public static void GetCyphortAlerts()
    {
      Console.WriteLine(@"Running Cyphort v3 detector.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs("cyphort");

      Parallel.ForEach(parseConfigs, conf =>
      {
        var request = conf.server + conf.query[0] + Base64.Decode(conf.token);
        var alertRequest = (HttpWebRequest) WebRequest.Create(request);
        alertRequest.Method = "GET";

        try
        {
          var getREST = new Fido_Rest_Connection();
          var stringreturn = getREST.RestCall(alertRequest, false);
          var cyphortReturn = JsonConvert.DeserializeObject<Object_Cyphort_Class.CyphortEvent>(stringreturn);
          if (cyphortReturn.Event_Array.Any())
          {
            ParseCyphort(cyphortReturn);
          }
          Console.WriteLine(@"Finished processing Cyphort detector.");
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error",
            "Fido Failed: {0} Exception caught in Cyphort Detector getting json:" + e);
        }
      });
    }

    //This function is designed get the incidents from an event, then determine if the 
    //incidents have already been processed. If they have not, they will be handed off
    //to the GetCyphortIncident function to gather necessary information before being
    //sent to TheDirector.
    private static void ParseCyphort(Object_Cyphort_Class.CyphortEvent cyphortReturn)
    {
      var x = 0;
      try
      {
        if (cyphortReturn.Event_Array.Any())
        {
          
          cyphortReturn.Event_Array = cyphortReturn.Event_Array.Reverse().ToArray();
          Parallel.For(0, cyphortReturn.Event_Array.Count(), i =>
          {
            x = i;
            Console.WriteLine(@"Processing Cyphort event " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.Event_Array.Count().ToString(CultureInfo.InvariantCulture) + @".");
            
            //We don't currently process IPv6, so if detected exit and process next alert
            if ((cyphortReturn.Event_Array[i].Endpoint_ip != null) && (cyphortReturn.Event_Array[i].Endpoint_ip.Contains(":"))) return;

            //initialize generic variables for Cyphort values
            var lFidoReturnValues = new FidoReturnValues
            {
              CurrentDetector = "cyphort",
              AlertID = cyphortReturn.Event_Array[i].Event_id,
              SrcIP = cyphortReturn.Event_Array[i].Endpoint_ip,
              TimeOccured = Convert.ToDateTime(cyphortReturn.Event_Array[i].Last_activity_time).ToString("s"),
              DstIP = new List<string>() {cyphortReturn.Event_Array[i].Source_ip}
            };
            if (!string.IsNullOrEmpty(cyphortReturn.Event_Array[i].Source_name)) lFidoReturnValues.DNSName = cyphortReturn.Event_Array[i].Source_name.Replace(".", "(.)");
            lFidoReturnValues.PreviousAlerts = new EventAlerts();
            lFidoReturnValues.Cyphort = new CyphortReturnValues
            {
              IncidentID = cyphortReturn.Event_Array[i].Incident_id,
              EventTime = Convert.ToDateTime(cyphortReturn.Event_Array[i].Last_activity_time).ToString("s"),
              DstIP = cyphortReturn.Event_Array[i].Source_ip
            };

            //Convert Cyphort classifications to more readable values
            switch (cyphortReturn.Event_Array[i].Event_type)
            {
              case "http":
                lFidoReturnValues.MalwareType = "Malware downloaded: " + cyphortReturn.Event_Array[i].Event_name + " Type: " + cyphortReturn.Event_Array[i].Event_category;
                break;
              case "cnc":
                lFidoReturnValues.MalwareType = "CNC Detected: " + cyphortReturn.Event_Array[i].Event_name;
                break;
              case "exploit":
                lFidoReturnValues.MalwareType = "Exploit Detected: " + cyphortReturn.Event_Array[i].Event_name;
                break;
            }

            if (!PreviousAlerts.GetCouchPreviousHostAlert(lFidoReturnValues.Hash, lFidoReturnValues.Hostname, lFidoReturnValues.SrcIP, lFidoReturnValues.TimeOccured, lFidoReturnValues.DNSName))
            {
              return;
            }

            var retAlerts = PreviousAlerts.GetPreviousAlerts(lFidoReturnValues.AlertID);

            if (retAlerts != null)
            {
              lFidoReturnValues.OldAlerts = retAlerts.rows;
            }

            //Check to see if ID has been processed before
            var isRunDirector = false;
            if (lFidoReturnValues.OldAlerts != null && lFidoReturnValues.OldAlerts.Count > 0)
            {
              isRunDirector = PreviousAlerts.PreviousAlert(lFidoReturnValues, lFidoReturnValues.AlertID, lFidoReturnValues.TimeOccured);
            }

            if (isRunDirector || lFidoReturnValues.MalwareType.Contains("EICAR"))
            {
              Console.WriteLine(@"Alert " + lFidoReturnValues.AlertID + @" has already been processed.");
              return;
            }
            //todo: build better file type versus targeted OS, then remove this.
            lFidoReturnValues.IsTargetOS = true;

            //Send information gathered thus far to function to gather incident details
            //and further parsing to determine if sending to TheDirector is needed.
            var getCyphort = new CyphortIncident();
            getCyphort.GetCyphortIncident(lFidoReturnValues);
            Console.WriteLine(@"Finished processing Cyphort event " + (i + 1).ToString(CultureInfo.InvariantCulture) + @" of " + cyphortReturn.Event_Array.Count().ToString(CultureInfo.InvariantCulture) + @".");
          });
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in cyphort Detector parse:" + e + " " + x.ToString());
      }
    }
  }
}
