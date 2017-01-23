// /*
// *
// *  Copyright 2016  Netflix, Inc.
// *
// *     Licensed under the Apache License, Version 2.0 (the "License");
// *     you may not use this file except in compliance with the License.
// *     You may obtain a copy of the License at
// *
// *         http://www.apache.org/licenses/LICENSE-2.0
// *
// *     Unless required by applicable law or agreed to in writing, software
// *     distributed under the License is distributed on an "AS IS" BASIS,
// *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// *     See the License for the specific language governing permissions and
// *     limitations under the License.
// *
// */

using System;
using System.Collections.Generic;
using System.Net;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Objects.CouchDB;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.PreviousAlerts
{
  public class PreviousAlerts
  {
    public static bool PreviousAlert(FidoReturnValues lFidoReturnValues, string event_id, string event_time)
    {
      var isRunDirector = false;
      for (var j = 0; j < lFidoReturnValues.OldAlerts.Count; j++)
      {
        if (lFidoReturnValues.OldAlerts[j].key != event_id) continue;
        if (Convert.ToDateTime(event_time) == Convert.ToDateTime(lFidoReturnValues.OldAlerts[j].value.TimeOccurred))
        {
          isRunDirector = true;
          return isRunDirector;
        }
      }
      return isRunDirector;
    }

    public static DateTime FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddMilliseconds(Convert.ToDouble(unixTime));
    }

    public static long ToEpochTime(DateTime date)
    {
      var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
      return Convert.ToInt64((date - epoch).TotalSeconds);
    }

    public static Object_CouchDB_AlertID.AlertID GetPreviousAlerts(string AlertID)
    {
      var test = new Fido_Rest_Connection();
      var request = @"http://127.0.0.1:5984/fido_events_alerts/_design/alerts/_view/alertid?key=" + '"' + AlertID + '"';
      var connection = (HttpWebRequest)WebRequest.Create(request);
      var stringreturn = test.RestCall(connection, false);
      if (string.IsNullOrEmpty(stringreturn)) return null;
      //stringreturn = stringreturn.Replace("rows", "Alert").Replace("value", "Entry");
      var alertreturn = JsonConvert.DeserializeObject<Object_CouchDB_AlertID.AlertID>(stringreturn);
      return alertreturn;
    }

    public static bool GetCouchPreviousHostAlert(List<string> Hash, string HostName, string SrcIP, string Date, string Domain)
    {
      var isHost = true;
      var isHash = true;
      var isDomain = true;
      var isTimeShort = false;
      var isTimeLong = false;
      var runAlert = true;
      var request = new Fido_Rest_Connection();
      string query;
      if (HostName != null)
      {
        query = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_events_alerts.alerts.hostname + "?key=\"" + HostName + "\"";
      }
      else
      {
        query = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_events_alerts.alerts.srcip + "?key=\"" + SrcIP + "\"";
      }

      var connection = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = request.RestCall(connection, false);
      if (string.IsNullOrEmpty(stringreturn)) return true;
      //stringreturn = stringreturn.Replace("rows", "Alert").Replace("value", "Entry");
      var alertreturn = JsonConvert.DeserializeObject<Object_CouchDB_Previous.Name>(stringreturn);
      if (alertreturn.rows.Count == 0) return true;
      if (alertreturn.rows.Count > 4)
      {
        Console.WriteLine("Host exceeded 5 alerts");
        isHost = false;
      }

      foreach (var alertEntry in alertreturn.rows)
      {
        if (Hash != null)
        {
          foreach (var hashEntry in Hash)
          {
            if (alertEntry.value.Hash != null)
            {
              foreach (var oldhashEntry in alertEntry.value.Hash)
              {
                if (hashEntry == oldhashEntry)
                {
                  isHash = false;
                }

              }
            }
          }
        }

        if (Domain != null)
        {
          foreach (var domainentry in Domain)
          {
            if (alertEntry.value.Domain != null)
            {
              foreach (var olddomainentry in alertEntry.value.Domain)
              {
                if (domainentry == olddomainentry)
                {
                  isDomain = false;
                }

              }
            }
          }
        }

      if (Convert.ToDateTime(alertEntry.value.TimeOccurred) - Convert.ToDateTime(Date) > TimeSpan.FromHours(4) && alertreturn.rows.Count < 6)
        {
          isTimeShort = true;

          if (Convert.ToDateTime(alertEntry.value.TimeOccurred) - Convert.ToDateTime(Date) > TimeSpan.FromHours(12) && alertreturn.rows.Count < 10)
          {
            isTimeLong = true;
          }
        }
      }

      if (isHost) return runAlert;
      else
      {
        if (!isHash) return false;
        if (!isDomain) return false;
        if (!isTimeShort)
        {
          Console.WriteLine(@"Alert threshold has been exceeded, hash has already been processed, or time thresh hold was not exceeded.");
          runAlert = false;
          if (!isTimeLong)
          {
            runAlert = false;
          }
        }

      }

      return runAlert;
    }

    public static bool GetCouchPreviousIPAlert(List<string> Hash, string SrcIP, string Date, string Domain)
    {
      var isHost = true;
      var isHash = true;
      var isDomain = true;
      var isTimeShort = false;
      var isTimeLong = false;
      var runAlert = true;
      var test = new Fido_Rest_Connection();
      var request = @"http://127.0.0.1:5984/fido_events_alerts/_design/alerts/_view/srcip?key=" + '"' + SrcIP + '"';
      var connection = (HttpWebRequest)WebRequest.Create(request);

      try
      {
        var stringreturn = test.RestCall(connection, false);
        if (string.IsNullOrEmpty(stringreturn)) return true;
        //stringreturn = stringreturn.Replace("rows", "Alert").Replace("value", "Entry");
        var alertreturn = JsonConvert.DeserializeObject<Object_CouchDB_Previous.Name>(stringreturn);
        if (alertreturn.rows.Count == 0) return true;
        if (alertreturn.rows.Count > 4)
        {
          Console.WriteLine("IP exceeded 5 alerts");
          isHost = false;
        }

        foreach (var alertEntry in alertreturn.rows)
        {
          if (Hash != null)
          {
            foreach (var hashEntry in Hash)
            {
              if (alertEntry.value.Hash != null)
              {
                foreach (var oldhashEntry in alertEntry.value.Hash)
                {
                  if (hashEntry == oldhashEntry)
                  {
                    isHash = false;
                  }

                }
              }
            }
          }
          if (Domain != null & alertEntry.value.Domain != null)
          {
            if (Domain == alertEntry.value.Domain)
            {
              isDomain = false;
            }
          }
        }

        if (isHost) return runAlert;
        else
        {
          if (!isHash) return false;
          if (!isDomain) return false;
          if (!isTimeShort)
          {
            Console.WriteLine(@"Alert threshold has been exceeded, hash has already been processed, or time thresh hold was not exceeded.");
            runAlert = false;
            if (!isTimeLong)
            {
              runAlert = false;
            }
          }

        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in PreviousAlert for IPs area:" + e);
      }



      return runAlert;

    }
  }
}