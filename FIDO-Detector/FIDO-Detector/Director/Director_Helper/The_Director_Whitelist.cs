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
using System.Linq;
using System.Net;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.Niddel;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.Director_Helper
{
  class The_Director_Whitelist
  {
    public bool CheckFidoWhitelist(string sSrcIP, List<string> sDstIP, List<string> sHash, string sDomain, List<string> sUrl, string sMalwareType, string sHostname)
    {

        const string query = "http://127.0.0.1:5984/fido_events_whitelist/_design/whitelist/_view/entries";
        var request = (HttpWebRequest)WebRequest.Create(query);
        request.Method = @"GET";
        try
        {
          var getREST = new Fido_Rest_Connection();
          var stringreturn = getREST.RestCall(request, false);
          if (string.IsNullOrEmpty(stringreturn)) return false;
          var tempReturn = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_Whitelist.Whitelist>(stringreturn);

          foreach (var entry in tempReturn.rows[0].key)
          {
            if (entry == null) continue;
            switch (entry.type)
            {
              case 0:
                if (sHash != null && sHash.Any(hash => entry.artifact == hash))
                {
                  return true;
                }
                break;

              case 1:
                if (sSrcIP != null && (entry.artifact == sSrcIP | sDstIP.Any(dst => entry.artifact == dst)))
                {
                  return true;
                }
                break;
              
              case 2:
                if (sDomain != null && sDomain == entry.artifact)
                  return true;
                break;
              
              case 3:
                if (sUrl != null && sUrl.Any(url => entry.artifact == url))
                  return true;
                break;
               
              case 4:
                if (sHostname != null && sHostname == entry.artifact)
                  return true;
                break;

              case 5:
                if (sMalwareType != null && sMalwareType == entry.artifact)
                {
                  return true;
                }
                break;
            }
          }
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in getting whitelist json from CouchDB:" + e);
        }

      return false;

      //if (!sDstIP.Contains(null))
      //{
      //  var qDstIPReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sDstIP + "'");
      //  if (!string.IsNullOrEmpty(qDstIPReturn))
      //  {
      //    isFound = true;
      //  }
      //}

      //if (!string.IsNullOrEmpty(sSrcIP))
      //{
      //  var qDstIPReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sSrcIP + "'");
      //  if (!string.IsNullOrEmpty(qDstIPReturn))
      //  {
      //    isFound = true;
      //  }
      //}

      //if (sHash != null)
      //{
      //  foreach (var hash in sHash)
      //  {

      //    var qHashReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + hash + "'");
      //    if (!string.IsNullOrEmpty(qHashReturn))
      //    {
      //      isFound = true;
      //    }
      //  }
      //}

      //if (!string.IsNullOrEmpty(sDomain))
      //{
      //  var qDomainReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sDomain + "'");
      //  if (!string.IsNullOrEmpty(qDomainReturn))
      //  {
      //    isFound = true;
      //  }
      //}

      //if (sUrl != null)
      //{
      //  foreach (var url in sUrl)
      //  {
      //    var qUrlReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + url + "'");
      //    if (!string.IsNullOrEmpty(qUrlReturn))
      //    {
      //      isFound = true;
      //    }
      //  }
      //}

      //if (sMalwareType != null)
      //{
      //  var qMalReturn = sqlQuery.ExecuteScalar("Select * from event_whitelist where artifact = '" + sMalwareType + "'");
      //  if (!string.IsNullOrEmpty(qMalReturn))
      //  {
      //    isFound = true;
      //  }
      //}

      //return isFound;
    }
  }
}
