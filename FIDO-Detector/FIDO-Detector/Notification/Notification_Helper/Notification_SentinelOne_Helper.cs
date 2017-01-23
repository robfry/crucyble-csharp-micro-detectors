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
using System.Globalization;
using System.Linq;
using System.Net;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Notification.Notification_Helper
{
  public class Notification_SentinelOne_Helper
  {
    public static Dictionary<string, string> SentinelOneBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.SentinelOne.VirusTotal != null)
      {
        if (lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn.Count(); i++)
          {
            if (lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadHashs += 1;
              lBadMD5Hashes.Add(lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn[i].Permalink);
            }
            else
            {
              lGoodMD5Hashes.Add(lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn[i].Permalink);
            }
          }
        }

        if (lFidoReturnValues.SentinelOne.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.SentinelOne.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.SentinelOne.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.SentinelOne.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.SentinelOne.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.SentinelOne.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }

      replacements = SentinelOneBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> SentinelOneBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      try
      {
        var getREST = new Fido_Rest_Connection();
        const string request = "http://127.0.0.1:5984/fido_configs/_design/app_configs/_view/integrations";
        var newRequest = (HttpWebRequest)WebRequest.Create(request);
        newRequest.Method = "GET"; ;
        var stringreturn = getREST.RestCall(newRequest, false);
        var integrationConfigs = new Object_Fido_Configs_CouchDB_Integrations.RootObject();
        if (!string.IsNullOrEmpty(stringreturn))
        {
          integrationConfigs = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_Integrations.RootObject>(stringreturn);
        }

        if (integrationConfigs.rows[0].value.threatstack.virustotal) replacements = SentinelOneVTReplacements(lFidoReturnValues, replacements);
          //if (new SqLiteDB().ExecuteBool(@"select virustotal from configs_director")) replacements = SentinelOneVTReplacements(lFidoReturnValues, replacements);

        if (integrationConfigs.rows[0].value.threatstack.threatgrid) replacements = SentinelOneGeoReplacements(lFidoReturnValues, replacements);
          //if (new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) replacements = SentinelOneVTReplacements(lFidoReturnValues, replacements);

        if (integrationConfigs.rows[0].value.threatstack.threatgrid) replacements = SentinelOneThreatGRIDReplacements(lFidoReturnValues, replacements);
          //if (new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) replacements = SentinelOneThreatGRIDReplacements(lFidoReturnValues, replacements);

        return replacements;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black Notification Helper:" + e);
      }
      return replacements;
    }

    private static Dictionary<string, string> SentinelOneGeoReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.SentinelOne.Alert != null)
      {
        replacements.Add("%asninfo%", "Location and ASN unknown");
        replacements.Add("%city%", string.Empty);
        replacements.Add("%country%", string.Empty);
        replacements.Add("%region%", string.Empty);
        return replacements;
      }
      return replacements;
    }

    private static Dictionary<string, string> SentinelOneVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.SentinelOne.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.SentinelOne.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.SentinelOne.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> SentinelOneThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.SentinelOne.ThreatGRID != null && lFidoReturnValues.SentinelOne.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.SentinelOne.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.SentinelOne.ThreatGRID != null && lFidoReturnValues.SentinelOne.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.SentinelOne.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.SentinelOne.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.SentinelOne.ThreatGRID != null && lFidoReturnValues.SentinelOne.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.SentinelOne.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.SentinelOne.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.SentinelOne.ThreatGRID != null && lFidoReturnValues.SentinelOne.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.SentinelOne.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.SentinelOne.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.SentinelOne.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridindicators%", "0");
      }

      return replacements;
    } 
  }
}