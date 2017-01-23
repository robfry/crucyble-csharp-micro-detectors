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

using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Notification.Notification_Helper
{
  static class Notfication_Niddel_Helper
  {

    public static Dictionary<string, string> NiddelBadGuyReturn(FidoReturnValues lFidoReturnValues, List<string> lBadMD5Hashes, List<string> lGoodMD5Hashes, List<string> lBadURLs, List<string> lGoodURLs, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Niddel.VirusTotal != null)
      {
        if (lFidoReturnValues.Niddel.VirusTotal.URLReturn != null)
        {
          for (var i = 0; i < lFidoReturnValues.Niddel.VirusTotal.URLReturn.Count(); i++)
          {
            if (lFidoReturnValues.Niddel.VirusTotal.URLReturn[i].Positives > 0)
            {
              lFidoReturnValues.BadUrLs += 1;
              lBadURLs.Add(lFidoReturnValues.Niddel.VirusTotal.URLReturn[i].Permalink);
            }
            else
            {
              lGoodURLs.Add(lFidoReturnValues.Niddel.VirusTotal.URLReturn[i].Permalink);
            }
          }
        }
        if (lFidoReturnValues.Niddel.VirusTotal.IPReturn != null)
        {
          if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedCommunicatingSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedCommunicatingSamples.Count();
              i++)
            {
              if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedCommunicatingSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedComms += 1;
              }
            }
          }
          if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedDownloadedSamples != null)
          {
            for (var i = 0;
              i < lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedDownloadedSamples.Count();
              i++)
            {
              if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedDownloadedSamples[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedDownloads += 1;
              }
            }
          }
          if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedUrls != null)
          {
            for (var i = 0; i < lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedUrls.Count(); i++)
            {
              if (lFidoReturnValues.Niddel.VirusTotal.IPReturn[0].DetectedUrls[i].Positives > 0)
              {
                lFidoReturnValues.BadDetectedUrls += 1;
              }
            }
          }
        }
      }

      replacements.Add("%alienrisk%", "Not Found");
      replacements.Add("%alienreliable%", "Not Found");
      replacements.Add("%alienactivity%", string.Empty);

      //Check Bit9 for values
      replacements.Add("%bit9threat%", "Not Configured");
      replacements.Add("%bit9trust%", "Not Configured");
      replacements = NiddelBadGuyReplacements(lFidoReturnValues, replacements);
      return replacements;
    }

    private static Dictionary<string, string> NiddelBadGuyReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      replacements = NiddelVTReplacements(lFidoReturnValues, replacements);

      replacements = Notification_Location_Helper.LocationReplacements(lFidoReturnValues, replacements);

      replacements = NiddelThreatGRIDReplacements(lFidoReturnValues, replacements);

      return replacements;
    }

    //private static Dictionary<string, string> NiddelGeoReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    //{
    //  if (lFidoReturnValues.Niddel.Niddel.Alerts. == null)
    //  {
    //    replacements.Add("%asninfo%", "Location and ASN unknown");
    //    replacements.Add("%city%", string.Empty);
    //    replacements.Add("%country%", string.Empty);
    //    replacements.Add("%region%", string.Empty);
    //    return replacements;
    //  }
    //  if (lFidoReturnValues.Niddel.GEO.Destination != null)
    //  {
    //    if (lFidoReturnValues.Niddel.GEO.Destination.City != null)
    //    {
    //      replacements.Add("%city%", lFidoReturnValues.Niddel.GEO.Destination.City.Name);
    //    }
    //    else
    //    {
    //      replacements.Add("%city%", string.Empty);
    //    }
    //    if (lFidoReturnValues.Niddel.GEO.Destination.Country != null)
    //    {
    //      replacements.Add("%country%", lFidoReturnValues.Niddel.GEO.Destination.Country.Name);
    //    }
    //    else
    //    {
    //      replacements.Add("%country%", string.Empty);
    //    }
    //    if (lFidoReturnValues.Niddel.GEO.Destination.Continent != null)
    //    {
    //      replacements.Add("%region%", lFidoReturnValues.Niddel.GEO.Destination.Continent.Name);
    //    }
    //    else
    //    {
    //      replacements.Add("%region%", string.Empty);
    //    }
    //    if (lFidoReturnValues.Niddel.GEO.Destination.Organization != null)
    //    {
    //      replacements.Add("%asninfo%", lFidoReturnValues.Niddel.GEO.Destination.Organization);
    //    }
    //    else
    //    {
    //      replacements.Add("%asninfo%", string.Empty);
    //    }
    //  }
    //  else if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo != null)
    //  {
    //    if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN == null)
    //    {
    //      replacements.Add("%asninfo%", "No ASN Found");
    //    }
    //    else
    //    {
    //      replacements.Add("%asninfo%", lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.ASN_Array.ASN + ":" + lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.ASN_Array.Org);
    //    }
    //    if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array != null)
    //    {
    //      if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.City != null)
    //      {
    //        replacements.Add("%city%", lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.City);
    //      }
    //      if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.Country != null)
    //      {
    //        replacements.Add("%country%", lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.Country);
    //      }
    //      if (lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.Region != null)
    //      {
    //        replacements.Add("%region%", lFidoReturnValues.Niddel.ThreatGRID.IPInfo.Data_Array.Location_Array.Region);
    //      }
    //    }
    //  }

    //  return replacements;
    //}

    private static Dictionary<string, string> NiddelVTReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Niddel.VirusTotal.VirusTotalScore > 0)
      {
        replacements.Add("%virustotalscore%", lFidoReturnValues.Niddel.VirusTotal.VirusTotalScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%virustotalscore%", "0");
      }
      if (lFidoReturnValues.BadDetectedComms > 0)
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedComms + " Detected!</a>");
      }
      else
      {
        replacements.Add("%cncip%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedDownloads > 0)
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedDownloads + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedip%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      if (lFidoReturnValues.BadDetectedUrls > 0)
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>" + lFidoReturnValues.BadDetectedUrls + " Detected!</a>");
      }
      else
      {
        replacements.Add("%totaldetectedurl%", "<a href='" + lFidoReturnValues.Niddel.VirusTotal.IPUrl + "'>None Detected</a>");
      }

      return replacements;
    }

    private static Dictionary<string, string> NiddelThreatGRIDReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Niddel.ThreatGRID != null && lFidoReturnValues.Niddel.ThreatGRID.ThreatScore > 0)
      {
        replacements.Add("%threatgridscore%", lFidoReturnValues.Niddel.ThreatGRID.ThreatScore.ToString(CultureInfo.InvariantCulture));
      }
      else
      {
        replacements.Add("%threatgridscore%", "0");
      }
      if (lFidoReturnValues.Niddel.ThreatGRID != null && lFidoReturnValues.Niddel.ThreatGRID.ThreatSeverity > 0)
      {
        if ((lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridseverity%", "<a href='%url_location%'>" + lFidoReturnValues.Niddel.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridseverity%", lFidoReturnValues.Niddel.ThreatGRID.ThreatSeverity.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridseverity%", "0");
      }
      if (lFidoReturnValues.Niddel.ThreatGRID != null && lFidoReturnValues.Niddel.ThreatGRID.ThreatConfidence > 0)
      {
        if ((lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridconfidence%", "<a href='%url_location%'>" + lFidoReturnValues.Niddel.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridconfidence%", lFidoReturnValues.Niddel.ThreatGRID.ThreatConfidence.ToString(CultureInfo.InvariantCulture));
        }
      }
      else
      {
        replacements.Add("%threatgridconfidence%", "0");
      }
      if (lFidoReturnValues.Niddel.ThreatGRID != null && lFidoReturnValues.Niddel.ThreatGRID.ThreatIndicators > 0)
      {
        if ((lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count > 0))
        {
          replacements.Add("%threatgridindicators%", "<a href='%url_location%'>" + lFidoReturnValues.Niddel.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture) + "</a>");
        }
        else
        {
          replacements.Add("%threatgridindicators%", lFidoReturnValues.Niddel.ThreatGRID.ThreatIndicators.ToString(CultureInfo.InvariantCulture));
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
