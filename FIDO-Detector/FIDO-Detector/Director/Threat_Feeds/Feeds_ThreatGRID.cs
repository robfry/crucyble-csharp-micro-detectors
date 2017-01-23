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
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using Fido_Main.Director.Director_Helper;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Hashing;
using Fido_Main.Fido_Support.Objects.ThreatGRID;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.Threat_Feeds
{
  static class Feeds_ThreatGRID
  {
    public static Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search SearchInfo(string Artifact, The_Director_ThreatFeed_Enum type, Int16 iDays)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

      var stringreturn = string.Empty;
      var ThreatGRIDReturn = new Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search();
      ThreatGRIDReturn = null;

      var request = Request(Artifact, type, iDays);

      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Timeout = 60000;
      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(alertRequest, true);
        if (stringreturn != null)
        {
          if (stringreturn == "The operation has timed out")
          {
            Thread.Sleep(1000);
            SearchInfo(Artifact, type, iDays);
          }
          ThreatGRIDReturn = JsonConvert.DeserializeObject<Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search>(stringreturn);
          //if (ThreatGRIDReturn.Data.Items.Count > 0)
          //{
          //  for (int i = 0; i < ThreatGRIDReturn.Data.Items.Count; i++)
          //  {
              
          //    if (ThreatGRIDReturn.Data.Items[i] == null) continue;

          //    var stringObject = ThreatGRIDReturn.Data.Items[i].DataDetail.ToString();
          //    if (stringObject.Contains("network-streams"))
          //    {
          //      stringObject = stringObject.Replace("\r\n", "");
          //      stringObject = stringObject.Replace('\"', '"');
          //      stringObject = stringObject.Replace(" ", "");
          //      var newObject = new Object_ThreatGRID_Search_ConfigClass.Search_Return_NetworkStreams();
          //      newObject = JsonConvert.DeserializeObject<Object_ThreatGRID_Search_ConfigClass.Search_Return_NetworkStreams>(stringObject);
          //      ThreatGRIDReturn.Data.Items[i].DataDetail = new Object_ThreatGRID_Search_ConfigClass.Search_Return_NetworkStreams();
          //      ThreatGRIDReturn.Data.Items[i].DataDetail = newObject;
          //    }
          //    else if (stringObject.Contains("nsid"))
          //    {
          //      stringObject = stringObject.Replace("\r\n", "");
          //      stringObject = stringObject.Replace('\"', '"');
          //      stringObject = stringObject.Replace(" ", "");
          //      var newObject = new List<Object_ThreatGRID_Search_ConfigClass.Search_Data_NetworkStreams[]>();
          //      newObject = JsonConvert.DeserializeObject<List<Object_ThreatGRID_Search_ConfigClass.Search_Data_NetworkStreams[]>>(stringObject);
          //    }
          //    else if (stringObject.Contains("query"))
          //    {
          //      stringObject = stringObject.Replace("\r\n", "");
          //      stringObject = stringObject.Replace('\"', '"');
          //      stringObject = stringObject.Replace(" ", "");
          //      var newObject = new Object_ThreatGRID_Search_ConfigClass.Search_Return_Query();
          //      newObject = JsonConvert.DeserializeObject<Object_ThreatGRID_Search_ConfigClass.Search_Return_Query>(stringObject);
          //      ThreatGRIDReturn.Data.Items[i].DataDetail = new Object_ThreatGRID_Search_ConfigClass.Search_Return_Query();
          //      ThreatGRIDReturn.Data.Items[i].DataDetail = newObject;
          //    }
              
          //  }
          //}
        }
        
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID search information:" + e + " Query : " + request + @" " + stringreturn);
        using (StreamWriter sTG = File.AppendText(@"d:\temp\threatgriderror.txt"))
        {
          sTG.WriteLine(request.Replace("&api_key=6l5jknrpr3g39b7qng0tbb1v86", "") + @"," + e.Message + @"," + DateTime.UtcNow + " (UTC)");
        }
      }
      return ThreatGRIDReturn;
    }

    private static string Request(string sArtifact, The_Director_ThreatFeed_Enum type, Int16 iDays)
    {
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("search-level");
      var searchdate = DateTime.Now.AddDays(iDays);
      var request = string.Empty;
      switch (type)
      {
        case The_Director_ThreatFeed_Enum.domain:
          request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?domain=" + sArtifact + parseConfigs.ApiQueryString + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
          break;

        case The_Director_ThreatFeed_Enum.hash:
          request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?checksum=" + sArtifact + parseConfigs.ApiQueryString + searchdate + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
          break;

        case The_Director_ThreatFeed_Enum.ip:
          request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?ip=" + sArtifact + parseConfigs.ApiQueryString + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
          break;

        case The_Director_ThreatFeed_Enum.url:
          request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + "?url=" + sArtifact + parseConfigs.ApiQueryString + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
          break;

        default:
          break;
      }

      return request;
    }

    public static Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info ThreatInfo(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var ThreatGRIDReturn = new Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info();
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("hash-threat-level");
      var request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + sHash + "/threat?" + parseConfigs.ApiQueryString + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
      var alertRequest = (HttpWebRequest) WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Timeout = 60000;
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, true);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        ThreatGRIDReturn =
          JsonConvert.DeserializeObject<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>(stringreturn);
        return ThreatGRIDReturn;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in retrieving ThreatGRID threat information:" + e + "Query : " + request);
        using (StreamWriter sTG = File.AppendText(@"d:\temp\threatgriderror.txt"))
        {
          sTG.WriteLine(request.Replace("&api_key=6l5jknrpr3g39b7qng0tbb1v86", "") + @"," + e.Message + @"," +
                        DateTime.UtcNow + " (UTC)");
        }
      }
      return ThreatGRIDReturn;
    }

    public static void ReportHTML(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("report-level");
      var request = parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + sHash + "/report.html?" + parseConfigs.ApiQueryString + "&api_key=" + Base64.Decode(parseConfigs.ApiKey);
      var alertRequest = (HttpWebRequest) WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Timeout = 60000;
      try
      {
        //if (respStream == null) return;
        //todo: move this to the DB
        //using (var file = File.Create(Environment.CurrentDirectory + @"\reports\threatgrid\" + sHash + ".html"))
        //{
        //  //respStream.CopyTo(file);
        //}
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught downloading ThreatGRID report information:" + e);
        using (StreamWriter sTG = File.AppendText(@"d:\temp\threatgriderror.txt"))
        {
          sTG.WriteLine(request.Replace("&api_key=6l5jknrpr3g39b7qng0tbb1v86", "") + @"," + e.Message + @"," + DateTime.UtcNow + " (UTC)");
        }
      }
    }

    public static Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo HlInfo(List<string> sIP)
    {
      Console.WriteLine(@"Gathering ThreatGRID IP information.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

      var stringreturn = string.Empty;
      var ThreatGRIDReturn = new Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo();
      var parseConfigs = Object_ThreatGRID_Configs.GetThreatGridConfigs("ip-high-level");
      try
      {
        foreach (var alertRequest in sIP.Select(ip => parseConfigs.ApiBaseUrl + parseConfigs.ApiFuncCall + ip + "?" + parseConfigs.ApiQueryString + "&api_key=" + parseConfigs.ApiKey).Select(request => (HttpWebRequest) WebRequest.Create(request)))
        {
          alertRequest.Method = "GET";
          alertRequest.Timeout = 60000;
          var getREST = new Fido_Rest_Connection();
          stringreturn = getREST.RestCall(alertRequest, true);
          Thread.Sleep(500);
          if (string.IsNullOrEmpty(stringreturn))
          {
            ThreatGRIDReturn.API_Version = string.Empty;
            ThreatGRIDReturn.Id = string.Empty;
            ThreatGRIDReturn.Data_Array = null;
            return ThreatGRIDReturn;
          }
          ThreatGRIDReturn = JsonConvert.DeserializeObject<Object_ThreatGRID_IP_ConfigClass.ThreatGRID_IP_HLInfo>(stringreturn);
        }
        return ThreatGRIDReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID IP information:" + e + " " + e.Response.ResponseUri);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID IP information:" + e);
      }
      return ThreatGRIDReturn;
    }
  }
}
