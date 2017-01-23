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
using Fido_Main.Director.Threat_Feeds;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.ThreatGRID;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;
using VirusTotalNET.Objects;


namespace Fido_Main.Director.Director_Helper
{
  static class The_Director_ThreatFeeds_Hash
  {

    public static FidoReturnValues DetectorsToThreatFeeds(FidoReturnValues lFidoReturnValues)
    {

      //Load Fido configs from CouchDB
      const string query = "http://127.0.0.1:5984/fido_configs/_design/app_configs/_view/integrations";
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Method = @"GET";
      var integrationConfigs = new Object_Fido_Configs_CouchDB_Integrations.RootObject();

      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(request, false);
        integrationConfigs = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_Integrations.RootObject>(stringreturn);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in fidomain area gathering startup configs:" + e);
      }

      switch (lFidoReturnValues.CurrentDetector)
      {
        case "mps":
          lFidoReturnValues = FireEyeHash(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal, integrationConfigs.rows[0].value.threatstack.threatgrid);
          break;
        case "cyphort":
          lFidoReturnValues = CyphortHash(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal, integrationConfigs.rows[0].value.threatstack.threatgrid);
          break;
        case "protectwise":
          lFidoReturnValues = ProtectWiseHash(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal, integrationConfigs.rows[0].value.threatstack.threatgrid);
          break;
        case "carbonblack":
          lFidoReturnValues = CarbonBlackHash(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal, integrationConfigs.rows[0].value.threatstack.threatgrid);
          break;
        case "sentinelone":
          lFidoReturnValues = SentinelOneHash(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal, integrationConfigs.rows[0].value.threatstack.threatgrid);
          break;
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SentinelOneHash(FidoReturnValues lFidoReturnValues, bool VirusTotal, bool ThreatGrid)
    {
      //if SentinelOne has hashes send to threat feeds
      if (VirusTotal)
      {
        if ((lFidoReturnValues.SentinelOne != null) && (lFidoReturnValues.SentinelOne != null) && (lFidoReturnValues.SentinelOne.Alert.file_id.content_hash != null))
        {
          if (lFidoReturnValues.SentinelOne.VirusTotal == null)
          {
            lFidoReturnValues.SentinelOne.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending SentinelOne hashes to VirusTotal.");
          lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn = new List<FileReport>();
          lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Hash);
        }
      }

      if (ThreatGrid)
      {
        Console.WriteLine(@"Sending SentinelOne hashes to ThreatGRID.");
        if (lFidoReturnValues.SentinelOne.ThreatGRID == null)
        {
          lFidoReturnValues.SentinelOne.ThreatGRID = new ThreatGRIDReturnValues();
        }
        lFidoReturnValues.SentinelOne.ThreatGRID = SendHashToThreatGRID(lFidoReturnValues.Hash);
      }
      return lFidoReturnValues;

    }

    private static FidoReturnValues FireEyeHash(FidoReturnValues lFidoReturnValues, bool VirusTotal, bool ThreatGrid)
    {
      //if FireEye has hashes send to threat feeds
      if (VirusTotal)
      {
        if ((lFidoReturnValues.FireEye != null) && (lFidoReturnValues.FireEye.MD5Hash.Any()))
        {
          if (lFidoReturnValues.FireEye.VirusTotal == null)
          {
            lFidoReturnValues.FireEye.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending FireEye hashes to VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.FireEye.MD5Hash);
        }
      }

      //todo: decide if FireEye should go to ThreatGRID
      //if (Object_Fido_Configs.GetAsBool("fido.director.threatgrid", false))
      //{
      //  Console.WriteLine(@"Sending FireEye hashes to ThreatGRID.");
      //  lFidoReturnValues = SendFireEyeToThreatGRID(lFidoReturnValues);
      //}

      return lFidoReturnValues;
    }

    private static FidoReturnValues CyphortHash(FidoReturnValues lFidoReturnValues, bool VirusTotal, bool ThreatGrid)
    {
      //if Cyphort has hashes send to threat feeds
      if (VirusTotal)
      {
        if ((lFidoReturnValues.Cyphort != null) && (lFidoReturnValues.Cyphort.MD5Hash != null) && (lFidoReturnValues.Cyphort.MD5Hash.Any()))
        {
          if (lFidoReturnValues.Cyphort.VirusTotal == null)
          {
            lFidoReturnValues.Cyphort.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending Cyphort hashes to VirusTotal.");
          lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Cyphort.MD5Hash);
        }
      }

      if (ThreatGrid)
      {
        Console.WriteLine(@"Sending Cyphort hashes to ThreatGRID.");
        if (lFidoReturnValues.Cyphort == null)
        {
          lFidoReturnValues.Cyphort = new CyphortReturnValues();
        }
        lFidoReturnValues.Cyphort.ThreatGRID = SendHashToThreatGRID(lFidoReturnValues.Hash);
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues ProtectWiseHash(FidoReturnValues lFidoReturnValues, bool VirusTotal, bool ThreatGrid)
    {
      //if ProtectWise has hashes send to threat feeds
      if (VirusTotal)
      {
        if (lFidoReturnValues.Hash != null)
        {
          if (lFidoReturnValues.ProtectWise.VirusTotal == null)
          {
            lFidoReturnValues.ProtectWise.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending ProtectWise hashes to VirusTotal.");
          lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Hash);
        }
      }

      if (ThreatGrid)
      {
        Console.WriteLine(@"Sending ProtectWise hashes to ThreatGRID.");
        if (lFidoReturnValues.ProtectWise.ThreatGRID == null)
        {
          lFidoReturnValues.ProtectWise.ThreatGRID = new ThreatGRIDReturnValues();
        }
        lFidoReturnValues.ProtectWise.ThreatGRID = SendHashToThreatGRID(lFidoReturnValues.Hash);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues CarbonBlackHash(FidoReturnValues lFidoReturnValues, bool VirusTotal, bool ThreatGrid)
    {
      //if Carbon Black has hashes send to threat feeds
      if (VirusTotal)
      {
        if ((lFidoReturnValues.CB != null) && (lFidoReturnValues.CB.Alert.MD5Hash != null))
        {
          if (lFidoReturnValues.CB.Alert.VirusTotal == null)
          {
            lFidoReturnValues.CB.Alert.VirusTotal = new VirusTotalReturnValues();
          }
          Console.WriteLine(@"Sending Carbon Black hashes to VirusTotal.");
          lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn = Feeds_VirusTotal.VirusTotalHash(lFidoReturnValues.Hash);
        }
      }
      if (ThreatGrid)
      {
        Console.WriteLine(@"Sending Carbon Black hashes to ThreatGRID.");
        if (lFidoReturnValues.CB == null)
        {
          lFidoReturnValues.CB = new CarbonBlackReturnValues();
        }
        lFidoReturnValues.CB.Alert.ThreatGRID = new ThreatGRIDReturnValues();
        lFidoReturnValues.CB.Alert.ThreatGRID = SendHashToThreatGRID(lFidoReturnValues.Hash);
      }

      return lFidoReturnValues;
    }

    private static ThreatGRIDReturnValues SendHashToThreatGRID(List<string> Hashes)
    {
      Int16 iDays = -180;
      var threatGRID = new ThreatGRIDReturnValues();
      if (Hashes == null) return threatGRID;
      threatGRID.HashSearch = new List<Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search>();

      try
      {
        foreach (var md5 in Hashes)
        {
          if (string.IsNullOrEmpty(md5)) continue;
          var hashsearch = Feeds_ThreatGRID.SearchInfo(md5, The_Director_ThreatFeed_Enum.hash, iDays);
          if (hashsearch == null) continue;
          threatGRID.HashSearch.Add(hashsearch);
          if (threatGRID.HashSearch == null) continue;
          if (!threatGRID.HashSearch.Any()) continue;

          //while (threatGRID.HashSearch.Data.CurrentItemCount < 50)
          //{
          //  if (iDays < -364) break;
          //  iDays = (Int16)(iDays * 2);
          //  threatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(md5, true, iDays);
          //}

          if (threatGRID.HashSearch.Count > 0)
          {
            Console.WriteLine(@"Successfully found ThreatGRID hash data (" + threatGRID.HashSearch.Count + @" records)... storing in Fido.");
          }

          if (threatGRID.HashThreatInfo == null)
          {
            threatGRID.HashThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
          }

          for (var i = 0; i < threatGRID.HashSearch.Count; i++)
          {
            for (int j = 0; j < threatGRID.HashSearch[i].Data.Items.Count; j++)
            {
              if (i >= 50) continue;
              if (string.IsNullOrEmpty(threatGRID.HashSearch[i].Data.Items[j].HashID)) continue;
              var x = Feeds_ThreatGRID.ThreatInfo(threatGRID.HashSearch[i].Data.Items[j].HashID);
              if (x == null) continue;
              threatGRID.HashThreatInfo.Add(x);
            }
          }
        }
        return threatGRID;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Threatfeed Hash area:" + e + " " + iDays + " " + threatGRID.HashSearch.Count);
      }
      return threatGRID;
    }
  }
}
