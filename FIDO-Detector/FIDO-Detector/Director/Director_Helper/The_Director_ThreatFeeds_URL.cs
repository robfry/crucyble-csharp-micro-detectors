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
using System.Threading.Tasks;
using Fido_Main.Director.Threat_Feeds;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.OpenDNS;
using Fido_Main.Fido_Support.Objects.ThreatGRID;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.Director_Helper
{
  static class The_Director_ThreatFeeds_URL
  {

    public static FidoReturnValues DetectorsToThreatFeeds(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.CurrentDetector == "mps") lFidoReturnValues = FireEyeURL(lFidoReturnValues);
      if (lFidoReturnValues.CurrentDetector.Contains("cyphort")) lFidoReturnValues = CyphortURL(lFidoReturnValues);
      if (lFidoReturnValues.CurrentDetector.Contains("protectwise")) lFidoReturnValues = ProtectWiseURL(lFidoReturnValues);
      if (lFidoReturnValues.CurrentDetector.Contains("pan")) lFidoReturnValues = PaloAltoURL(lFidoReturnValues);
      if (lFidoReturnValues.CurrentDetector.Contains("niddel")) lFidoReturnValues = NiddelDomain(lFidoReturnValues);

      return lFidoReturnValues;
    }

    private static FidoReturnValues FireEyeURL(FidoReturnValues lFidoReturnValues)
    {

      if ((lFidoReturnValues.FireEye != null) && ((lFidoReturnValues.FireEye.URL.Count != 0) || (lFidoReturnValues.FireEye.ChannelHost.Count != 0)))
      {
        //initialize VT area if null
        if (lFidoReturnValues.FireEye.VirusTotal == null)
        {
          lFidoReturnValues.FireEye.VirusTotal = new VirusTotalReturnValues();
        }

        //convert return from FireEye to list
        var sURLToCheck = new List<string>();
        //if ((lFidoReturnValues.FireEye.URL != null) && (lFidoReturnValues.FireEye.URL.Count > 0))
        //{
        //  sURLToCheck.AddRange(lFidoReturnValues.FireEye.URL);
        //}
        if ((lFidoReturnValues.FireEye.ChannelHost != null) && (lFidoReturnValues.FireEye.ChannelHost.Count > 0))
        {
          sURLToCheck.AddRange(lFidoReturnValues.FireEye.ChannelHost);
        }
        //if (lFidoReturnValues.FireEye.DstIP != null)
        //{
        //  sURLToCheck.Add(lFidoReturnValues.FireEye.DstIP);
        //}

        sURLToCheck = sURLToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

        //send FireEye return to VT
        if ((sURLToCheck != null) && sURLToCheck.Any())
        {
          Console.WriteLine(@"Sending FireEye URLs to VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.URLReturn = Feeds_VirusTotal.VirusTotalUrl(sURLToCheck);
        }

        var sIPToCheck = new List<string>();

        if (lFidoReturnValues.FireEye.DstIP != null)
        {
          sIPToCheck.Add(lFidoReturnValues.FireEye.DstIP);
        }

        sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

        //send IP information to VT IP API
        if (sIPToCheck != null)
        {
          Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
          lFidoReturnValues.FireEye.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
          lFidoReturnValues.FireEye.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.FireEye.DstIP + "/information/";
        }

        //initialize AlienVault area if null
        if (lFidoReturnValues.FireEye.AlienVault == null)
        {
          lFidoReturnValues.FireEye.AlienVault = new AlienVaultReturnValues();
        }

        //next send FireEye return to AlienVault
        if ((lFidoReturnValues.FireEye != null) && (lFidoReturnValues.FireEye.DstIP != null))
        {
          Console.WriteLine(@"Getting IP information from AlienVault");
          lFidoReturnValues.FireEye.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
        }

      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues CyphortURL(FidoReturnValues lFidoReturnValues)
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

      if ((lFidoReturnValues.Cyphort != null) && ((lFidoReturnValues.Cyphort.URL.Count != 0) || (lFidoReturnValues.Cyphort.Domain.Count != 0)))
      {
        lFidoReturnValues = SendCyphortToVirusTotal(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal);

        lFidoReturnValues.Cyphort.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Url, The_Director_ThreatFeed_Enum.url, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.Cyphort.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Domain, The_Director_ThreatFeed_Enum.domain, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.Cyphort.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.DstIP, The_Director_ThreatFeed_Enum.ip, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.Cyphort.OpenDNS = SendDomainIPToOpenDNS(lFidoReturnValues.Domain, lFidoReturnValues.DstIP);

        lFidoReturnValues = SendCyphortToAlienVault(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.alienvault);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues ProtectWiseURL(FidoReturnValues lFidoReturnValues)
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

      if ((lFidoReturnValues.ProtectWise != null) && ((lFidoReturnValues.ProtectWise.URL != null) || (lFidoReturnValues.ProtectWise.DstIP != null)))
      {
        lFidoReturnValues = SendProtectWiseToVirusTotal(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal);

        lFidoReturnValues.ProtectWise.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Url, The_Director_ThreatFeed_Enum.url, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.ProtectWise.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Domain, The_Director_ThreatFeed_Enum.domain, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.ProtectWise.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.DstIP, The_Director_ThreatFeed_Enum.ip, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.ProtectWise.OpenDNS = SendDomainIPToOpenDNS(lFidoReturnValues.Domain, lFidoReturnValues.DstIP);

        lFidoReturnValues = SendProtectWiseToAlienVault(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.alienvault);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues NiddelDomain(FidoReturnValues lFidoReturnValues)
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

      if ((lFidoReturnValues.Niddel != null) && ((lFidoReturnValues.Niddel.Domain != null) || (lFidoReturnValues.Niddel.DstIp != null)))
      {
        lFidoReturnValues = SendNiddelToVirusTotal(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal);

        lFidoReturnValues.Niddel.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Domain, The_Director_ThreatFeed_Enum.domain, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.Niddel.OpenDNS = SendDomainIPToOpenDNS(lFidoReturnValues.Domain, lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues PaloAltoURL(FidoReturnValues lFidoReturnValues)
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

      if ((lFidoReturnValues.PaloAlto != null) && ((lFidoReturnValues.PaloAlto.DstIp != null)))
      {
        lFidoReturnValues = SendPaloAltoToVirusTotal(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.virustotal);

        lFidoReturnValues.PaloAlto.ThreatGRID = SendIOCToThreatGRID(lFidoReturnValues.Url, The_Director_ThreatFeed_Enum.url, integrationConfigs.rows[0].value.threatstack.threatgrid);
        lFidoReturnValues.PaloAlto.OpenDNS = SendDomainIPToOpenDNS(lFidoReturnValues.Domain, lFidoReturnValues.DstIP);

        lFidoReturnValues = SendPaloAltoToAlienVault(lFidoReturnValues, integrationConfigs.rows[0].value.threatstack.alienvault);
      }

      return lFidoReturnValues;

    }

    private static FidoReturnValues SendCyphortToVirusTotal(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!VirusTotal) return lFidoReturnValues;

      //convert return from Cyphort to list
      var sURLToCheck = new List<string>();
      if ((lFidoReturnValues.Cyphort.URL.Any()) && (lFidoReturnValues.Cyphort.URL.Count > 0))
      {
        for (var i = 0; i < lFidoReturnValues.Cyphort.URL.Count(); i++)
        {
          if (string.IsNullOrEmpty(lFidoReturnValues.Cyphort.URL[i])) continue;
          if (lFidoReturnValues.Cyphort.URL[i].Contains(".exe")) continue;
          //if (!lFidoReturnValues.Cyphort.URL[i].Contains(".com"))
          //{
          //  lFidoReturnValues.Cyphort.URL[i] = lFidoReturnValues.Cyphort.URL[i] + @".com";
          //}
          sURLToCheck.Add(lFidoReturnValues.Cyphort.URL[i]);
        }
      }

      if ((lFidoReturnValues.Cyphort.Domain != null) && (lFidoReturnValues.Cyphort.Domain.Count > 0))
      {
        sURLToCheck.AddRange(lFidoReturnValues.Cyphort.Domain);
      }

      if (lFidoReturnValues.Cyphort.DstIP != null)
      {
        sURLToCheck.Add(lFidoReturnValues.Cyphort.DstIP);
      }

      sURLToCheck = sURLToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

      //send Cyphort return to VT URL API
      if (sURLToCheck.Any())
      {
        Console.WriteLine(@"Sending Cyphort URLs to VirusTotal.");
        if (lFidoReturnValues.Cyphort.VirusTotal == null)
        {
          lFidoReturnValues.Cyphort.VirusTotal = new VirusTotalReturnValues();
        }
        lFidoReturnValues.Cyphort.VirusTotal.URLReturn = Feeds_VirusTotal.VirusTotalUrl(sURLToCheck);
      }

      var sIPToCheck = new List<string>();

      if (lFidoReturnValues.Cyphort.DstIP != null)
      {
        sIPToCheck.Add(lFidoReturnValues.Cyphort.DstIP);
      }

      sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();

      //send Cyphort return to VT IP API
      if (sIPToCheck.Any())
      {
        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        lFidoReturnValues.Cyphort.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
        //todo: move the url to the database
        lFidoReturnValues.Cyphort.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.Cyphort.DstIP + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToVirusTotal(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!VirusTotal) return lFidoReturnValues;

      var sIPToCheck = new List<string>();
      if (lFidoReturnValues.ProtectWise.VirusTotal == null)
      {
        lFidoReturnValues.ProtectWise.VirusTotal = new VirusTotalReturnValues();
      }
      //send ProtectWise return to VT URL API
      if (lFidoReturnValues.ProtectWise.URL != null)
      {
        Console.WriteLine(@"Sending ProtectWise URLs to VirusTotal.");
        var vtURLReturn = Feeds_VirusTotal.VirusTotalUrl(lFidoReturnValues.ProtectWise.URL);
        if (vtURLReturn != null)
        {
          lFidoReturnValues.ProtectWise.VirusTotal.URLReturn = vtURLReturn;
        }
      }

      if (lFidoReturnValues.ProtectWise.DstIP != null)
      {
        sIPToCheck.Add(lFidoReturnValues.ProtectWise.DstIP);
      }

      sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();
      //send ProtectWise return to VT IP API
      if (sIPToCheck.Any())
      {
        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        lFidoReturnValues.ProtectWise.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
        //todo: move the url to the database
        lFidoReturnValues.ProtectWise.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.ProtectWise.DstIP + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendNiddelToVirusTotal(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!VirusTotal) return lFidoReturnValues;

      var sIPToCheck = new List<string>();
      if (lFidoReturnValues.Niddel.VirusTotal == null)
      {
        lFidoReturnValues.Niddel.VirusTotal = new VirusTotalReturnValues();
      }
      //send Niddel return to VT URL API
      if (lFidoReturnValues.Niddel.Domain != null)
      {
        Console.WriteLine(@"Sending Niddel domains to VirusTotal.");
        var vtURLReturn = Feeds_VirusTotal.VirusTotalUrl(lFidoReturnValues.Niddel.Domain);
        if (vtURLReturn != null)
        {
          lFidoReturnValues.Niddel.VirusTotal.URLReturn = vtURLReturn;
        }
      }

      if (lFidoReturnValues.Niddel.DstIp != null)
      {
        sIPToCheck.Add(lFidoReturnValues.Niddel.DstIp);
      }

      sIPToCheck = sIPToCheck.Where(s => !string.IsNullOrEmpty(s)).Distinct().ToList();
      //send Niddel return to VT IP API
      if (sIPToCheck.Any())
      {
        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        lFidoReturnValues.Niddel.VirusTotal.IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
        //todo: move the url to the database
        lFidoReturnValues.Niddel.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.Niddel.DstIp + "/information/";
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SendPaloAltoToVirusTotal(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!VirusTotal) return lFidoReturnValues;

      var sIPToCheck = new List<string> {lFidoReturnValues.PaloAlto.DstIp};
      //send ProtectWise return to VT IP API
      if (lFidoReturnValues.PaloAlto.DstIp.Any())
      {
        if (lFidoReturnValues.PaloAlto.VirusTotal == null)
        {
          lFidoReturnValues.PaloAlto.VirusTotal = new VirusTotalReturnValues();
        }

        Console.WriteLine(@"Getting detailed IP information from VirusTotal.");
        try
        {
          var IPReturn = Feeds_VirusTotal.VirusTotalIP(sIPToCheck);
          if (IPReturn != null)
          {
            lFidoReturnValues.PaloAlto.VirusTotal.IPReturn = IPReturn;
          }
        }
        catch (Exception e)
        {
          Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving VT IP information:" + e);
        }
        
        //todo: move the url to the database
        lFidoReturnValues.PaloAlto.VirusTotal.IPUrl = "http://www.virustotal.com/en/ip-address/" + lFidoReturnValues.PaloAlto.DstIp + "/information/";
      }
      return lFidoReturnValues;
    }

    private static ThreatGRIDReturnValues SendIOCToThreatGRID(List<string> Artifact, The_Director_ThreatFeed_Enum type, bool VirusTotal)
    {
      if (!new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) return null;
      Console.WriteLine(@"Getting detailed IP information from ThreatGRID.");
      
      Int16 iDays = -180;
      var threatGRID = new ThreatGRIDReturnValues();
      if (Artifact == null) return threatGRID;

      try
      {
        foreach (var artifact in Artifact)
        {
          if (string.IsNullOrEmpty(artifact)) continue;
          var iocsearch = Feeds_ThreatGRID.SearchInfo(artifact, type, iDays);
          if (iocsearch == null) continue;
          threatGRID.IPSearch = new List<Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search>() {iocsearch};
          if (threatGRID.IPSearch == null) continue;
          if (!threatGRID.IPSearch.Any()) continue;

          //while (threatGRID.HashSearch.Data.CurrentItemCount < 50)
          //{
          //  if (iDays < -364) break;
          //  iDays = (Int16)(iDays * 2);
          //  threatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(md5, true, iDays);
          //}

          if (threatGRID.IPSearch.Count > 0)
          {
            Console.WriteLine(@"Successfully found ThreatGRID hash data (" + threatGRID.IPSearch.Count + @" records)... storing in Fido.");
          }

          if (threatGRID.IPThreatInfo == null)
          {
            threatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
          }

          for (var i = 0; i < threatGRID.IPSearch.Count; i++)
          {
            for (var j = 0; j < threatGRID.IPSearch[i].Data.Items.Count; j++)
            {
              if (i >= 50 | j >= 50) continue;

              if (string.IsNullOrEmpty(threatGRID.IPSearch[i].Data.Items[j].HashID)) continue;
              var x = Feeds_ThreatGRID.ThreatInfo(threatGRID.IPSearch[i].Data.Items[j].HashID);
              if (x == null) continue;
              threatGRID.IPThreatInfo.Add(x);
            }
          }
        }
        return threatGRID;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Threatfeed Hash area:" + e + " " + iDays + " " + threatGRID.IPSearch.Count);
      }
      return threatGRID;
    }

    private static OpenDNS SendDomainIPToOpenDNS(List<string> Domain, List<string> DstIP)
    {
      var odReturn = new OpenDNS();
      var getFeed = new Feeds_OpenDNS();

      if (DstIP != null)
      {
        odReturn.BgpRoutesIP = new List<BGPRoutesIP>();
        odReturn.DnsDbip = new List<DnsDBIP>();
        odReturn.LatestDomains = new List<LatestDomains>();

        foreach (var ip in DstIP)
        {
          odReturn.LatestDomains.AddRange(getFeed.GetLatestDomains(ip));
          odReturn.BgpRoutesIP.AddRange(getFeed.GetBGPRoutesIP(ip));
          odReturn.DnsDbip.Add(getFeed.GetDnsDbip(ip));
        }
      }

      if (odReturn.BgpRoutesIP.Any())
      {
        odReturn.BgpRoutesAsn = new List<BGPRoutesASN>();
        foreach (BGPRoutesIP t in odReturn.BgpRoutesIP.Where(t => !string.IsNullOrEmpty(t.asn.ToString())))
        {
          odReturn.BgpRoutesAsn.AddRange(getFeed.GetBGPRoutesASN(t.asn.ToString()));
        }
      }

      if (Domain == null)
      {
        Domain = new List<string>();
        foreach (var entry in odReturn.DnsDbip)
        {
          foreach (var record in entry.rrs)
          {
           if (!string.IsNullOrEmpty(record.rr)) Domain.Add(record.rr);
          }
        }
        //Domain.AddRange(odReturn.LatestDomains.Where(t => !string.IsNullOrEmpty(t.name)).Select(t => t.name));
        
      }

      if (Domain == null) return odReturn;

      odReturn.DomainStatus = new List<DomainStatus>();
      odReturn.DnsDBDomain = new List<DnsDBDomain>();
      odReturn.DomainsLatestTags = new List<DomainsLatestTags>();
      odReturn.DomainScore = new List<DomainScore>();
      odReturn.LinkedDomains = new List<LinkedDomains>();
      odReturn.SecurityScore = new List<SecurityScore>();
      odReturn.Whois = new List<Whois>();
      
      Console.WriteLine(@"Querying OpenDNS for information.");
      Parallel.ForEach(Domain.Take(10), domain =>
      //foreach (var domain in Domain)
      {
        if (domain == null) return;
        odReturn.DomainStatus.Add(getFeed.GetDomainStatus(domain));
        odReturn.DnsDBDomain.Add(getFeed.GetDnsDBDomain(domain));
        odReturn.DomainsLatestTags.AddRange(getFeed.GetDomainsLatestTags(domain));
        odReturn.DomainScore.Add(getFeed.GetDomainScore(domain));
        odReturn.LinkedDomains.Add(getFeed.GetLinkedDomains(domain));
        odReturn.SecurityScore.Add(getFeed.GetSecurityScore(domain));
        odReturn.Whois.AddRange(getFeed.GetWhois(domain));
      });


      return odReturn;
    }

    //private static FidoReturnValues SendProtectWiseToThreatGRID(FidoReturnValues lFidoReturnValues)
    //{

    //  if (!new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) return lFidoReturnValues;
    //  Console.WriteLine(@"Getting detailed IP information from ThreatGRID.");
    //  Int16 iDays = -7;
    //  if (lFidoReturnValues.ProtectWise.ThreatGRID == null)
    //  {
    //    lFidoReturnValues.ProtectWise.ThreatGRID = new ThreatGRIDReturnValues();
    //    lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch = new Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search();
    //  }
    //  lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  while (Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
    //  {
    //    if (iDays < -364) break;
    //    iDays = (Int16)(iDays * 2);
    //    lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  }

    //  Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

    //  for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.CurrentItemCount); i++)
    //  {
    //    if (i >= 50) continue;
    //    if (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo == null)
    //    {
    //      lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
    //    }
    //    lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Data.Items[i].HashID));
    //  }

    //  return lFidoReturnValues;
    //}

    //private static FidoReturnValues SendNiddelToThreatGRID(FidoReturnValues lFidoReturnValues)
    //{

    //  if (!new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) return lFidoReturnValues;
    //  Console.WriteLine(@"Getting detailed IP information from ThreatGRID.");
    //  Int16 iDays = -7;
    //  if (lFidoReturnValues.Niddel.ThreatGRID == null)
    //  {
    //    lFidoReturnValues.Niddel.ThreatGRID = new ThreatGRIDReturnValues();
    //    lFidoReturnValues.Niddel.ThreatGRID.IPSearch = new Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search();
    //  }
    //  lFidoReturnValues.Niddel.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  while (Convert.ToInt16(lFidoReturnValues.Niddel.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
    //  {
    //    if (iDays < -364) break;
    //    iDays = (Int16)(iDays * 2);
    //    lFidoReturnValues.Niddel.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  }

    //  Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.Niddel.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

    //  for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.Niddel.ThreatGRID.IPSearch.Data.CurrentItemCount); i++)
    //  {
    //    if (i >= 50) continue;
    //    if (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo == null)
    //    {
    //      lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
    //    }
    //    lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.Niddel.ThreatGRID.IPSearch.Data.Items[i].HashID));
    //  }

    //  return lFidoReturnValues;
    //}

    //private static FidoReturnValues SendPaloAltoToThreatGRID(FidoReturnValues lFidoReturnValues)
    //{
    //  if (!new SqLiteDB().ExecuteBool(@"select threatgrid from configs_director")) return lFidoReturnValues;
    //  Console.WriteLine(@"Getting detailed IP information from ThreatGRID.");
    //  Int16 iDays = -7;
    //  if (lFidoReturnValues.PaloAlto.ThreatGRID == null)
    //  {
    //    lFidoReturnValues.PaloAlto.ThreatGRID = new ThreatGRIDReturnValues();
    //    lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch = new Object_ThreatGRID_Search_ConfigClass.ThreatGRID_Search();
    //  }
    //  lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  while (Convert.ToInt16(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount) < 50)
    //  {
    //    if (iDays < -364) break;
    //    iDays = (Int16)(iDays * 2);
    //    lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch = Feeds_ThreatGRID.SearchInfo(lFidoReturnValues.DstIP, false, iDays);
    //  }

    //  Console.WriteLine(@"Successfully found ThreatGRID IP data (" + lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount + @" records)... storing in Fido.");

    //  for (var i = 0; i < Convert.ToInt16(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.CurrentItemCount); i++)
    //  {
    //    if (i >= 50) continue;
    //    if (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo == null)
    //    {
    //      lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo = new List<Object_ThreatGRID_Threat_ConfigClass.ThreatGRID_Threat_Info>();
    //    }
    //    lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Add(Feeds_ThreatGRID.ThreatInfo(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Data.Items[i].HashID));
    //  }

    //  return lFidoReturnValues;
    //}

    private static FidoReturnValues SendCyphortToAlienVault(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!new SqLiteDB().ExecuteBool(@"select alienvault from configs_director")) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.Cyphort.AlienVault == null)
      {
        lFidoReturnValues.Cyphort.AlienVault = new AlienVaultReturnValues();
      }

      //next send Cyphort return to AlienVault
      if ((lFidoReturnValues.Cyphort != null) && (lFidoReturnValues.Cyphort.DstIP != null))
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.Cyphort.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendProtectWiseToAlienVault(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!new SqLiteDB().ExecuteBool(@"select alienvault from configs_director")) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.ProtectWise.AlienVault == null)
      {
        lFidoReturnValues.ProtectWise.AlienVault = new AlienVaultReturnValues();
      }

      //next send Cyphort return to AlienVault
      if ((lFidoReturnValues.ProtectWise != null) && (lFidoReturnValues.ProtectWise.DstIP != null))
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.ProtectWise.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }

    private static FidoReturnValues SendPaloAltoToAlienVault(FidoReturnValues lFidoReturnValues, bool VirusTotal)
    {
      if (!new SqLiteDB().ExecuteBool(@"select alienvault from configs_director")) return lFidoReturnValues;

      //initialize AlienVault area if null
      if (lFidoReturnValues.PaloAlto.AlienVault == null)
      {
        lFidoReturnValues.PaloAlto.AlienVault = new AlienVaultReturnValues();
      }

      //next send PAN return to AlienVault
      if (lFidoReturnValues.DstIP != null)
      {
        Console.WriteLine(@"Getting IP informaiton from AlienVault.");
        lFidoReturnValues.PaloAlto.AlienVault = Feeds_AlientVault.AlienVaultIP(lFidoReturnValues.DstIP);
      }

      return lFidoReturnValues;
    }
    
    public static FidoReturnValues ThreatGRIDIPInfo(FidoReturnValues lFidoReturnValues)
    {
      //if (!new SqLiteDB().ExecuteBool(@"select alienvault from configs_director")) return lFidoReturnValues;

      if (!lFidoReturnValues.DstIP.Contains(null))
      {
        if (lFidoReturnValues.FireEye != null)
        {
          if (lFidoReturnValues.FireEye.ThreatGRID == null)
          {
            lFidoReturnValues.FireEye.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.FireEye.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.Cyphort != null)
        {
          if (lFidoReturnValues.Cyphort.ThreatGRID == null)
          {
            lFidoReturnValues.Cyphort.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.Cyphort.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.ProtectWise != null)
        {
          if (lFidoReturnValues.ProtectWise.ThreatGRID == null)
          {
            lFidoReturnValues.ProtectWise.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.ProtectWise.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
        if (lFidoReturnValues.PaloAlto != null)
        {
          if (lFidoReturnValues.PaloAlto.ThreatGRID == null)
          {
            lFidoReturnValues.PaloAlto.ThreatGRID = new ThreatGRIDReturnValues();
          }
          lFidoReturnValues.PaloAlto.ThreatGRID.IPInfo = Feeds_ThreatGRID.HlInfo(lFidoReturnValues.DstIP);
        }
      }
      return lFidoReturnValues;
    }

  }
}