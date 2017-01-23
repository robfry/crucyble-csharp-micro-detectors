﻿/*
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


//using Fido_Main.Logger;

using System;
using System.Collections.Generic;
using System.Linq;
using Fido_Main.Director.Director_Helper;
using Fido_Main.Director.Scoring;
using Fido_Main.Director.SysMgmt;
using Fido_Main.Director.VPN;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support;
using Fido_Main.Fido_Support.GeoIP;
using Fido_Main.Fido_Support.Objects.DDI;
using Fido_Main.Fido_Support.Objects.ElasticSearch;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.GEOIP;
using Fido_Main.Fido_Support.RabbitMQ;
using Fido_Main.Main.Detectors;

namespace Fido_Main.Director
{
  public static class TheDirector
  {
    public static void Direct(FidoReturnValues lFidoReturnValues)
    {

      var sSrcIP = lFidoReturnValues.SrcIP;
      var sHostname = lFidoReturnValues.Hostname;

      try
      {
        //if DHCP detection is turned on, then gather DHCP information from DDI
        if (string.IsNullOrEmpty(lFidoReturnValues.Hostname) && new SqLiteDB().ExecuteBool(@"select dhcpdetection from configs_director"))
        {
          lFidoReturnValues.DDI = new Object_DDI();
          lFidoReturnValues.DDI = SysMgmt_DDI.GetDDIRecord(lFidoReturnValues);

          if (lFidoReturnValues.DDI.DhcpEntries != null)
          {
            if (lFidoReturnValues.DDI.DhcpEntries[0].DhcpLeaseClientName != null)
            {
              var aryTemp = lFidoReturnValues.DDI.DhcpEntries[0].DhcpLeaseClientName.Split('.');
              lFidoReturnValues.Hostname = aryTemp[0];
              sHostname = aryTemp[0];
            }
          }
        }        

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught getting DDI DHCP information:" + e);
      }

      try
      {
        //check detector values versus whitelist and exclude if true
        var isFound = new The_Director_Whitelist().CheckFidoWhitelist(lFidoReturnValues.SrcIP, lFidoReturnValues.DstIP, lFidoReturnValues.Hash, lFidoReturnValues.DNSName, lFidoReturnValues.Url, lFidoReturnValues.MalwareType, lFidoReturnValues.Hostname);
        if (isFound)
        {
          Console.WriteLine(@"Artifact from alert is whitelisted.");
          return; 
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director processing whitelist:" + e);
      }

      if (lFidoReturnValues.DstIP.Any())
      {
        lFidoReturnValues.Location = new GEO_IP_Object.Location();
        var locret = new GEO_IP_Lookup();
        lFidoReturnValues.Location = locret.GetLookup(lFidoReturnValues.DstIP);
        if (lFidoReturnValues.location == null && lFidoReturnValues.Location != null)
        {
          lFidoReturnValues.location = new double[] { lFidoReturnValues.Location.longitude, lFidoReturnValues.Location.latitude };
        }
      }

      if (lFidoReturnValues.SrcIP.StartsWith("100.127."))
      {
        var VPNSrcIP = SysMgmt_ElasticSearch.QueryESDB(lFidoReturnValues.SrcIP, null, Enum_F5_VPN.IP);
        if (VPNSrcIP.entries != null)
        {
          var entry = new Object_F5_VPN.Hit();
          foreach (var hit in VPNSrcIP.entries.hits)
          {
            if (string.IsNullOrEmpty(entry._score))
            {
              entry = hit;
            }
            if (entry._source.es_timestamp < hit._source.es_timestamp)
            {
              entry = hit;
            }

          }

          if (entry._source != null)
          {
            var Common = SysMgmt_ElasticSearch.ParseQueryReturn(entry._source.message, Object_F5_VPN_Search.Common);
            var retVPN = SysMgmt_ElasticSearch.QueryESDB(null, Common, Enum_F5_VPN.Record);
            lFidoReturnValues.VPN = new Object_F5_VPN.ESVPN();
            lFidoReturnValues.VPN = retVPN;
            var parseVPN = new VPN_F5();
            var returnVPN = parseVPN.ParseQueryReturn(lFidoReturnValues.VPN);
            lFidoReturnValues.Inventory = new Inventory {VPN = new Object_F5_VPN_Inventory()};
            lFidoReturnValues.Inventory.VPN = returnVPN;

            if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.VPN.HostName))
              lFidoReturnValues.Hostname = lFidoReturnValues.Inventory.VPN.HostName;
            if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.VPN.UserName))
              lFidoReturnValues.Username = lFidoReturnValues.Inventory.VPN.UserName.Replace("'", string.Empty);
          }
        }
      }

      try
      {

        //if HostDetection is turned on, then gather information directly from host
        //if (new SqLiteDB().ExecuteBool(@"select hostdetection from configs_director")) lFidoReturnValues = The_Director_HostDetection.HostDetection(lFidoReturnValues, sHostname, sSrcIP);
        
        //Write results out to console
        if (!string.IsNullOrEmpty(sHostname))
        {
          Console.WriteLine(@"Detected hostname=" + sHostname + @", gathering detailed inventory.");
        }
        else
        {
          Console.WriteLine(@"Unable to detect hostname, gathering detailed inventory for " + sSrcIP + @".");
        }

        //go to our sysmgmt data sources to get detailed inventory information
        if (new SqLiteDB().ExecuteBool(@"select runinventory from configs_director")) lFidoReturnValues = The_Director_HostDetection.SQLFidoReturnValues(lFidoReturnValues, sSrcIP, sHostname);

        //determine if hostname from host discover matches inventory data
        if (string.IsNullOrEmpty(lFidoReturnValues.Hostname))
        {
          Console.WriteLine(@"Hostname still unknown. Proceeding to evaluate threat.");
          lFidoReturnValues.IsHostKnown = false;
          lFidoReturnValues.Hostname = "unknown";
        }
        else if (lFidoReturnValues.Hostname.ToLower() == "unknown")
        {
          //todo: need to write code to take existing data
          //hold it for %configurable% minutes and then
          //send it out 'unmanaged' if hostinfo continues to come 
          //back empty
        }
        else
        {
          if (new SqLiteDB().ExecuteBool(@"select userdetect from configs_director")) lFidoReturnValues = The_Director_HostDetection.GetUserInfo(lFidoReturnValues);
        }

        if (lFidoReturnValues.Username != null)
        {
          var runUserDetect = new SqLiteDB().ExecuteBool(@"select userdetect from configs_director");
          if (runUserDetect) lFidoReturnValues = The_Director_HostDetection.GetUserInfo(lFidoReturnValues);
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director gathering host information:" + e);
      }

      //try
      //{
      //  //Gather more information about destination IP address
      //  lFidoReturnValues = The_Director_ThreatFeeds_URL.ThreatGRIDIPInfo(lFidoReturnValues);
      //}
      //catch (Exception e)
      //{
      //  Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director gathering host IP/GEO information:" + e);
      //}

      //try
      //{
      //  //todo: this area is half-baked... why is bit9 return not being assigned to lFidoReturnValues?
      //  //If detector == AV then check if AV information has a filepath/name
      //  //then parse and send to bit9 to get additional info
      //  if ((lFidoReturnValues.Antivirus != null) && (The_Director_HostDetection.IsBit9Installed()))
      //  {
      //    AntiVirusToBit9(lFidoReturnValues);
      //  }
      //}
      //catch (Exception e)
      //{
      //  Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director sending AV info to Bit9:" + e);
      //}

      //try
      //{
      //  //this area will take detector hashes and reference them against Bit9
      //  //to see if Bit9 has seen the hash, where and if it was executed
      //  if (The_Director_HostDetection.IsBit9Installed())
      //  {
      //    Console.WriteLine(@"Bit9 detected... cross-referencing hashes.");
      //    //if FireEye has hashes send to Bit9
      //    if ((lFidoReturnValues.FireEye != null) && (lFidoReturnValues.FireEye.MD5Hash.Any()))
      //    {
      //      if (lFidoReturnValues.Bit9 == null)
      //      {
      //        lFidoReturnValues.Bit9 = new Bit9ReturnValues();
      //      }
      //      lFidoReturnValues.Bit9.Bit9Hashes = Detect_Bit9.GetFileInfo(lFidoReturnValues.FireEye.MD5Hash, null).ToArray();
      //      //lFidoReturnValues = FireEyeHashToBit9(lFidoReturnValues);
      //    }

      //    //if FireEyeMPS has hashes send to Bit9

      //    //if PaloAlto has hashes send to Bit9

      //    //if Cyphort has hashes send to Bit9

      //    //if Protectwise has hashes send to Bit9
      //  }
      //}
      //catch (Exception e)
      //{
      //  Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director sending network detector info to Bit9:" + e);
      //}

      try
      {
        //this area will send hash data to threatfeeds to get additional information
        //to be used in scoring for the attack

        lFidoReturnValues = The_Director_ThreatFeeds_Hash.DetectorsToThreatFeeds(lFidoReturnValues);

        //this area will send URL data to threatfeeds to get additional information
        //to be used in scoring for the attack
        lFidoReturnValues = The_Director_ThreatFeeds_URL.DetectorsToThreatFeeds(lFidoReturnValues);

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director sending network detector info to threat feeds:" + e);
      }

      //Send accumulated information to the Matrix for scoring
      Console.WriteLine(@"Running scoring matrix.");
      lFidoReturnValues = Matrix.RunMatrix(lFidoReturnValues);
      Console.WriteLine(@"Exiting scoring matrix.");

      var actions = new List<string>();
        //handoff to  enforcement
        //
        //

      //todo: more whack
      if (!lFidoReturnValues.IsSendAlert)
      {
        actions.Add("Created Ticket");
        actions.Add("Not Needed");
      }
      else
      {
        actions.Add("Created Ticket");
        actions.Add("Success");
      }
      //Thebelow highlighted out as the Service-Now module is too proprietary
      //in its current form to be included with OSS. What will happen in a future
      //version is a module to handle the different ticketing solutions,
      //Service-Now, Zendesk, ServiceDesk, etc., so that tickets can be 
      //created based on user configuration.
      //ServiceNowUpdate.InsertResponse(lFidoReturnValues);

      lFidoReturnValues.Actions = actions;

      //Send configurable information for output to syslog
      //SysLogger.SendEventToSyslog(lFidoReturnValues);
        
      //todo: WTF is this? It's whack, thats what... 
      actions.Add("Update FIDO DB");
      actions.Add("Success");

      //new code to write to ES
      var esearch = new Fido_ElasticSearchDB();
      esearch.WriteToDBFactory(lFidoReturnValues);

      //new code to write to CouchDB
      var couchdb = new Fido_CouchDB();
      couchdb.WriteToDBFactory(lFidoReturnValues);

      //update FIDO DB with event information
      //Console.WriteLine(@"Updating FidoDB.");
      //Fido_UpdateDB.InsertEventToDB(lFidoReturnValues);

      //send information for notifications
      //Console.WriteLine(@"Sending notification.");
      //Notification.Notification.Notify(lFidoReturnValues);


    }

    private static void AntiVirusToBit9(FidoReturnValues lFidoReturnValues)
    {
      var lBit9ReturnValues = new Bit9ReturnValues();
      var sFileInfo = lFidoReturnValues.Antivirus.FilePath.Split('\\');
      if ((sFileInfo != null) && (sFileInfo.Length != 0))
      {
        Console.WriteLine(@"Antivirus detector found! Cross-referencing with Bit9.");
        lBit9ReturnValues.FileName = sFileInfo[sFileInfo.Length - 1];
        lFidoReturnValues.Antivirus.FileName = lBit9ReturnValues.FileName;
        for (var i = 0; i < sFileInfo.Length - 1; i++)
        {
          if (i == sFileInfo.Length - 2)
          {
            lBit9ReturnValues.FilePath += sFileInfo[i];
          }
          else
          {
            if (!sFileInfo[i].Contains("'"))
            {
              lBit9ReturnValues.FilePath += sFileInfo[i] + "\\";
            }
            else
            {
              break;
            }
          }
        }
        lBit9ReturnValues.HostName = lFidoReturnValues.Hostname;
        var lBit9Info = Detect_Bit9.GetFileInfo(null, lBit9ReturnValues);
      }
    }

    //todo: is this still necessary? should we handle this in the bit9 module?
    private static FidoReturnValues FireEyeHashToBit9(FidoReturnValues lFidoReturnValues)
    {
      //Check FireEye returns and  go to Bit9 to see if the hash exists, where and
      //if it was executed, then go to VT and pass hash info on there too
      //var lVirusTotalReturnValues = new VirusTotalReturnValues();
      List<string> sBit9FileInfo = Detect_Bit9.GetFileInfo(lFidoReturnValues.FireEye.MD5Hash, null);
      if (sBit9FileInfo.Count == 0) return lFidoReturnValues;
      if (lFidoReturnValues.Bit9 == null)
      {
        lFidoReturnValues.Bit9 = new Bit9ReturnValues {Bit9Hashes = sBit9FileInfo.ToArray()};
      }
      else
      {
        lFidoReturnValues.Bit9.Bit9Hashes = sBit9FileInfo.ToArray();
      }
      return lFidoReturnValues;
    }
  }
}
