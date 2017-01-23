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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Fido_Support.FidoDB
{
  internal static class Fido_UpdateDB
  {
    public static void InsertEventToDB(FidoReturnValues lFidoReturnValues)
    {
      var iKeepAlive = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select unknownkeepalive from configs_application"));
      var db = new SqLiteDB();
      var data = new Dictionary<String, String>
      {
        {"timer", iKeepAlive.ToString(CultureInfo.InvariantCulture)},
        {"ip_address", lFidoReturnValues.SrcIP},
        {"hostname", lFidoReturnValues.Hostname.ToLower()},
        {"timestamp", Convert.ToDateTime(lFidoReturnValues.TimeOccured).ToString(CultureInfo.InvariantCulture)},
        {"previous_score", lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture)},
        {"alert_id", lFidoReturnValues.AlertID}
      };

      try
      {
        //insert event to primary alert table
        db.Insert("event_alerts", data);
        const string eventAlerts = @"select count() from event_alerts";
        var newRow = db.ExecuteScalar(eventAlerts);

        ////if there is threat data then insert otherwise
        ////todo: figure out a better way to find out if a detector is empty
        //if (lFidoReturnValues.Bit9 != null | lFidoReturnValues.Antivirus != null | lFidoReturnValues.FireEye != null |
        //    lFidoReturnValues.Cyphort != null | lFidoReturnValues.ProtectWise != null | lFidoReturnValues.PaloAlto != null |
        //    lFidoReturnValues.Niddel != null)
        //{
        //  UpdateThreatToDB(lFidoReturnValues, newRow);
        //}

        ////if there is machine data then insert otherwise
        //if ((lFidoReturnValues.Inventory.Landesk != null) | (lFidoReturnValues.Inventory.Jamf != null))
        //{
        //  UpdateMachineToDB(lFidoReturnValues, newRow);
        //}

        ////if there is user data then insert otherwise
        //if (lFidoReturnValues.UserInfo != null)
        //{
        //  UpdateUserToDB(lFidoReturnValues, newRow);
        //}


        ////if there is detailed threat data insert


        //if there is histiorical url data insert
        UpdateHistoricalURLInfo(lFidoReturnValues);
        UpdateHistoricalHashInfo(lFidoReturnValues);
        UpdateHistoricalIPInfo(lFidoReturnValues);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in insert of event alert to fidodb:" + e);
      }

    }

    private static void UpdateUserToDB(FidoReturnValues lFidoReturnValues, string row)
    {
      var db = new SqLiteDB();
      var data = new Dictionary<String, String>
      {
        {"username", lFidoReturnValues.Username.ToLower()},
        {"fullname", lFidoReturnValues.UserInfo.Username.ToLower()},
        {"email", lFidoReturnValues.UserInfo.UserEmail.ToLower()},
        {"title", lFidoReturnValues.UserInfo.Title.ToLower()},
        {"dept", lFidoReturnValues.UserInfo.Department.ToLower()},
        {"emp_type", lFidoReturnValues.UserInfo.EmployeeType.ToLower()},
        {"emp_phone", lFidoReturnValues.UserInfo.MobileNumber},
        {"cube", lFidoReturnValues.UserInfo.CubeLocation.ToLower()},
        {"city_state", lFidoReturnValues.UserInfo.City.ToLower() + "\\" + lFidoReturnValues.UserInfo.State.ToLower()},
        {"manager", lFidoReturnValues.UserInfo.ManagerName.ToLower()},
        {"manager_title", lFidoReturnValues.UserInfo.ManagerTitle.ToLower()},
        {"manager_email", lFidoReturnValues.UserInfo.ManagerMail.ToLower()},
        {"manager_phone", lFidoReturnValues.UserInfo.MobileNumber},
        {"user_score", lFidoReturnValues.UserScore.ToString(CultureInfo.InvariantCulture)}
      };

      try
      {
        db.Update("event_user", data, "primkey = " + row);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in update user area of fidodb:" + e);
      }

    }

    private static void UpdateMachineToDB(FidoReturnValues lFidoReturnValues, string row)
    {
      var db = new SqLiteDB();
      try
      {

        if (lFidoReturnValues.Inventory.Landesk != null)
        {
          var data = new Dictionary<String, String>
          {
            {"hostname", lFidoReturnValues.Hostname.ToLower()},
            {"os", lFidoReturnValues.Inventory.Landesk.OSName.ToLower()},
            {"os_version", lFidoReturnValues.Inventory.Landesk.OSVersion.ToLower()},
            {"os_build", lFidoReturnValues.Inventory.Landesk.OSBuild.ToLower()},
            {"type", lFidoReturnValues.Inventory.Landesk.Type.ToLower()},
            {"domain", lFidoReturnValues.Inventory.Landesk.Domain.ToLower()},
            {"patches_critical", lFidoReturnValues.Inventory.Landesk.Patches[0].ToString(CultureInfo.InvariantCulture)},
            {"patches_high", lFidoReturnValues.Inventory.Landesk.Patches[1].ToString(CultureInfo.InvariantCulture)},
            {"patches_low", lFidoReturnValues.Inventory.Landesk.Patches[2].ToString(CultureInfo.InvariantCulture)},
            //{"av_installed", lFidoReturnValues.Inventory.Landesk.Product.ToLower()},
            //{"av_running", lFidoReturnValues.Inventory.Landesk.AgentRunning.ToLower()},
            //{"av_def_ver", lFidoReturnValues.Inventory.Landesk.DefInstallDate.ToLower()},
            {"cb_version", lFidoReturnValues.Inventory.Landesk.CBVersion},
            {"cb_running", lFidoReturnValues.Inventory.Landesk.CBRunning.ToLower()},
            {"sentinel_version", lFidoReturnValues.Inventory.Landesk.SentinelVersion.ToLower()},
            {"sentinel_running", lFidoReturnValues.Inventory.Landesk.SentinelRunning.ToLower()},
            {"has_battery", lFidoReturnValues.Inventory.Landesk.Battery.ToLower()},
            {"chassis_type", lFidoReturnValues.Inventory.Landesk.ChassisType.ToLower()},
            {"last_update", lFidoReturnValues.Inventory.Landesk.LastUpdate.ToLower()},
            {"machine_score", lFidoReturnValues.MachineScore.ToString(CultureInfo.InvariantCulture)},
            {"computer_idn", lFidoReturnValues.Inventory.Landesk.ComputerIDN.ToLower()}
          };

          db.Update("event_machine", data, "primkey = " + row);
        }
        else if (lFidoReturnValues.Inventory.Jamf != null)
        {
          var data = new Dictionary<String, String>
          {
            {"hostname", lFidoReturnValues.Hostname.ToLower()},
            {"os", lFidoReturnValues.Inventory.Jamf.Hardware.Os_name + " " + lFidoReturnValues.Inventory.Jamf.Hardware.Os_version},
            {"domain", string.Empty},
            {"patches_critical", string.Empty},
            {"patches_high", string.Empty},
            {"patches_low", string.Empty},
            {"av_installed", string.Empty},
            {"av_running", string.Empty},
            {"av_def_ver", string.Empty},
            {"machine_score", lFidoReturnValues.MachineScore.ToString(CultureInfo.InvariantCulture)}
          };

          db.Update("event_machine", data, "primkey = " + row);
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in update machine area of fidodb:" + e);
      }
    }

    private static void UpdateThreatToDB(FidoReturnValues lFidoReturnValues, string row)
    {
      var db = new SqLiteDB();
      var detector = lFidoReturnValues.CurrentDetector;
      var data = new Dictionary<String, String>
      {
        //{"threat_dst_ip", lFidoReturnValues.DstIP},
        {"threat_name", lFidoReturnValues.MalwareType.ToLower()},
        {"threat_score", lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture)},
        {"detector", lFidoReturnValues.CurrentDetector.ToLower()},
        {"threat_url", lFidoReturnValues.BadUrLs.ToString(CultureInfo.InvariantCulture)},
        {"threat_hash", lFidoReturnValues.BadHashs.ToString(CultureInfo.InvariantCulture)}
      };

      switch (detector)
      {
        case "mps":
          data.Add("time_occurred", lFidoReturnValues.FireEye.EventTime);
          break;
        case "bit9":
          //todo: Fido.db does not have a column for filename... legacy? still needed?
          //data.Add("file_name", lFidoReturnValues.Bit9.FileName);
          break;
        case "antivirus":
          data.Add("time_occurred", lFidoReturnValues.Antivirus.EventTime);
          data.Add("action_taken", lFidoReturnValues.Antivirus.ActionTaken);
          data.Add("file_name", lFidoReturnValues.Antivirus.FileName);
          data.Add("threat_status", lFidoReturnValues.Antivirus.Status);
          break;
        case "cyphortv2":
          data.Add("time_occurred", lFidoReturnValues.Cyphort.EventTime);
          break;
        case "cyphort":
          data.Add("time_occurred", lFidoReturnValues.Cyphort.EventTime);
          break;
        case "protectwise":
          data.Add("time_occurred", lFidoReturnValues.ProtectWise.EventTime);
          break;
        case "pan":
          data.Add("time_occurred", lFidoReturnValues.PaloAlto.EventTime);
          break;
        case "carbonblack":
          data.Add("time_occurred", lFidoReturnValues.CB.Alert.EventTime);
          break;
        case "niddel":
          data.Add("time_occurred", lFidoReturnValues.Niddel.EventTime);
          break;
      }
      db.Update("event_threat", data, "primkey = " + row);
    }

    private static void UpdateDetailedThreatToDB(FidoReturnValues lFidoReturnValues, string row)
    {
      //todo: figure out best way to insert detailed reports to prevent having to query web services again
      //var threatURL = lFidoReturnValues.FireEye.URL.Aggregate(string.Empty, (current, url) => current + (url + ","));
      //threatURL = lFidoReturnValues.FireEye.ChannelHost.Aggregate(threatURL, (current, link) => current + (link + ","));
      //data.Add("threat_url", threatURL);
      //var threatMD5 = lFidoReturnValues.FireEye.MD5Hash.Aggregate(string.Empty, (current, md5) => current + (md5 + ","));
      //data.Add("threat_hash", threatMD5);
    }

    private static void InsertHistoricalThreatToDB(string sdb, string invalue, string timedate)
    {
      var db = new SqLiteDB();
      var data = new Dictionary<String, String>
      {
        { sdb, invalue },
        { "timedate", timedate}
      };
      sdb = @"previous_threat_" + sdb;
      //db.Insert("previous_threat_url", data);
      db.Insert(sdb, data);
    }

    private static void UpdateHistoricalURLInfo(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        if (lFidoReturnValues.Url != null)
        {
          foreach (var url in lFidoReturnValues.Url.Where(url => !string.IsNullOrEmpty(url)))
          {
            InsertHistoricalThreatToDB(@"url", url, lFidoReturnValues.TimeOccured.ToString());
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in update of historicaal URL info in fidodb:" + e);
      }
    }

    private static void UpdateHistoricalHashInfo(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        if (lFidoReturnValues.Hash != null)
        {
          foreach (var hash in lFidoReturnValues.Hash.Where(hash => !string.IsNullOrEmpty(hash)))
          {
            InsertHistoricalThreatToDB(@"hash", hash, lFidoReturnValues.TimeOccured.ToString());
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in update of historical hash info in fidodb:" + e);
      }
    }

    private static void UpdateHistoricalIPInfo(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        if (!lFidoReturnValues.DstIP.Contains(null))
        {
          //InsertHistoricalThreatToDB(@"ip", lFidoReturnValues.DstIP, lFidoReturnValues.TimeOccured.ToString());
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in update of historical IP info in fidodb:" + e);
      }
    }
  }
}
