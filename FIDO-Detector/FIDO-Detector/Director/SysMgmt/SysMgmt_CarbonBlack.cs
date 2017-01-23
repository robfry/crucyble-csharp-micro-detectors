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
using System.Data;
using System.Net;
using System.Threading;
using FIDO_Detector.Fido_Support.API_Endpoints;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Objects.Carbon_Black;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Director.SysMgmt
{
  public class SysMgmt_CarbonBlack
  {
    public static Object_CarbonBlack_Inventory_Class.CarbonBlackEntry GetCarbonBlackHost(string Hostname, string SrcIP, bool isHostname)
    {
      Console.WriteLine(@"Gathering inventory data from Carbon Black.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var parseConfigs = new CBConfigs();
      parseConfigs = GetCBConfigs();
      var request = isHostname ? parseConfigs.rows[0].value.configs.server + parseConfigs.rows[0].value.configs.query.hostname + Hostname : parseConfigs.rows[0].value.configs.server + parseConfigs.rows[0].value.configs.query.ip + SrcIP;

      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Headers[@"X-Auth-Token"] = parseConfigs.rows[0].value.configs.token;
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        Thread.Sleep(500);
        if (stringreturn == "[]") return null;
        var cbTempReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Inventory_Class.CarbonBlackEntry[]>(stringreturn);
        var cbLastRun = cbTempReturn[0].LastUpdated;
        var cbReturn = new Object_CarbonBlack_Inventory_Class.CarbonBlackEntry();
        foreach (var entry in cbTempReturn)
        {
          if (entry.LastUpdated >= cbLastRun)
          {
            cbReturn = entry;
          }
        }
        Console.WriteLine(@"Finished retrieving CB inventory.");
        return cbReturn;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black sysmgmt area:" + e);
      }

      return null;
    }

    public static Object_CarbonBlack_Inventory_Class.CarbonBlackEntry GetCarbonBlackHost(string ID)
    {
      Console.WriteLine(@"Gathering inventory data from Carbon Black.");
      //currently needed to bypass site without a valid cert.
      //todo: make ssl bypass configurable
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var parseConfigs = new CBConfigs();
      parseConfigs = GetCBConfigs();
      //parseConfigs = ParseDetectorConfigs("get_host_by_name");
      var request = parseConfigs.rows[0].value.configs.server + parseConfigs.rows[0].value.configs.query.id + ID;

      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Headers[@"X-Auth-Token"] = parseConfigs.rows[0].value.configs.token;
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        Thread.Sleep(500);
        if ((stringreturn == "[]") | (stringreturn == null)) return null;
        var cbReturn = JsonConvert.DeserializeObject<Object_CarbonBlack_Inventory_Class.CarbonBlackEntry>(stringreturn);
        Console.WriteLine(@"Finished retrieving CB inventory.");
        return cbReturn;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Carbon Black sysmgmt area:" + e);
      }

      return null;
    }

    //private static ParseCBConfigs ParseDetectorConfigs(string detect)
    //{
    //  //todo: move this to the database, assign a variable to 'detect' and replace being using in GEtFidoConfigs
    //  var query = @"SELECT * from configs_sysmgmt_carbonblack WHERE api_call = '" + detect + @"'";

    //  var fidoSQlite = new SqLiteDB(); 
    //  var fidoData = new DataTable();
    //  var cbReturn = new ParseCBConfigs();
    //  try
    //  {
    //    fidoData = fidoSQlite.GetDataTable(query);
    //    cbReturn = CBConfigs(fidoData);
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
    //  }
    //  return cbReturn;
    //}

    private static CBConfigs GetCBConfigs()
    {
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_sysmgmt.sysmgmt.vendors + "?key=\"carbonblack\"";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new CBConfigs();
      var getREST = new Fido_Rest_Connection();
      stringreturn = getREST.RestCall(alertRequest, false);
      cdbReturn = JsonConvert.DeserializeObject<CBConfigs>(stringreturn);
      return cdbReturn;
    }

    public class CBConfigs
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Query
      {
        public string ip { get; set; }
        public string hostname { get; set; }
        public string sensor { get; set; }
        public string id { get; set; }
      }

      public class Configs
      {
        public string server { get; set; }
        public string token { get; set; }
        public Query query { get; set; }
      }

      public class Value
      {
        public string _id { get; set; }
        public string _rev { get; set; }
        public int type { get; set; }
        public int server { get; set; }
        public string label { get; set; }
        public string vendor { get; set; }
        public Configs configs { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Value value { get; set; }
      }


    }

    //private static ParseCBConfigs CBConfigs(DataTable cbData)
    //{
    //  try
    //  {
    //    var reformat = new ParseCBConfigs
    //    {
    //      APIKey = Convert.ToString(cbData.Rows[0].ItemArray[1]),
    //      BaseURL = Convert.ToString(cbData.Rows[0].ItemArray[2]),
    //      APICall = Convert.ToString(cbData.Rows[0].ItemArray[3]),
    //      APIFunction = Convert.ToString(cbData.Rows[0].ItemArray[4]),
    //      APIQuery = Convert.ToString(cbData.Rows[0].ItemArray[5])
    //    };

    //    return reformat;
    //  }
    //  catch (Exception e)
    //  {
    //    Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
    //  }
    //  return null;
    //}

    private class ParseCBConfigs
    {
      internal string APIKey { get; set; }
      internal string BaseURL { get; set; }
      internal string APICall { get; set; }
      internal string APIFunction { get; set; }
      internal string APIQuery { get; set; }
    }
  }
}
