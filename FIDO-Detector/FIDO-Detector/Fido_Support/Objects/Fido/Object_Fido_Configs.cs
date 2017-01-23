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
using System.Net;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Objects.Fido
{
  public static class Object_Fido_Configs
  {

    public static IEnumerable<Object_Fido_Configs_CouchDB_Detectors.Sensor> ParseCouchDetectorConfigs(string detect)
    {

      var connect = new Fido_Rest_Connection();
      var request = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_configs_detectors.detectors.detector_configs + "?key=" + '"' + detect + '"';
        //@"http://127.0.0.1:5984/fido_configs_detectors/_design/detectors/_view/detector_configs?key=" + '"' + detect + '"';
      var connection = (HttpWebRequest) WebRequest.Create(request);
      var stringreturn = connect.RestCall(connection, false);
      if (string.IsNullOrEmpty(stringreturn)) return null;
      var detectorsReturn = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_Detectors.Detector>(stringreturn);
      var sensors = new List<Object_Fido_Configs_CouchDB_Detectors.Sensor>();
      for (var i = 0; i < detectorsReturn.rows.Count; i++)
      {
        sensors.Add(detectorsReturn.rows[i].value.sensor);
      }
      return sensors;

    }

    private static Dictionary<string, string> _dict = new Dictionary<string, string>();

    //internal static void LoadConfigFromDb(string table)
    //{
    //  var fidoSQLite = new SqLiteDB();
    //  _dict = fidoSQLite.GetDataTable("select key, value from " + table).AsEnumerable().ToDictionary<DataRow, string, string>(row => row.Field<string>(0), row => row.Field<string>(1));
    //}

    public static string GetAsString(string name, string dft)
    {
      return _dict.ContainsKey(name) ? _dict[name] : dft;
    }

    public static int GetAsInt(string name, int dft)
    {
      return _dict.ContainsKey(name) ? int.Parse(_dict[name]) : dft;
    }

    //public static double GetAsDouble(string name, double dft)
    //{
    //  return _dict.ContainsKey(name) ? double.Parse(_dict[name]) : dft;
    //}

    //public static bool GetAsBool(string name, bool dft)
    //{
    //  return _dict.ContainsKey(name) ? bool.Parse(_dict[name]) : dft;
    //}

  }
}
