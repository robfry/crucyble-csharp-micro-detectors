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
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Objects.Carbon_Black
{
  [DataContract]
  public class Object_CarbonBlack_Alert_Class
  {

    [DataContract]
    public class CarbonBlack
    {
      [DataMember]
      [JsonProperty("start")]
      public int Start { get; set; }

      [DataMember]
      [JsonProperty("total_results")]
      public int Total_Results { get; set; }

      [DataMember]
      [JsonProperty("results")]
      public List<Result> Results { get; set; }
    }

    [DataContract]
    public class Result
    {
      [DataMember]
      [JsonProperty("username")]
      public string Username { get; set; }

      [DataMember]
      [JsonProperty("alert_type")]
      public string AlertType { get; set; }

      [DataMember]
      [JsonProperty("sensor_criticality")]
      public double SensorCriticality { get; set; }

      [DataMember]
      [JsonProperty("modload_count")]
      public int ModloadCount { get; set; }

      [DataMember]
      [JsonProperty("observed_filename")]
      public List<string> ObservedFilename { get; set; }

      [DataMember]
      [JsonProperty("report_score")]
      public int ReportScore { get; set; }

      [DataMember]
      [JsonProperty("watchlist_id")]
      public string WatchlistID { get; set; }

      [DataMember]
      [JsonProperty("sensor_id")]
      public int SensorID { get; set; }

      [DataMember]
      [JsonProperty("created_time")]
      public string CreatedTime { get; set; }

      [DataMember]
      [JsonProperty("ioc_type")]
      public string IOCType { get; set; }

      [DataMember]
      [JsonProperty("watchlist_name")]
      public string WatchlistName { get; set; }

      [DataMember]
      [JsonProperty("ioc_confidence")]
      public double IOCConfidence { get; set; }

      [DataMember]
      [JsonProperty("alert_severity")]
      public double AlertSeverity { get; set; }

      [DataMember]
      [JsonProperty("crossproc_count")]
      public int CrossprocCount { get; set; }

      [DataMember]
      [JsonProperty("group")]
      public string Group { get; set; }

      [DataMember]
      [JsonProperty("hostname")]
      public string Hostname { get; set; }

      [DataMember]
      [JsonProperty("filemod_count")]
      public int FilemodCount { get; set; }

      [DataMember]
      [JsonProperty("feed_name")]
      public string FeedName { get; set; }

      [DataMember]
      [JsonProperty("netconn_count")]
      public int NetconnCount { get; set; }

      [DataMember]
      [JsonProperty("status")]
      public string Status { get; set; }

      [DataMember]
      [JsonProperty("observed_hosts")]
      public ObservedHosts ObservedHosts { get; set; }

      [DataMember]
      [JsonProperty("process_path")]
      public string ProcessPath { get; set; }

      [DataMember]
      [JsonProperty("process_name")]
      public string ProcessName { get; set; }

      [DataMember]
      [JsonProperty("process_id")]
      public string ProcessId { get; set; }

      [DataMember]
      [JsonProperty("_version_")]
      public object Version { get; set; }

      [DataMember]
      [JsonProperty("regmod_count")]
      public int RegmodCount { get; set; }

      [DataMember]
      [JsonProperty("md5")]
      public string MD5 { get; set; }

      [DataMember]
      [JsonProperty("segment_id")]
      public int SegmentID { get; set; }

      [DataMember]
      [JsonProperty("total_hosts")]
      public string TotalHosts { get; set; }

      [DataMember]
      [JsonProperty("feed_id")]
      public int FeedID { get; set; }

      [DataMember]
      [JsonProperty("os_type")]
      public string OSType { get; set; }

      [DataMember]
      [JsonProperty("childproc_count")]
      public int ChildprocCount { get; set; }

      [DataMember]
      [JsonProperty("unique_id")]
      public string UniqueID { get; set; }

      [DataMember]
      [JsonProperty("feed_rating")]
      public double FeedRating { get; set; }
    }

    [DataContract]
    public class ObservedHosts
    {
      [DataMember]
      [JsonProperty("numFound")]
      public int NumFound { get; set; }

      [DataMember]
      [JsonProperty("hostCount")]
      public int HostCount { get; set; }

      [DataMember]
      [JsonProperty("globalCount")]
      public int GlobalCount { get; set; }

      [DataMember]
      [JsonProperty("hostnames")]
      public List<Hostnames> Hostnames { get; set; }

      [DataMember]
      [JsonProperty("processCount")]
      public int ProcessCount { get; set; }

      [DataMember]
      [JsonProperty("numDocs")]
      public string NumDocs { get; set; }

      [DataMember]
      [JsonProperty("processTotal")]
      public int ProcessTotal { get; set; }
    }

    [DataContract]
    public class Hostnames
    {
      [DataMember]
      [JsonProperty("name")]
      public string Name { get; set; }

      [DataMember]
      [JsonProperty("value")]
      public int Value { get; set; }
    }
  }
}
