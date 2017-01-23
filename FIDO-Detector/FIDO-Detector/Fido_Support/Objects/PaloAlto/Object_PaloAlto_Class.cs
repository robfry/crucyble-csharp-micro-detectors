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
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Objects.PaloAlto
{
  public static class Object_PaloAlto_Class
  {
    [DataContract]
    public class GetJob
    {
      [DataMember]
      [JsonProperty("result")]
      public GetResult Result { get; set; }
    }

    [DataContract]
    public class GetResult
    {
      [DataMember]
      [JsonProperty("job")]
      public string Job { get; set; }
    }

    [DataContract]
    public class PanReturn
    {
      [DataMember]
      [JsonProperty("result")]
      public Result Result { get; set; }
    }

    [DataContract]
    public class Result
    {
      [DataMember]
      [JsonProperty("log")]
      public Log Log { get; set; }
    }

    [DataContract]
    public class Log
    {
      [DataMember]
      [JsonProperty("logs")]
      public Logs Logs { get; set; }
    }

    [DataContract]
    public class Logs
    {
      [DataMember]
      [JsonProperty("entry")]
      public Entries[] Entry { get; set; }
    }

    public class Entries
    {
      [JsonProperty("@logid")]
      public string EventID { get; set; }

      [JsonProperty("domain")]
      public string domain { get; set; }

      [JsonProperty("receive_time")]
      public DateTime ReceivedTime { get; set; }

      [JsonProperty("serial")]
      public string serial { get; set; }

      [JsonProperty("seqno")]
      public string seqno { get; set; }

      [JsonProperty("actionflags")]
      public string actionflags { get; set; }
      
      [JsonProperty("type")]
      public string type { get; set; }
      
      [JsonProperty("subtype")]
      public string subtype { get; set; }
      
      [JsonProperty("config_ver")]
      public string config_ver { get; set; }
      
      [JsonProperty("time_generated")]
      public string time_generated { get; set; }
      
      [JsonProperty("src")]
      public string SrcIP { get; set; }
      
      [JsonProperty("dst")]
      public string DstIP { get; set; }
      
      [JsonProperty("dstuser")]
      public string DstUser { get; set; }
      
      [JsonProperty("natsrc")]
      public string natsrc { get; set; }
      
      [JsonProperty("natdat")]
      public string natdst { get; set; }
      
      [JsonProperty("rule")]
      public string rule { get; set; }
      
      [JsonProperty("srcloc")]
      public Location srcloc { get; set; }
      
      [JsonProperty("dstloc")]
      public Location dstloc { get; set; }
      
      [JsonProperty("app")]
      public string app { get; set; }
      
      [JsonProperty("vsys")]
      public string vsys { get; set; }
      
      [JsonProperty("from")]
      public string from { get; set; }
      
      [JsonProperty("to")]
      public string to { get; set; }
      
      [JsonProperty("inbound_if")]
      public string inbound_if { get; set; }
      
      [JsonProperty("outbound_if")]
      public string outbound_if { get; set; }
      
      [JsonProperty("logset")]
      public string logset { get; set; }
      
      [JsonProperty("time_received")]
      public string time_received { get; set; }
      
      [JsonProperty("sessionid")]
      public string sessionid { get; set; }
      
      [JsonProperty("repeatcnt")]
      public string repeatcnt { get; set; }
      
      [JsonProperty("sport")]
      public string sport { get; set; }
      
      [JsonProperty("dport")]
      public string dport { get; set; }
      
      [JsonProperty("natsport")]
      public string natsport { get; set; }
      
      [JsonProperty("natdport")]
      public string natdport { get; set; }
      
      [JsonProperty("flags")]
      public string flags { get; set; }
      
      [JsonProperty("flag-pcap")]
      public string flag_pcap { get; set; }
      
      [JsonProperty("flag-flagged")]
      public string flag_flagged { get; set; }
      
      [JsonProperty("flag-proxy")]
      public string flag_proxy { get; set; }
      
      [JsonProperty("flag-url-denied")]
      public string flag_url_denied { get; set; }
      
      [JsonProperty("flag-nat")]
      public string flag_nat { get; set; }
      
      [JsonProperty("captive-portal")]
      public string captive_portal { get; set; }
      
      [JsonProperty("non-std-dport")]
      public string non_std_dport { get; set; }
      
      [JsonProperty("transaction")]
      public string transaction { get; set; }
      
      [JsonProperty("pbf_c2s")]
      public string pbf_c2s { get; set; }
      
      [JsonProperty("pbf_s2c")]
      public string pbf_s2c { get; set; }
      
      [JsonProperty("temporary_match")]
      public string temporary_match { get; set; }
      
      [JsonProperty("sym_return")]
      public string sym_return { get; set; }
      
      [JsonProperty("decrypt_mirror")]
      public string decrypt_mirror { get; set; }
      
      [JsonProperty("pktlog")]
      public string pktlog { get; set; }
      
      [JsonProperty("proto")]
      public string proto { get; set; }
      
      [JsonProperty("action")]
      public string action { get; set; }
      
      [JsonProperty("cpadding")]
      public string cpadding { get; set; }
      
      [JsonProperty("dg_hier_level_1")]
      public string dg_hier_level_1 { get; set; }
      
      [JsonProperty("dg_hier_level_2")]
      public string dg_hier_level_2 { get; set; }
      
      [JsonProperty("dg_hier_level_3")]
      public string dg_hier_level_3 { get; set; }
      
      [JsonProperty("dg_hier_level_4")]
      public string dg_hier_level_4 { get; set; }
      
      [JsonProperty("device_name")]
      public string device_name { get; set; }
      
      [JsonProperty("vsys_id")]
      public string vsys_id { get; set; }
      
      [JsonProperty("threatid")]
      public string threatid { get; set; }
      
      [JsonProperty("tid")]
      public string tid { get; set; }
      
      [JsonProperty("reportid")]
      public string reportid { get; set; }
      
      [JsonProperty("category")]
      public string category { get; set; }
      
      [JsonProperty("severity")]
      public string severity { get; set; }
      
      [JsonProperty("direction")]
      public string direction { get; set; }
      
      [JsonProperty("url_idx")]
      public string url_idx { get; set; }
      
      [JsonProperty("padding")]
      public string padding { get; set; }

      [JsonProperty("pcap_id")]
      public string pcap_id { get; set; }
    }

    public class RootObject
    {
      public string status { get; set; }
      public Result result { get; set; }

    }

    public class Location
    {
      public string code { get; set; }
      public string cc { get; set; }
      public string text { get; set; }
    }

  }

}
