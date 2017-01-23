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

namespace Fido_Main.Fido_Support.Objects.ThreatGRID
{
  [DataContract]
  public class Object_ThreatGRID_Search_ConfigClass
  {
    [DataContract]
    public class ThreatGRID_Search
    {
      [DataMember]
      [JsonProperty("data")]
      internal ThreatGRID_Search_Detail Data { get; set; }

      [DataMember]
      [JsonProperty("id")]
      internal string Id { get; set; }

      [DataMember]
      [JsonProperty("api_version")]
      internal string API_Version { get; set; }
    }

    [DataContract]
    public class ThreatGRID_Search_Detail
    {
      [DataMember]
      [JsonProperty("index")]
      internal string Index { get; set; }

      [DataMember]
      [JsonProperty("current_item_count")]
      internal int CurrentItemCount { get; set; }

      [DataMember]
      [JsonProperty("items_per_page")]
      internal string ItemsPerPage { get; set; }

      [DataMember]
      [JsonProperty("items")]
      internal List<ThreatGRID_Search_Item_Detail> Items { get; set; }
    }

    [DataContract]
    [KnownType(typeof(Search_Data_NetworkStreams))]
    public class ThreatGRID_Search_Item_Detail
    {
      [DataMember]
      [JsonProperty("data")]
      internal Search_Return_NetworkStreams DataDetail { get; set; }

      [DataMember]
      [JsonProperty("relation")]
      internal string Relation { get; set; }

      [DataMember]
      [JsonProperty("ip")]
      internal string CIDR { get; set; }

      [DataMember]
      [JsonProperty("domain")]
      internal string Domain { get; set; }

      [DataMember]
      [JsonProperty("ts")]
      internal string TimeStamp { get; set; }

      [DataMember]
      [JsonProperty("sample")]
      internal string HashID { get; set; }
    }

    //public class Search_Data_Detail
    //{
    //  [JsonProperty("network-streams")]
    //  internal List<Search_Data_NetworkStreams> NetworkStreams { get; set; }

    //  [JsonProperty("queries")]
    //  internal List<Search_Data_DNS_Query> DNSQueries { get; set; }

    //  [JsonProperty("nsid")]
    //  internal int nsid { get; set; }

    //  [JsonProperty("tid")]
    //  internal int tid { get; set; }

    //  [JsonProperty("url")]
    //  internal int url { get; set; }

    //}


    public class Search_Data_NetworkStreams
    {
      [JsonProperty("src")]
      internal string SrcIP { get; set; }

      [JsonProperty("nsid")]
      internal string NSID { get; set; }

      [JsonProperty("dst_port")]
      internal string DSTPort { get; set; }

      [JsonProperty("src_port")]
      internal string SRCPort { get; set; }
    }

    public class Search_Return_NetworkStreams
    {
      [JsonProperty("network-streams")]
      internal List<Search_Data_NetworkStreams> Streams { get; set; }
    }

    [DataContract]
    public class Search_Data_DNS_Query
    {
      [DataMember]
      [JsonProperty("query")]
      internal string DNSQuery { get; set; }

      [DataMember]
      [JsonProperty("type")]
      internal string RecordType { get; set; }
    }

    [DataContract]
    public class Search_Return_Query
    {
      [DataMember]
      [JsonProperty("queries")]
      internal List<Search_Data_DNS_Query> Queries { get; set; }
    }

  }
}