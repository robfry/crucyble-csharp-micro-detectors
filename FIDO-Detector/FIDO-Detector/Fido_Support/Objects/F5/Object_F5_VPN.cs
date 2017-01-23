using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.ElasticSearch
{
  public class Object_F5_VPN
  {
    public class ESVPN
    {
      [JsonProperty("took")]
      public int took { get; set; }

      [JsonProperty("timed_out")]
      public bool timed_out { get; set; }

      [JsonProperty("_shards")]
      public Shards _shards { get; set; }

      [JsonProperty("hits")]
      public Hits entries { get; set; }
    }

    public class Shards
    {
      [JsonProperty("total")]
      public int total { get; set; }

      [JsonProperty("successful")]
      public int successful { get; set; }

      [JsonProperty("failed")]
      public int failed { get; set; }
    }

    public class Source
    {
      [JsonProperty("message")]
      public string message { get; set; }
      
      [JsonProperty("@version")]
      public string es_version { get; set; }
      
      [JsonProperty("@timestamp")]
      public DateTime es_timestamp { get; set; }

      [JsonProperty("host")]
      public string host { get; set; }

      //[JsonProperty("type")]
      //public object type { get; set; }

      [JsonProperty("CW_collector_cluster")]
      public string CW_collector_cluster { get; set; }

      [JsonProperty("CW_collector_node")]
      public string CW_collector_node { get; set; }

      [JsonProperty("tags")]
      public List<string> tags { get; set; }

      [JsonProperty("CW_indexer_cluster")]
      public string CW_indexer_cluster { get; set; }

      [JsonProperty("CW_indexer_node")]
      public string CW_indexer_node { get; set; }

      [JsonProperty("syslog_pri")]
      public string syslog_pri { get; set; }

      [JsonProperty("syslog_timestamp")]
      public string syslog_timestamp { get; set; }

      [JsonProperty("vpnhost")]
      public string vpnhost { get; set; }

      [JsonProperty("session")]
      public string session { get; set; }

      [JsonProperty("hostname")]
      public string hostname { get; set; }

      [JsonProperty("os")]
      public string os { get; set; }

      [JsonProperty("cpu")]
      public string cpu { get; set; }

      [JsonProperty("javascript")]
      public string javascript { get; set; }

      [JsonProperty("activex")]
      public string activex { get; set; }

      [JsonProperty("plugin")]
      public string plugin { get; set; }
      
      [JsonProperty("timestamp")]
      public string timestamp { get; set; }

      [JsonProperty("logsource")]
      public string logsource { get; set; }
    }

    public class Hit
    {
      [JsonProperty("_index")]
      public string _index { get; set; }

      [JsonProperty("_type")]
      public string _type { get; set; }

      [JsonProperty("_id")]
      public string _id { get; set; }

      [JsonProperty("_score")]
      public string _score { get; set; }

      [JsonProperty("_source")]
      public Source _source { get; set; }
    }

    public class Hits
    {
      [JsonProperty("total")]
      public int total { get; set; }

      [JsonProperty("max_score")]
      public string max_score { get; set; }

      [JsonProperty("hits")]
      public List<Hit> hits { get; set; }
    }

  }
}
