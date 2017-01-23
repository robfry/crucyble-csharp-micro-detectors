using System.Collections.Generic;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Objects.Niddel
{
  [DataContract]
  public class Object_Niddel_Class
  {
    [DataMember]
    [JsonProperty("entries")]
    public List<NiddelAlert> Alerts { get; set; } 
  }

  [DataContract]
  public class NiddelAlert
  {
    [DataMember]
    [JsonProperty("asnumber")]
    public int ASNumber { get; set; }

    [DataMember]
    [JsonProperty("net_app")]
    public string NetApp { get; set; }

    [DataMember]
    [JsonProperty("net_src_id")]
    public string NetSrcID { get; set; }

    [DataMember]
    [JsonProperty("net_dst_port")]
    public int NetDstPort { get; set; }

    [DataMember]
    [JsonProperty("net_dst_ip")]
    public string NetDstIP { get; set; }

    [DataMember]
    [JsonProperty("matches")]
    public List<Matches> Matches { get; set; }

    [DataMember]
    [JsonProperty("agg_first")]
    public string AggFirst { get; set; }

    [DataMember]
    [JsonProperty("asname")]
    public string ASName { get; set; }

    [DataMember]
    [JsonProperty("net_l4proto")]
    public string NetL4Proto { get; set; }

    [DataMember]
    [JsonProperty("report_tags")]
    public List<object> ReportTags { get; set; }

    [DataMember]
    [JsonProperty("net_device_types")]
    public List<string> NetDeviceTypes { get; set; }

    [DataMember]
    [JsonProperty("net_src_ip")]
    public string NetSrcIP { get; set; }

    [DataMember]
    [JsonProperty("agg_count")]
    public int AggCount { get; set; }

    [DataMember]
    [JsonProperty("last_modified")]
    public string LastModified { get; set; }

    [DataMember]
    [JsonProperty("country")]
    public string Country { get; set; }

    [DataMember]
    [JsonProperty("date")]
    public string Date { get; set; }

    [DataMember]
    [JsonProperty("organization")]
    public string Organization { get; set; }

    [DataMember]
    [JsonProperty("bal_score")]
    public double BalScore { get; set; }

    [DataMember]
    [JsonProperty("agg_last")]
    public string AggLast { get; set; }

    [DataMember]
    [JsonProperty("id")]
    public int ID { get; set; }

    [DataMember]
    [JsonProperty("net_blocked")]
    public bool NetBlocked { get; set; }

    [DataMember]
    [JsonProperty("authority")]
    public string Authority { get; set; }

    [DataMember]
    [JsonProperty("SOA_email")]
    public string SOAEmail { get; set; }
    
    [DataMember]
    [JsonProperty("SOA_host")]
    public string SOAHost { get; set; }

    [DataMember]
    [JsonProperty("net_dst_ip_rdomain")]
    public string NetDstIPDrDomain { get; set; }

    [DataMember]
    [JsonProperty("net_dst_domain")]
    public string NetDstDomain { get; set; }

    [DataMember]
    [JsonProperty("net_src_ip_rdomain")]
    public string NetSrcIPrDomain { get; set; }
  }

  [DataContract]
  public class Matches
  {
    [DataMember]
    [JsonProperty("source")]
    public string Source { get; set; }

    [DataMember]
    [JsonProperty("category")]
    public string Category { get; set; }

    [DataMember]
    [JsonProperty("entity")]
    public string Entity { get; set; }

    [DataMember]
    [JsonProperty("entity_type")]
    public string EntityType { get; set; }

    [DataMember]
    [JsonProperty("notes")]
    public string Notes { get; set; }

    [DataMember]
    [JsonProperty("campaign")]
    public string Camppaign { get; set; }

  }
}
