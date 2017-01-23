using System.Collections.Generic;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.DDI
{
  [DataContract]
  class Object_DDI
  {
    [DataMember]
    [JsonProperty("entries")]
    public List<DHCPEntry> DhcpEntries { get; set; }
  }

  [DataContract]
  public class DHCPEntry
  {
    [DataMember]
    [JsonProperty("errno")]
    internal string Errno { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_vendor_id")]
    internal string DhcpLeaseVendorId { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_fingerbank_os")]
    internal string DhcpLeaseFingerbankOS { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_remote_id")]
    internal string DhcpLeaseRemoteId { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_circuit_id")]
    internal string DhcpLeasecircuit_id { get; set; }

    [DataMember]
    [JsonProperty("mac_vendor")]
    internal string MacVendor { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_id")]
    internal string DhcpLeaseId { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_addr")]
    internal string DhcpLeaseAddr { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_ip_addr")]
    internal string DhcpLeaseIpAddr { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_mac_addr")]
    internal string DhcpLeaseMACAddr { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_client_ident")]
    internal string DhcpLeaseClientIdent { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_time")]
    internal string DhcpLeaseTime { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_end_time")]
    internal string DhcpLeaseEndTime { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_period")]
    internal string DhcpLeasePeriod { get; set; }

    [DataMember]
    [JsonProperty("percent")]
    internal string Percent { get; set; }

    [DataMember]
    [JsonProperty("time_to_expire")]
    internal string TimeToExpire { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_name")]
    internal string DhcpLeaseName { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_clientname")]
    internal string DhcpLeaseClientName { get; set; }

    [DataMember]
    [JsonProperty("dhcpscope_id")]
    internal string DhcpScopeId { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_id")]
    internal string DhcpRangeId { get; set; }

    [DataMember]
    [JsonProperty("dhcplease_domain")]
    internal string DhcpLeaseDomain { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_name")]
    internal string DhcpRangeName { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_start_addr")]
    internal string DhcpRangeStartAddr { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_end_addr")]
    internal string DhcpRangeEndAddr { get; set; }

    [DataMember]
    [JsonProperty("dhcpscope_name")]
    internal string DhcpScopeName { get; set; }

    [DataMember]
    [JsonProperty("dhcpscope_size")]
    internal string DhcpScopeSize { get; set; }

    [DataMember]
    [JsonProperty("dhcp_id")]
    internal string DhcpId { get; set; }

    [DataMember]
    [JsonProperty("dhcp_name")]
    internal string DhcpName { get; set; }

    [DataMember]
    [JsonProperty("dhcp_type")]
    internal string DhcpType { get; set; }

    [DataMember]
    [JsonProperty("vdhcp_parent_id")]
    internal string VDhcpParentId { get; set; }

    [DataMember]
    [JsonProperty("vdhcp_parent_namek")]
    internal string VDhcpParentNamek { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_failover_name")]
    internal string DhcpRangeFailoverName { get; set; }

    [DataMember]
    [JsonProperty("dhcprange_class_name")]
    internal string DhcpRangeClassName { get; set; }

    [DataMember]
    [JsonProperty("dhcpscope_class_name")]
    internal string DhcpScopeClassName { get; set; }

    [DataMember]
    [JsonProperty("dhcp_class_name")]
    internal string DhcpClassName { get; set; }

    [DataMember]
    [JsonProperty("vdhcp_parent_name")]
    internal string VDhcpParentName { get; set; }

    [DataMember]
    [JsonProperty("dhcp_version")]
    internal string DhcpVersion { get; set; }

    [DataMember]
    [JsonProperty("ip_addr")]
    internal string IPAddr { get; set; }

    [DataMember]
    [JsonProperty("multistatus")]
    internal string Multistatus { get; set; }
  }
}
