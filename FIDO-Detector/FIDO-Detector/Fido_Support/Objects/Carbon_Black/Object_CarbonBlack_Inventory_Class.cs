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

namespace FIDO_Detector.Fido_Support.Objects.Carbon_Black
{
  [DataContract]
  public class Object_CarbonBlack_Inventory_Class
  {

    [DataContract]
    public class CarbonBlackEntry
    {
      [DataMember]
      [JsonProperty("os_environment_display_string")]
      public string OSName { get; set; }

      [DataMember]
      [JsonProperty("supports_cblr")]
      public string SupportsCBLR { get; set; }

      [DataMember]
      [JsonProperty("last_update")]
      public DateTime LastUpdated { get; set; }

      [DataMember]
      [JsonProperty("build_id")]
      public string BuildID { get; set; }

      [DataMember]
      [JsonProperty("is_isolating")]
      public bool isIsolating { get; set; }

      [DataMember]
      [JsonProperty("computer_dns_name")]
      public string HostDNSName { get; set; }

      [DataMember]
      [JsonProperty("id")]
      public Int16 ID { get; set; }

      [DataMember]
      [JsonProperty("network_isolation_enabled")]
      public bool NetworkIsolationEnabled { get; set; }

      [DataMember]
      [JsonProperty("status")]
      public string Status { get; set; }

      [DataMember]
      [JsonProperty("sensor_health_message")]
      public string SensorHealthMessage { get; set; }

      [DataMember]
      [JsonProperty("build_version_string")]
      public string ClientVersion { get; set; }

      [DataMember]
      [JsonProperty("computer_sid")]
      public string ComputerSID { get; set; }

      [DataMember]
      [JsonProperty("next_checkin_time")]
      public DateTime NextCheckinTime { get; set; }

      [DataMember]
      [JsonProperty("node_id")]
      public short NodeID { get; set; }

      [DataMember]
      [JsonProperty("computer_name")]
      public string HostName { get; set; }

      [DataMember]
      [JsonProperty("supports_isolation")]
      public bool SupportsIso { get; set; }

      [DataMember]
      [JsonProperty("parity_host_id")]
      public string ParityHostID { get; set; }

      [DataMember]
      [JsonProperty("network_adapters")]
      public string NetworkAdapters { get; set; }

      [DataMember]
      [JsonProperty("sensor_health_status")]
      public string SensorHealthStatus { get; set; }

      [DataMember]
      [JsonProperty("restart_queued")]
      public bool RestartQueued { get; set; }

      [DataMember]
      [JsonProperty("notes")]
      public string Notes { get; set; }

      [DataMember]
      [JsonProperty("os_environment_id")]
      public string OSEnvironmentID { get; set; }

      [DataMember]
      [JsonProperty("boot_id")]
      public string BootID { get; set; }

      [DataMember]
      [JsonProperty("last_checkin_time")]
      public DateTime LastCheckinTime { get; set; }

      [DataMember]
      [JsonProperty("group_id")]
      public short GroupdID { get; set; }

      [DataMember]
      [JsonProperty("display")]
      public bool Display { get; set; }

      [DataMember]
      [JsonProperty("uninstall")]
      public bool Uninstall { get; set; }
    }
  }

}
