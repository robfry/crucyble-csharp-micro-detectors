// /*
// *
// *  Copyright 2016  Netflix, Inc.
// *
// *     Licensed under the Apache License, Version 2.0 (the "License");
// *     you may not use this file except in compliance with the License.
// *     You may obtain a copy of the License at
// *
// *         http://www.apache.org/licenses/LICENSE-2.0
// *
// *     Unless required by applicable law or agreed to in writing, software
// *     distributed under the License is distributed on an "AS IS" BASIS,
// *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// *     See the License for the specific language governing permissions and
// *     limitations under the License.
// *
// */

using System.Collections.Generic;

namespace FIDO_Detector.Fido_Support.Objects.SentinelOne
{
  public class Object_SentinelOne_Inventory_Class
  {
    public class MetaData
    {
      public string created_at { get; set; }
    }

    public class Interface
    {
      public string name { get; set; }
      public List<object> inet { get; set; }
      public List<string> inet6 { get; set; }
      public string physical { get; set; }
    }

    public class NetworkInformation
    {
      public List<Interface> interfaces { get; set; }
      public string domain { get; set; }
      public string computer_name { get; set; }
    }

    public class SoftwareInformation
    {
      public string os_name { get; set; }
      public string os_revision { get; set; }
      public string os_arch { get; set; }
      public string os_username { get; set; }
      public string os_start_time { get; set; }
      public int os_type { get; set; }
    }

    public class HardwareInformation
    {
      public int total_memory { get; set; }
      public string model_name { get; set; }
      public string machine_type { get; set; }
      public string cpu_id { get; set; }
      public int cpu_count { get; set; }
      public int core_count { get; set; }
    }

    public class Configuration
    {
      public bool learning_mode { get; set; }
      public List<string> auto_mitigation_actions { get; set; }
      public string research_data { get; set; }
    }

    public class SentinelOne
    {
      public string id { get; set; }
      public MetaData meta_data { get; set; }
      public string license_key { get; set; }
      public string uuid { get; set; }
      public string agent_version { get; set; }
      public NetworkInformation network_information { get; set; }
      public SoftwareInformation software_information { get; set; }
      public HardwareInformation hardware_information { get; set; }
      public string external_ip { get; set; }
      public string group_ip { get; set; }
      public int threat_count { get; set; }
      public string last_active_date { get; set; }
      public bool is_active { get; set; }
      public bool is_up_to_date { get; set; }
      public string network_status { get; set; }
      public string registration_date { get; set; }
      public object status { get; set; }
      public bool in_grace_period { get; set; }
      public Configuration configuration { get; set; }
      public bool is_pending_uninstall { get; set; }
      public bool acknowledge_next_uninstall_request { get; set; }
      public bool is_decommissioned { get; set; }
    } 
  }
}