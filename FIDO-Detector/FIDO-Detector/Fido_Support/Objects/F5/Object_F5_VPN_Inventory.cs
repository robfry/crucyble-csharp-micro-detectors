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

using System.Runtime.Serialization;

namespace Fido_Main.Fido_Support.Objects.ElasticSearch
{
  [DataContract]
  public class Object_F5_VPN_Inventory
  {
    [DataMember]
    public string ClientIP { get; set; }
    [DataMember]
    public string VipIP { get; set; }
    [DataMember]
    public string HostName { get; set; }
    [DataMember]
    public string UserName { get; set; }
    [DataMember]
    public string Common { get; set; }
    [DataMember]
    public string Header { get; set; }
    [DataMember]
    public string VpnRules { get; set; }
    [DataMember]
    public string VpnWebTop { get; set; }
    [DataMember]
    public string AccessPolicy { get; set; }
    [DataMember]
    public string OsInfo { get; set; }
    [DataMember]
    public string RegionInfo { get; set; }
    
  }
}