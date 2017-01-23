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
namespace Fido_Main.Fido_Support.Objects.ElasticSearch
{

  public class Object_F5_VPN_Search
  {
    private Object_F5_VPN_Search(string value)
    {
      Value = value;
    }
    
    public string Value { get; set; }

    public static Object_F5_VPN_Search UserName { get { return new Object_F5_VPN_Search(@"'\w*'"); } }
    public static Object_F5_VPN_Search Common { get { return new Object_F5_VPN_Search(@":\b\w{8}\b:"); } }
    public static Object_F5_VPN_Search HostName { get { return new Object_F5_VPN_Search(@"Hostname:.+Type:"); } }
    public static Object_F5_VPN_Search ClientIP { get { return new Object_F5_VPN_Search(@"client IP \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"); } }
    public static Object_F5_VPN_Search VpnIP { get { return new Object_F5_VPN_Search(@"VIP \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"); } }
    public static Object_F5_VPN_Search Header { get { return new Object_F5_VPN_Search(@"Type:.+"); } }
    public static Object_F5_VPN_Search VpnRules { get { return new Object_F5_VPN_Search(@"Following rule .+"); } }
    public static Object_F5_VPN_Search AccessPolicy { get { return new Object_F5_VPN_Search(@"Access policy.+"); } }
    public static Object_F5_VPN_Search WebTop { get { return new Object_F5_VPN_Search(@"Webtop.+"); } }

  }
}