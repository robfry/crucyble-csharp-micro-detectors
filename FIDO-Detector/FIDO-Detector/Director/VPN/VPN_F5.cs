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

using System;
using Fido_Main.Director.SysMgmt;
using Fido_Main.Fido_Support.Objects.ElasticSearch;

namespace Fido_Main.Director.VPN
{
  public class VPN_F5
  {
    public Object_F5_VPN_Inventory ParseQueryReturn(Object_F5_VPN.ESVPN VPN)
    {
      var reVPN = new Object_F5_VPN_Inventory();

      foreach (var entry in VPN.entries.hits)
      {
        if (entry._source.message.Contains(@"01490005"))
        {
          reVPN.VpnRules = ParseVPNRules(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490128"))
        {
          reVPN.VpnWebTop = ParseWebTop(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490102"))
        {
          reVPN.AccessPolicy = ParseAccessPolicy(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490248"))
        {
          reVPN.HostName = ParseHostName(entry._source.message);
          reVPN.Header = ParseHeader(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490010"))
        {
          reVPN.UserName = ParseUserName(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490500"))
        {
          reVPN.ClientIP = ParseClientIP(entry._source.message);
          reVPN.VipIP = ParseVipIP(entry._source.message);
        }
        else if (entry._source.message.Contains(@"01490506"))
        {
          
        }
      }

      return reVPN;
    }

    private string ParseHeader(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.Header);
      return ret;
    }

    private string ParseClientIP(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.ClientIP);
      ret = ret.Replace("client IP ", string.Empty);
      return ret;
    }

    private string ParseVipIP(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.VpnIP);
      ret = ret.Replace("VIP ", string.Empty);
      return ret;
    }

    private string ParseUserName(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.UserName);
      return ret;
    }

    private string ParseHostName(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.HostName);
      ret = ret.Replace(@"Hostname: ", String.Empty).Replace(@" Type:", String.Empty);
      return ret;
    }

    private string ParseAccessPolicy(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.AccessPolicy);
      return ret;
    }

    private string ParseWebTop(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.WebTop);
      return ret;
    }

    private string ParseVPNRules(string message)
    {
      var ret = SysMgmt_ElasticSearch.ParseQueryReturn(message, Object_F5_VPN_Search.VpnRules);
      return ret;
      
    }
 
  }
}