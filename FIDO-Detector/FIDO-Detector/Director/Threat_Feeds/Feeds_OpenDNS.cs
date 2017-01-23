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
using System.Collections.Generic;
using System.Net;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Hashing;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.OpenDNS;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.Threat_Feeds
{
  class Feeds_OpenDNS
  {
    public DomainStatus GetDomainStatus(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new DomainStatus();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.domainStatus.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null)
        {
          stringreturn = stringreturn.Replace("{\"" + Domain + "\":", string.Empty);
          stringreturn = stringreturn.Remove(stringreturn.Length -1);
          odReturn = JsonConvert.DeserializeObject<DomainStatus>(stringreturn);
          odReturn.Domain = Domain;
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }
        
      return odReturn;
    }

    public List<Whois> GetWhois(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<Whois>();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.whois.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<Whois>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<BGPRoutesASN> GetBGPRoutesASN(string ASN)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<BGPRoutesASN>();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.BGPRoutesASN.Replace(@"%asn%", ASN);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<BGPRoutesASN>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<BGPRoutesIP> GetBGPRoutesIP(string DstrIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<BGPRoutesIP>();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.BGPRoutesIP.Replace(@"%dstip%", DstrIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<List<BGPRoutesIP>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<DomainsLatestTags> GetDomainsLatestTags(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<DomainsLatestTags>();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.DomainsLatestTags.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<DomainsLatestTags>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public LinkedDomains GetLinkedDomains(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new LinkedDomains();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.LinkedDomains.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<LinkedDomains>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public DomainScore GetDomainScore(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new DomainScore();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.DomainScore.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<DomainScore>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public DnsDBIP GetDnsDbip(string DstIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new DnsDBIP();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.DnsDBIP.Replace(@"%dstip%", DstIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<DnsDBIP>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public DnsDBDomain GetDnsDBDomain(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new DnsDBDomain();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.DnsDBDomain.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<DnsDBDomain>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public SecurityScore GetSecurityScore(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new SecurityScore();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.SecurityScore.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<SecurityScore>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<LatestDomains> GetLatestDomains(string DstIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<LatestDomains>();
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.apiquery.LatestDomains.Replace(@"%dstip%", DstIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(request, false);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<LatestDomains>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }
    
    private Object_Fido_OpenDNS.ApiQueries OpenDnsQueries()
    {
      var queries = new Object_Fido_OpenDNS.ApiQueries();
      const string request = @"http://127.0.0.1:5984/fido_configs/_design/threatfeeds/_view/opendns";
      var connection = (HttpWebRequest)WebRequest.Create(request);

      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(connection, false);
        if (stringreturn == null) return queries;
        queries = JsonConvert.DeserializeObject<Object_Fido_OpenDNS.ApiQueries>(stringreturn);
        }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in OpenDNS request when getting json:" + e);
      }

      return queries;
    }

  }
}
