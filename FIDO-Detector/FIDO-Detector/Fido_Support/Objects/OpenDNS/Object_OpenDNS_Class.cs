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

namespace FIDO_Detector.Fido_Support.Objects.OpenDNS
{
  [DataContract]
  public class OpenDNS
  {
    [DataMember]
    public List<DomainStatus> DomainStatus { get; set; }
    [DataMember]
    public List<Whois> Whois { get; set; }
    [DataMember]
    public List<BGPRoutesASN> BgpRoutesAsn { get; set; }
    [DataMember]
    public List<BGPRoutesIP> BgpRoutesIP { get; set; }
    [DataMember]
    public List<DomainsLatestTags> DomainsLatestTags { get; set; }
    [DataMember]
    public List<LinkedDomains> LinkedDomains { get; set; }
    [DataMember]
    public List<DomainScore> DomainScore { get; set; }
    [DataMember]
    public List<DnsDBIP> DnsDbip { get; set; }
    [DataMember]
    public List<DnsDBDomain> DnsDBDomain { get; set; }
    [DataMember]
    public List<SecurityScore> SecurityScore { get; set; }
    [DataMember]
    public List<LatestDomains> LatestDomains { get; set; }
  }

  [DataContract]
  public class DomainStatus
  {
    [DataMember]
    internal string Domain { get; set; }
    [DataMember]
    [JsonProperty("status")]
    internal string Status { get; set; }

    [DataMember]
    [JsonProperty("security_categories")]
    internal List<string> SecurityCategories { get; set; }

    [DataMember]
    [JsonProperty("content_categories")]
    internal List<string> ContentCategories { get; set; }

  }

  [DataContract]
  public class Whois
  {
    [DataMember]
    public object administrativeContactFax { get; set; }
    [DataMember]
    public string whoisServers { get; set; }
    [DataMember]
    public List<string> addresses { get; set; }
    [DataMember]
    public string administrativeContactName { get; set; }
    [DataMember]
    public string zoneContactEmail { get; set; }
    [DataMember]
    public string billingContactFax { get; set; }
    [DataMember]
    public string administrativeContactTelephoneExt { get; set; }
    [DataMember]
    public string administrativeContactEmail { get; set; }
    [DataMember]
    public string technicalContactEmail { get; set; }
    [DataMember]
    public string technicalContactFax { get; set; }
    [DataMember]
    public List<string> nameServers { get; set; }
    [DataMember]
    public string zoneContactName { get; set; }
    [DataMember]
    public string billingContactPostalCode { get; set; }
    [DataMember]
    public string zoneContactFax { get; set; }
    [DataMember]
    public string registrantTelephoneExt { get; set; }
    [DataMember]
    public string zoneContactFaxExt { get; set; }
    [DataMember]
    public string technicalContactTelephoneExt { get; set; }
    [DataMember]
    public string billingContactCity { get; set; }
    [DataMember]
    public List<object> zoneContactStreet { get; set; }
    [DataMember]
    public string created { get; set; }
    [DataMember]
    public string administrativeContactCity { get; set; }
    [DataMember]
    public string registrantName { get; set; }
    [DataMember]
    public string zoneContactCity { get; set; }
    [DataMember]
    public string domainName { get; set; }
    [DataMember]
    public string zoneContactPostalCode { get; set; }
    [DataMember]
    public string administrativeContactFaxExt { get; set; }
    [DataMember]
    public string technicalContactCountry { get; set; }
    [DataMember]
    public string registrarIANAID { get; set; }
    [DataMember]
    public string updated { get; set; }
    [DataMember]
    public List<string> administrativeContactStreet { get; set; }
    [DataMember]
    public string billingContactEmail { get; set; }
    [DataMember]
    public List<string> status { get; set; }
    [DataMember]
    public string registrantCity { get; set; }
    [DataMember]
    public string billingContactCountry { get; set; }
    [DataMember]
    public string expires { get; set; }
    [DataMember]
    public List<object> technicalContactStreet { get; set; }
    [DataMember]
    public string registrantOrganization { get; set; }
    [DataMember]
    public List<object> billingContactStreet { get; set; }
    [DataMember]
    public string registrarName { get; set; }
    [DataMember]
    public string registrantPostalCode { get; set; }
    [DataMember]
    public string zoneContactTelephone { get; set; }
    [DataMember]
    public string registrantEmail { get; set; }
    [DataMember]
    public string technicalContactFaxExt { get; set; }
    [DataMember]
    public string technicalContactOrganization { get; set; }
    [DataMember]
    public List<string> emails { get; set; }
    [DataMember]
    public List<string> registrantStreet { get; set; }
    [DataMember]
    public string technicalContactTelephone { get; set; }
    [DataMember]
    public string technicalContactState { get; set; }
    [DataMember]
    public string technicalContactCity { get; set; }
    [DataMember]
    public string registrantFax { get; set; }
    [DataMember]
    public string registrantCountry { get; set; }
    [DataMember]
    public string billingContactFaxExt { get; set; }
    [DataMember]
    public object timestamp { get; set; }
    [DataMember]
    public string zoneContactOrganization { get; set; }
    [DataMember]
    public string administrativeContactCountry { get; set; }
    [DataMember]
    public string billingContactName { get; set; }
    [DataMember]
    public string registrantState { get; set; }
    [DataMember]
    public string registrantTelephone { get; set; }
    [DataMember]
    public string administrativeContactState { get; set; }
    [DataMember]
    public string registrantFaxExt { get; set; }
    [DataMember]
    public string technicalContactPostalCode { get; set; }
    [DataMember]
    public string zoneContactTelephoneExt { get; set; }
    [DataMember]
    public string administrativeContactOrganization { get; set; }
    [DataMember]
    public string billingContactTelephone { get; set; }
    [DataMember]
    public string billingContactTelephoneExt { get; set; }
    [DataMember]
    public string zoneContactState { get; set; }
    [DataMember]
    public string administrativeContactTelephone { get; set; }
    [DataMember]
    public string billingContactOrganization { get; set; }
    [DataMember]
    public string technicalContactName { get; set; }
    [DataMember]
    public string administrativeContactPostalCode { get; set; }
    [DataMember]
    public string zoneContactCountry { get; set; }
    [DataMember]
    public string billingContactState { get; set; }
    [DataMember]
    public string auditUpdatedDate { get; set; }
    [DataMember]
    public bool recordExpired { get; set; }
    [DataMember]
    public long? timeOfLatestRealtimeCheck { get; set; }
    [DataMember]
    public bool hasRawText { get; set; }
  }

  [DataContract]
  public class BGPRoutesASN
  {
    [DataMember]  
    public string cidr { get; set; }
    [DataMember]
    public Geo geo { get; set; }

    [DataContract]
    public class Geo
    {
      [DataMember]
      public string country_name { get; set; }
      [DataMember]
      public int country_code { get; set; }
    }

  }

  [DataContract]
  public class BGPRoutesIP
  {
    [DataMember]
    public string cidr { get; set; }
    [DataMember]
    public int asn { get; set; }
    [DataMember]
    public int ir { get; set; }
    [DataMember]
    public string description { get; set; }
    [DataMember]
    public string creation_date { get; set; }
  }

  [DataContract]
  public class DomainsLatestTags
  {
    [DataMember]
    public Period period { get; set; }
    [DataMember]
    public string category { get; set; }
    [DataMember]
    public object url { get; set; }

    [DataContract]
    public class Period
    {
      [DataMember]
      public string begin { get; set; }
      //todo: comeback and figure out why this is erroring 
      //when writing to ES.
      //[DataMember]
      public string end { get; set; }
    }

  }

  [DataContract]
  public class LinkedDomains
  {
    [DataMember]
    public List<List<object>> tb1 { get; set; }
    [DataMember]
    public bool found { get; set; }
  }

  [DataContract]
  public class DomainScore
  {
    [DataMember]
    public string score { get; set; }
  }

  [DataContract]
  public class DnsDBIP
  {
    [DataMember]
    public List<Rr> rrs { get; set; }
    [DataMember]
    public Features features { get; set; }

    public class Rr
    {
      [DataMember]
      public string rr { get; set; }
      [DataMember]
      public int ttl { get; set; }
      [DataMember]
      public string @class { get; set; }
      [DataMember]
      public string type { get; set; }
      [DataMember]
      public string name { get; set; }
    }
    public class Features
    {
      [DataMember]
      public int rr_count { get; set; }
      [DataMember]
      public int ld2_count { get; set; }
      [DataMember]
      public int ld3_count { get; set; }
      [DataMember]
      public int ld2_1_count { get; set; }
      [DataMember]
      public int ld2_2_count { get; set; }
      [DataMember]
      public double div_ld2 { get; set; }
      [DataMember]
      public double div_ld3 { get; set; }
      [DataMember]
      public double div_ld2_1 { get; set; }
      [DataMember]
      public double div_ld2_2 { get; set; }
    }
  }

  [DataContract]
  public class DnsDBDomain
  {
    [DataMember]
    public List<RrsTf> rrs_tf { get; set; }
    [DataMember]
    public Features features { get; set; }

    [DataContract]
    public class Rr
    {
      [DataMember]
      public string name { get; set; }
      [DataMember]
      public int ttl { get; set; }
      [DataMember]
      public string @class { get; set; }
      [DataMember]
      public string type { get; set; }
      [DataMember]
      public string rr { get; set; }
    }

    [DataContract]
    public class RrsTf
    {
      [DataMember]
      public string first_seen { get; set; }
      [DataMember]
      public string last_seen { get; set; }
      [DataMember]
      public List<Rr> rrs { get; set; }
    }

    [DataContract]
    public class Location
    {
      [DataMember]
      public double lat { get; set; }
      [DataMember]
      public double lon { get; set; }
    }

    [DataContract]
    public class Features
    {
      [DataMember]
      public int age { get; set; }
      [DataMember]
      public int ttls_min { get; set; }
      [DataMember]
      public int ttls_max { get; set; }
      [DataMember]
      public double ttls_mean { get; set; }
      [DataMember]
      public double ttls_median { get; set; }
      [DataMember]
      public double ttls_stddev { get; set; }
      [DataMember]
      public List<string> country_codes { get; set; }
      [DataMember]
      public int country_count { get; set; }
      [DataMember]
      public List<string> asns { get; set; }
      [DataMember]
      public int asns_count { get; set; }
      [DataMember]
      public List<string> prefixes { get; set; }
      [DataMember]
      public int prefixes_count { get; set; }
      [DataMember]
      public int rips { get; set; }
      [DataMember]
      public double div_rips { get; set; }
      [DataMember]
      public List<Location> locations { get; set; }
      [DataMember]
      public int locations_count { get; set; }
      [DataMember]
      public double geo_distance_sum { get; set; }
      [DataMember]
      public double geo_distance_mean { get; set; }
      [DataMember]
      public bool non_routable { get; set; }
      [DataMember]
      public bool mail_exchanger { get; set; }
      [DataMember]
      public bool cname { get; set; }
      [DataMember]
      public bool ff_candidate { get; set; }
      [DataMember]
      public double rips_stability { get; set; }
      [DataMember]
      public string base_domain { get; set; }
      [DataMember]
      public bool is_subdomain { get; set; }
    }
  }

  [DataContract]
  public class SecurityScore
  {
    [DataMember]
    public double dga_score { get; set; }
    [DataMember]
    public double perplexity { get; set; }
    [DataMember]
    public double entropy { get; set; }
    [DataMember]
    public double securerank2 { get; set; }
    [DataMember]
    public double pagerank { get; set; }
    [DataMember]
    public double asn_score { get; set; }
    [DataMember]
    public double prefix_score { get; set; }
    [DataMember]
    public double rip_score { get; set; }
    [DataMember]
    public double popularity { get; set; }
    [DataMember]
    public bool fastflux { get; set; }
    [DataMember]
    public List<List<object>> geodiversity { get; set; }
    [DataMember]
    public List<List<object>> geodiversity_normalized { get; set; }
    [DataMember]
    public List<List<object>> tld_geodiversity { get; set; }
    [DataMember]
    public double geoscore { get; set; }
    [DataMember]
    public double ks_test { get; set; }
    [DataMember]
    public Handlings handlings { get; set; }
    [DataMember]
    public string attack { get; set; }
    [DataMember]
    public string threat_type { get; set; }
    [DataMember]
    public bool found { get; set; }
    
    [DataContract]
    public class Handlings
    {
      [DataMember]
      public double normal { get; set; }
    }

  }

  [DataContract]
  public class LatestDomains
  {
    [DataMember]
    public int id { get; set; }
    [DataMember]
    public string name { get; set; }
  }

  //[DataContract]
  //public class DomainCategory
  //{
  //  public ZoltyEu __invalid_name__zolty.eu { get; set; }

  //  public class ZoltyEu
  //  {
  //    public int status { get; set; }
  //    public List<string> security_categories { get; set; }
  //    public List<object> content_categories { get; set; }
  //  }

  //}
    


}
