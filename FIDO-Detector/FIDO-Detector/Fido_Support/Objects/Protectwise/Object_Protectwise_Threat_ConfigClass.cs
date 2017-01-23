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

namespace FIDO_Detector.Fido_Support.Objects.Protectwise
{
  public class Object_ProtectWise_Threat_ConfigClass
  {

    [DataContract]
    public class ProtectWise_Events
    {
      [DataMember]
      [JsonProperty("events")]
      public ProtectWise_Search_Event[] Events { get; set; }

      [JsonProperty("count")]
      public int Count { get; set; }

      [JsonProperty("nextPage")]
      public string NextPage { get; set; }
    }

    [DataContract]
    public class ProtectWise_Search_Event
    {
      [DataMember]
      [JsonProperty("cid")]
      public Int16 Cid { get; set; }

      [DataMember]
      [JsonProperty("agentId")]
      public int AgentID { get; set; }

      [DataMember]
      [JsonProperty("id")]
      public string Id { get; set; }

      [DataMember]
      [JsonProperty("type")]
      public string Type { get; set; }

      [DataMember]
      [JsonProperty("message")]
      public string Message { get; set; }

      [DataMember]
      [JsonProperty("observations")]
      public ProtectWise_Observation[] Observations { get; set; }

      [DataMember]
      [JsonProperty("netflows")]
      public ProtectWise_Netflow[] Netflow { get; set; }

      [DataMember]
      [JsonProperty("confidence")]
      public Int16 Confidence { get; set; }

      [DataMember]
      [JsonProperty("threatScore")]
      public Int16 ThreatScore { get; set; }

      [DataMember]
      [JsonProperty("threatLevel")]
      public string ThreatLevel { get; set; }

      [DataMember]
      [JsonProperty("killChainStage")]
      public string KillChainStage { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }

      [DataMember]
      [JsonProperty("threatSubCategory")]
      public string ThreatSubCategory { get; set; }

      [DataMember]
      [JsonProperty("observationCount")]
      public Int16 ObservationCount { get; set; }

      [DataMember]
      [JsonProperty("netflowCount")]
      public Int16 NetflowCount { get; set; }

    }

    [DataContract]
    public class ProtectWise_Observation
    {
      [DataMember]
      [JsonProperty("agentId")]
      public string AgentID { get; set; }

      [DataMember]
      [JsonProperty("flowId")]
      public ProtectWise_Flow_Detail Flow { get; set; }

      [DataMember]
      [JsonProperty("data")]
      public ProtectWise_Data Data { get; set; }

      [DataMember]
      [JsonProperty("occurredAt")]
      public string EventTime { get; set; }

      [DataMember]
      [JsonProperty("observedAt")]
      public string ObservedTime { get; set; }

      [DataMember]
      [JsonProperty("threatLevel")]
      public string ThreatLevel { get; set; }

      [DataMember]
      [JsonProperty("confidence")]
      public Int16 Confidence { get; set; }

      [DataMember]
      [JsonProperty("killChainStage")]
      public string KillChainStage { get; set; }

      [DataMember]
      [JsonProperty("severity")]
      public Int16 Severity { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }
      
      [DataMember]
      [JsonProperty("threatScore")]
      public Int16 ThreatScore { get; set; }

      [DataMember]
      [JsonProperty("observedStage")]
      public string ObservedStage { get; set; }

      [DataMember]
      [JsonProperty("source")]
      public string Source { get; set; }

      [DataMember]
      [JsonProperty("id")]
      public string EventID { get; set; }

      [DataMember]
      [JsonProperty("threatSubCategory")]
      public string ThreatSubCategory { get; set; }
    }

    [DataContract]
    public class ProtectWise_Netflow
    {
      [DataMember]
      [JsonProperty("details")]
      public ProtectWise_Flow_Details FlowDetails { get; set; }

      [DataMember]
      [JsonProperty("id")]
      public ProtectWise_Flow_IP Id { get; set; }

      [DataMember]
      [JsonProperty("geo")]
      public ProtectWise_GEO GEO { get; set; }
    }

    [DataContract]
    public class ProtectWise_Flow_Details
    {
      [DataMember]
      [JsonProperty("startTime")]
      public double StartTime { get; set; }

      [DataMember]
      [JsonProperty("isEncrypted")]
      public bool isEncrypted { get; set; }

    }

    [DataContract]
    public class ProtectWise_Flow_IP
    {
      [DataMember]
      [JsonProperty("srcMac")]
      public string SrcMAC { get; set; }

      [DataMember]
      [JsonProperty("dstMac")]
      public string DstMAC { get; set; }

      [DataMember]
      [JsonProperty("srcIP")]
      public string SrcIP { get; set; }

      [DataMember]
      [JsonProperty("dstIP")]
      public string DstIP { get; set; }

      [DataMember]
      [JsonProperty("srcPort")]
      public string SrcPort { get; set; }

      [DataMember]
      [JsonProperty("dstPort")]
      public string DstPort { get; set; }

    }

    [DataContract]
    public class ProtectWise_Flow_Detail
    {
      [DataMember]
      [JsonProperty("key")]
      public String Key { get; set; }

      [DataMember]
      [JsonProperty("startTime")]
      public String StartTime { get; set; }

      [DataMember]
      [JsonProperty("ip")]
      public ProtectWise_IP IP { get; set; }

    }

    [DataContract]
    public class ProtectWise_IP
    {
      [DataMember]
      [JsonProperty("srcMac")]
      public string SrcMAC { get; set; }

      [DataMember]
      [JsonProperty("dstMac")]
      public string DstMAC { get; set; }

      [DataMember]
      [JsonProperty("srcIp")]
      public string SrcIP { get; set; }

      [DataMember]
      [JsonProperty("dstIp")]
      public string DstIP { get; set; }
      
      [DataMember]
      [JsonProperty("srcPort")]
      public string SrcPort { get; set; }

      [DataMember]
      [JsonProperty("dstPort")]
      public string DstPort { get; set; }

      [DataMember]
      [JsonProperty("proto")]
      public string Protocol { get; set; }
      
    }

    [DataContract]
    public class ProtectWise_Data
    {
      [DataMember]
      [JsonProperty("idsEvent")]
      public ProtectWise_IDS_Event IdsEvent { get; set; }

      [DataMember]
      [JsonProperty("protocol")]
      public string Protocol { get; set; }

      [DataMember]
      [JsonProperty("ipReputation")]
      public ProtectWise_IP_Reputation Ip_Reputation { get; set; }

      [DataMember]
      [JsonProperty("httpRequest")]
      public string HttpReq { get; set; }

      [DataMember]
      [JsonProperty("urlReputation")]
      public ProtectWise_URL_Reputation URL_Reputation { get; set; }

      [DataMember]
      [JsonProperty("dns")]
      public string DNS { get; set; }

      [DataMember]
      [JsonProperty("dnsReputation")]
      public ProtectWise_DNS_Reputation DNS_Reputation { get; set; }

      [DataMember]
      [JsonProperty("fileReputation")]
      public ProtectWise_File_Reputation File_Reputation { get; set; }

    }

    [DataContract]
    public class ProtectWise_IDS_Event
    {
      [DataMember]
      [JsonProperty("timestampSeconds")]
      public string TimeStampSeconds { get; set; }

      [DataMember]
      [JsonProperty("classification")]
      public string Classification { get; set; }

      [DataMember]
      [JsonProperty("description")]
      public string Description { get; set; }
    }

    [DataContract]
    public class ProtectWise_DNS_Reputation
    {
      [DataMember]
      [JsonProperty("dns")]
      public string DNSDomain { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }

      [DataMember]
      [JsonProperty("partnercategory")]
      public string PartnerCategory { get; set; }

      [DataMember]
      [JsonProperty("dnsObservationDAta")]
      public string DNSObservationData { get; set; }
    }

    [DataContract]
    public class ProtectWise_URL_Reputation
    {
      [DataMember]
      [JsonProperty("url")]
      public string Url { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }

      [DataMember]
      [JsonProperty("partnerCategory")]
      public string PartnerCategory { get; set; }

      [DataMember]
      [JsonProperty("urlData")]
      public string UrlData { get; set; }
    }

    [DataContract]
    public class ProtectWise_File_Reputation
    {
      [DataMember]
      [JsonProperty("transportProtocol")]
      public string TransPortProtocol { get; set; }

      [DataMember]
      [JsonProperty("isTruncated")]
      public string isTruncated { get; set; }

      [DataMember]
      [JsonProperty("advertisedType")]
      public string AdvertisedType { get; set; }

      [DataMember]
      [JsonProperty("isTypeMismatched")]
      public string isTypeMismatched { get; set; }

      [DataMember]
      [JsonProperty("extractedName")]
      public string ExtractedName { get; set; }

      [DataMember]
      [JsonProperty("extractedPath")]
      public string ExtractedPath { get; set; }

      [DataMember]
      [JsonProperty("advertisedSize")]
      public string AdvertisedSize { get; set; }

      [DataMember]
      [JsonProperty("id")]
      public string ID { get; set; }

      [DataMember]
      [JsonProperty("detectedType")]
      public string DetectedType { get; set; }

      [DataMember]
      [JsonProperty("detectedFileSize")]
      public string DetectedFileSize { get; set; }

      [DataMember]
      [JsonProperty("hashes")]
      public Hashes Hashes { get; set; }

      [DataMember]
      [JsonProperty("type")]
      public string Type { get; set; }

      [DataMember]
      [JsonProperty("isArchive")]
      public string isArchive { get; set; }

      [DataMember]
      [JsonProperty("isEncrypted")]
      public string isEncrypted { get; set; }

      [DataMember]
      [JsonProperty("detectedDescription")]
      public string DetectedDescription { get; set; }

      [DataMember]
      [JsonProperty("serviceType")]
      public string ServiceType { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }

      [DataMember]
      [JsonProperty("finding")]
      public Finding Finding { get; set; }
    }

    [DataContract]
    public class Hashes
    {
      [DataMember]
      public string md5 { get; set; }

      [DataMember]
      public string sha1 { get; set; }

      [DataMember]
      public string sha256 { get; set; }

      [DataMember]
      public string sha512 { get; set; }

      [DataMember]
      public AdditionalHashes additionalHashes { get; set; }
    }

    [DataContract]
    public class Finding
    {
      [DataMember]
      public int score { get; set; }
    }

    [DataContract]
    public class AdditionalHashes
    {
    }

    [DataContract]
    public class ProtectWise_IP_Reputation
    {
      [DataMember]
      [JsonProperty("ip")]
      public string IP { get; set; }

      [DataMember]
      [JsonProperty("category")]
      public string Category { get; set; }

      [DataMember]
      [JsonProperty("partnerCategory")]
      public string PartnerCategory { get; set; }
    }

    [DataContract]
    public class ProtectWise_GEO
    {
      [DataMember]
      [JsonProperty("src")]
      public ProtectWise_Destination Destination { get; set; }

    }

    [DataContract]
    public class ProtectWise_Destination
    {
      [DataMember]
      [JsonProperty("continent")]
      public ProtectWise_Destination_Continent Continent { get; set; }

      [DataMember]
      [JsonProperty("country")]
      public ProtectWise_Destination_Country Country { get; set; }

      [DataMember]
      [JsonProperty("postal")]
      public ProtectWise_Destination_Postal Postal { get; set; }

      [DataMember]
      [JsonProperty("city")]
      public ProtectWise_Destination_City City { get; set; }

      [DataMember]
      [JsonProperty("organization")]
      public string Organization { get; set; }

    }

    [DataContract]
    public class ProtectWise_Destination_Continent
    {
      [DataMember]
      [JsonProperty("confidence")]
      public string Confidence { get; set; }

      [DataMember]
      [JsonProperty("code")]
      public string CountryCode { get; set; }

      [DataMember]
      [JsonProperty("name")]
      public string Name { get; set; }
    }

    [DataContract]
    public class ProtectWise_Destination_Country
    {
      [DataMember]
      [JsonProperty("confidence")]
      public string Confidence { get; set; }

      [DataMember]
      [JsonProperty("isoCode")]
      public string IsoCode { get; set; }

      [DataMember]
      [JsonProperty("name")]
      public string Name { get; set; }
    }

    [DataContract]
    public class ProtectWise_Destination_Postal
    {
      [DataMember]
      [JsonProperty("code")]
      public string Code { get; set; }

      [DataMember]
      [JsonProperty("confidence")]
      public string Confidence { get; set; }
    }

    [DataContract]
    public class ProtectWise_Destination_City
    {
      [DataMember]
      [JsonProperty("confidence")]
      public string Confidence { get; set; }

      [DataMember]
      [JsonProperty("isoCode")]
      public string IsoCode { get; set; }

      [DataMember]
      [JsonProperty("name")]
      public string Name { get; set; }
    }
  }
}