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
using System.Data;
using System.Runtime.Serialization;
using Fido_Main.Fido_Support.ErrorHandling;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.ThreatGRID
{
  [DataContract]
  internal class Object_ThreatGRID_IP_ConfigClass
  {
    [DataContract]
    public class ThreatGRID_IP_HLInfo
    {
      [DataMember]
      [JsonProperty("data")]
      internal ThreatGRID_IP_HLDetail Data_Array { get; set; }

      [DataMember]
      [JsonProperty("id")]
      internal string Id { get; set; }

      [DataMember]
      [JsonProperty("api_version")]
      internal string API_Version { get; set; }
    }

    [DataContract]
    internal class ThreatGRID_IP_HLDetail
    {
      [DataMember]
      [JsonProperty("ip")]
      internal string IP { get; set; }

      [DataMember]
      [JsonProperty("asn")]
      internal ThreatGRID_IP_ASNDetail ASN_Array { get; set; }

      [DataMember]
      [JsonProperty("location")]
      internal ThreatGRID_IP_Location Location_Array { get; set; }

      [DataMember]
      [JsonProperty("rev")]
      internal string RevDomain { get; set; }
    
      [DataMember]
      [JsonProperty("flags")]
      internal ThreatGRID_Flag[] Flags { get; set; }

      [DataMember]
      [JsonProperty("tags")]
      internal ThreatGRID_Tags[] Tags { get; set; }

    }

    [DataContract]
    internal class ThreatGRID_IP_ASNDetail
    {
      [DataMember]
      [JsonProperty("org")]
      internal string Org { get; set; }

      [DataMember]
      [JsonProperty("asn")]
      internal string ASN { get; set; }
    }

    [DataContract]
    internal class ThreatGRID_IP_Location
    {
      [DataMember]
      [JsonProperty("city")]
      internal string City { get; set; }

      [DataMember]
      [JsonProperty("region")]
      internal string Region { get; set; }

      [DataMember]
      [JsonProperty("country")]
      internal string Country { get; set; }
    }

    [DataContract]
    internal class ThreatGRID_Flag
    {
      [DataMember]
      [JsonProperty("flag")]
      internal string Flag { get; set; }

      [DataMember]
      [JsonProperty("reason")]
      internal string Reason { get; set; }

      [DataMember]
      [JsonProperty("mine")]
      internal bool isMine { get; set; }
    }

    [DataContract]
    internal class ThreatGRID_Tags
    {
      [DataMember]
      [JsonProperty("tag")]
      internal string Flag { get; set; }

      [DataMember]
      [JsonProperty("count")]
      internal string Reason { get; set; }

      [DataMember]
      [JsonProperty("mine")]
      internal bool isMine { get; set; }
    }

    
    [DataContract]
    internal class ParseConfigs
    {
      [DataMember]
      internal Int16 PrimeKey { get; set; }
      [DataMember]
      internal string ApiCall { get; set; }
      [DataMember]
      internal string ApiBaseUrl { get; set; }
      [DataMember]
      internal string ApiFuncCall { get; set; }
      [DataMember]
      internal string ApiQueryString { get; set; }
      [DataMember]
      internal string ApiKey { get; set; }
    }

    internal static ParseConfigs FormatParse(DataTable dbReturn)
    {
      try
      {
        var reformat = new ParseConfigs
        {
          PrimeKey = Convert.ToInt16(dbReturn.Rows[0].ItemArray[0]),
          ApiCall = Convert.ToString(dbReturn.Rows[0].ItemArray[1]),
          ApiBaseUrl = Convert.ToString(dbReturn.Rows[0].ItemArray[2]),
          ApiFuncCall = Convert.ToString(dbReturn.Rows[0].ItemArray[3]),
          ApiQueryString = Convert.ToString(dbReturn.Rows[0].ItemArray[4]),
          ApiKey = Convert.ToString(dbReturn.Rows[0].ItemArray[5])
        };

        return reformat;
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Unable to format datatable return." + e);
      }
      return null;
    }
  }
}