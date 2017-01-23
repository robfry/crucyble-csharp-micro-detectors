using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.Objects.GEOIP
{
  class GEO_IP_Object
  {
    [DataContract]
    public class Location
    {
      [DataMember]
      [JsonProperty("ip")]
      public string DstIP { get; set; }

      [DataMember]
      [JsonProperty("country_code")]
      public string country_code { get; set; }

      [DataMember]
      [JsonProperty("country_name")]
      public string country_name { get; set; }

      [DataMember]
      [JsonProperty("region_code")]
      public string region_code { get; set; }

      [DataMember]
      [JsonProperty("region_name")]
      public string region_name { get; set; }

      [DataMember]
      [JsonProperty("city")]
      public string city { get; set; }

      [DataMember]
      [JsonProperty("zip_code")]
      public string zip_code { get; set; }

      [DataMember]
      [JsonProperty("time_zone")]
      public string time_zone { get; set; }

      [DataMember]
      [JsonProperty("latitude")]
      public double latitude { get; set; }

      [DataMember]
      [JsonProperty("longitude")]
      public double longitude { get; set; }

      [DataMember]
      [JsonProperty("metro_code")]
      public int metro_code { get; set; }

      [DataMember]
      public Pin pin { get; set; }

    }

    [DataContract]
    public class Pin
    {
      [DataMember]
      public string location { get; set; }
    }

  }
}
