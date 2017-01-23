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

using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Objects.Cyphort
{
  [DataContract]
  public class Object_Cyphort_Class
  {

    [DataContract]
    public class CyphortEvent
    {
      [DataMember]
      [JsonProperty("first_dummy_value")]
      public int first_dummy_value { get; set; }

      [DataMember]
      [JsonProperty("event_array")]
      public CyphortEventDetails[] Event_Array { get; set; }
    }

    [DataContract]
    public class CyphortEventDetails
    {

      [DataMember]
      [JsonProperty("event_id")]
      public string Event_id { get; set; }

      [DataMember]
      [JsonProperty("event_type")]
      public string Event_type { get; set; }

      [DataMember]
      [JsonProperty("event_category")]
      public string Event_category { get; set; }

      [DataMember]
      [JsonProperty("event_name")]
      public string Event_name { get; set; }

      [DataMember]
      [JsonProperty("event_severity")]
      public string Event_severity { get; set; }

      [DataMember]
      [JsonProperty("last_activity_time")]
      public string Last_activity_time { get; set; }

      [DataMember]
      [JsonProperty("endpoint_ip")]
      public string Endpoint_ip { get; set; }

      [DataMember]
      [JsonProperty("endpoint_name")]
      public string Endpoint_name { get; set; }

      [DataMember]
      [JsonProperty("endpoint_os_type")]
      public string Endpoint_os_type { get; set; }

      [DataMember]
      [JsonProperty("source_ip")]
      public string Source_ip { get; set; }

      [DataMember]
      [JsonProperty("source_name")]
      public string Source_name { get; set; }

      [DataMember]
      [JsonProperty("source_country_code")]
      public string Source_country_code { get; set; }

      [DataMember]
      [JsonProperty("source_country_name")]
      public string Source_country_name { get; set; }

      [DataMember]
      [JsonProperty("incident_id")]
      public string Incident_id { get; set; }

      [DataMember]
      [JsonProperty("incident_risk")]
      public string Incident_risk { get; set; }

      [DataMember]
      [JsonProperty("collector_id")]
      public string Collector_id { get; set; }

      [JsonProperty("search_data")]
      public string Search_data { get; set; }

    }

    [DataContract]
    public class CyphortIncident
    {
      [DataMember]
      [JsonProperty("incident_details")]
      public CyphortIncidentDetails Incident { get; set; }
    }

    [DataContract]
    public class CyphortIncidentDetails
    {
      [DataMember]
      [JsonProperty("incident_id")]
      public string Incident_id { get; set; }

      [DataMember]
      [JsonProperty("incident_risk")]
      public string Incident_risk { get; set; }

      [DataMember]
      [JsonProperty("incident_category")]
      public string Incident_category { get; set; }

      [DataMember]
      [JsonProperty("incident_name")]
      public string Incident_name { get; set; }

      [DataMember]
      [JsonProperty("incident_severity")]
      public string Incident_severity { get; set; }

      [DataMember]
      [JsonProperty("incident_relevance")]
      public string Incident_relevance { get; set; }

      [DataMember]
      [JsonProperty("last_activity_time")]
      public string Last_activity_time { get; set; }

      [DataMember]
      [JsonProperty("endpoint_ip")]
      public string Endpoint_ip { get; set; }

      [DataMember]
      [JsonProperty("endpoint_name")]
      public string Endpoint_name { get; set; }

      [DataMember]
      [JsonProperty("endpoint_value")]
      public string Endpoint_value { get; set; }

      [DataMember]
      [JsonProperty("endpoint_os_type")]
      public string Endpoint_os_type { get; set; }

      [DataMember]
      [JsonProperty("source_ip")]
      public string Source_ip { get; set; }

      [DataMember]
      [JsonProperty("source_name")]
      public string Source_name { get; set; }

      [DataMember]
      [JsonProperty("source_country_code")]
      public string Source_country_code { get; set; }

      [DataMember]
      [JsonProperty("source_country_name")]
      public string Source_country_name { get; set; }

      [DataMember]
      [JsonProperty("has_valid_av")]
      public string Has_valid_av { get; set; }

      [DataMember]
      [JsonProperty("has_os_match")]
      public string Has_os_match { get; set; }

      [DataMember]
      [JsonProperty("has_exploit")]
      public string Has_exploit { get; set; }

      [DataMember]
      [JsonProperty("has_download")]
      public string Has_download { get; set; }

      [DataMember]
      [JsonProperty("has_execution")]
      public string Has_execution { get; set; }

      [DataMember]
      [JsonProperty("has_infection")]
      public string Has_infection { get; set; }

      [DataMember]
      [JsonProperty("has_data_theft")]
      public string Has_data_theft { get; set; }

      [DataMember]
      [JsonProperty("has_file_submission")]
      public string Has_file_submission { get; set; }

      [DataMember]
      [JsonProperty("collector_id")]
      public string Collector_id { get; set; }

      [DataMember]
      [JsonProperty("collector_type")]
      public string Collector_type { get; set; }

      [JsonProperty("search_data")]
      public string Search_data { get; set; }

      [DataMember]
      [JsonProperty("search_collector_id")]
      public string Search_collector_id { get; set; }

      [DataMember]
      [JsonProperty("exploit_array")]
      public CyphortExploitsArrayDetails[] ExploitsArray { get; set; }

      [DataMember]
      [JsonProperty("download_array")]
      public CyphortDownloadArrayDetails[] DownloadArray { get; set; }

      [DataMember]
      [JsonProperty("infection_array")]
      public CyphortInfectionArrayDetails[] InfectionArray { get; set; }

      [DataMember]
      [JsonProperty("second_order_array")]
      public CyphortSecondOrderArrayDetails[] SecondOrderArray { get; set; }

      [DataMember]
      [JsonProperty("file_submission_array")]
      public CyphortFileSubmissionArrayDetails[] FileSubmissionArray { get; set; }

      [DataMember]
      [JsonProperty("snort_event_array")]
      public CyphortSnortEventArrayDetails[] SnortEventArray { get; set; }

    }

    [DataContract]
    public class CyphortExploitsArrayDetails
    {

    }

    [DataContract]
    public class CyphortDownloadArrayDetails
    {
      [DataMember]
      [JsonProperty("event_id")]
      public string Event_id { get; set; }

      [DataMember]
      [JsonProperty("capture_time_string")]
      public string Capture_time_string { get; set; }

      [DataMember]
      [JsonProperty("endpoint_ip")]
      public string Endpoint_ip { get; set; }

      [DataMember]
      [JsonProperty("endpoint_name")]
      public string Endpoint_name { get; set; }

      [DataMember]
      [JsonProperty("source_ip")]
      public string Source_ip { get; set; }

      [DataMember]
      [JsonProperty("source_url")]
      public string Source_url { get; set; }

      [DataMember]
      [JsonProperty("client_os")]
      public string Client_os { get; set; }

      [DataMember]
      [JsonProperty("req_headers")]
      public RequestHeader Req_headers { get; set; }

      [DataMember]
      [JsonProperty("appliance_id")]
      public string Appliance_id { get; set; }

      [DataMember]
      [JsonProperty("req_referer")]
      public string Req_referer { get; set; }

      [DataMember]
      [JsonProperty("country_code")]
      public string Country_code { get; set; }

      [DataMember]
      [JsonProperty("country_name")]
      public string Country_name { get; set; }

      [DataMember]
      [JsonProperty("local_path")]
      public string Local_path { get; set; }

      [DataMember]
      [JsonProperty("file_md5_string")]
      public string File_md5_string { get; set; }

      [DataMember]
      [JsonProperty("file_sha1_string")]
      public string File_sha1_string { get; set; }

      [DataMember]
      [JsonProperty("file_sha256_string")]
      public string File_sha256_string { get; set; }

      [DataMember]
      [JsonProperty("file_size")]
      public string File_size { get; set; }

      [DataMember]
      [JsonProperty("file_type_string")]
      public string File_type_string { get; set; }

      [DataMember]
      [JsonProperty("file_suffix")]
      public string File_suffix { get; set; }

      [DataMember]
      [JsonProperty("mime_type_string")]
      public string Mime_type_string { get; set; }

      [DataMember]
      [JsonProperty("packer_name")]
      public string Packer_name { get; set; }

      [DataMember]
      [JsonProperty("malware_name")]
      public string Malware_name { get; set; }

      [DataMember]
      [JsonProperty("malware_severity")]
      public string Malware_severity { get; set; }

      [DataMember]
      [JsonProperty("malware_category")]
      public string Malware_category { get; set; }

      [DataMember]
      [JsonProperty("malware_classname")]
      public string Malware_classname { get; set; }

      [DataMember]
      [JsonProperty("has_static_detection")]
      public string Has_static_detection { get; set; }

      [DataMember]
      [JsonProperty("has_behavioral_detection")]
      public string Has_behavioral_detection { get; set; }

      [DataMember]
      [JsonProperty("user_whitelisted")]
      public string User_whitelisted { get; set; }

      [DataMember]
      [JsonProperty("cyphort_whitelisted")]
      public string Cyphort_whitelisted { get; set; }

      [DataMember]
      [JsonProperty("has_cnc")]
      public string Has_cnc { get; set; }

      [DataMember]
      [JsonProperty("dig_cert_name")]
      public string Dig_cert_name { get; set; }

      [DataMember]
      [JsonProperty("cooking_duration")]
      public string Cooking_duration { get; set; }

      [DataMember]
      [JsonProperty("source_url_rank")]
      public string Source_url_rank { get; set; }

      [DataMember]
      [JsonProperty("reputation_score")]
      public string Reputation_score { get; set; }

      [DataMember]
      [JsonProperty("microsoft_name")]
      public string Microsoft_name { get; set; }

      [DataMember]
      [JsonProperty("user_agent")]
      public string User_agent { get; set; }
    }

    [DataContract]
    public class RequestHeader
    {
      [DataMember]
      [JsonProperty("connection")]
      public string Connection { get; set; }

      [DataMember]
      [JsonProperty("accept_language")]
      public string Accept_language { get; set; }

      [DataMember]
      [JsonProperty("accept_encoding")]
      public string Accept_encoding { get; set; }

      [DataMember]
      [JsonProperty("referer")]
      public string Referer { get; set; }

      [DataMember]
      [JsonProperty("host")]
      public string Host { get; set; }

      [DataMember]
      [JsonProperty("accept")]
      public string Accept { get; set; }

      [DataMember]
      [JsonProperty("user_agent")]
      public string User_agent { get; set; }
    }

    [DataContract]
    public class CyphortInfectionArrayDetails
    {
      [DataMember]
      [JsonProperty("infection_id")]
      public string Infection_id { get; set; }

      [DataMember]
      [JsonProperty("time_string")]
      public string Time_string { get; set; }

      [DataMember]
      [JsonProperty("endpoint_ip")]
      public string Endpoint_ip { get; set; }

      [DataMember]
      [JsonProperty("endpoint_name")]
      public string Endpoint_name { get; set; }

      [DataMember]
      [JsonProperty("malware_name")]
      public string Malware_name { get; set; }

      [DataMember]
      [JsonProperty("malware_severity")]
      public string Malware_severity { get; set; }

      [DataMember]
      [JsonProperty("malware_category")]
      public string Malware_category { get; set; }

      [DataMember]
      [JsonProperty("cnc_servers")]
      public string Cnc_servers { get; set; }

      [DataMember]
      [JsonProperty("malware_classname")]
      public string Malware_classname { get; set; }
    }

    [DataContract]
    public class CyphortSecondOrderArrayDetails
    {
    }

    [DataContract]
    public class CyphortFileSubmissionArrayDetails
    {
    }

    [DataContract]
    public class CyphortSnortEventArrayDetails
    {
      [DataMember]
      [JsonProperty("time")]
      public string Time { get; set; }

      [DataMember]
      [JsonProperty("sig_name")]
      public string Sig_name { get; set; }

      [DataMember]
      [JsonProperty("cnc")]
      public string CNC { get; set; }

      [DataMember]
      [JsonProperty("data_payload")]
      public string Data_payload { get; set; }
    }
  }
}
