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
  public class Object_SentinelOne_Alert_Class
  {

    public class MitigationResults
    {
    }

    public class MetaData
    {
      public string created_at { get; set; }
      public string updated_at { get; set; }
    }

    public class FileId
    {
      public string display_name { get; set; }
      public object malicious_content { get; set; }
      public string permission { get; set; }
      public object extension_type { get; set; }
      public object is_system { get; set; }
      public string object_id { get; set; }
      public object verification_type { get; set; }
      public object is_executable { get; set; }
      public string path { get; set; }
      public string content_hash { get; set; }
      public object group_id { get; set; }
      public int size { get; set; }
    }

    public class SentinelOne
    {
      public bool resolved { get; set; }
      public int mitigation_status { get; set; }
      public MitigationResults mitigation_results { get; set; }
      public string description { get; set; }
      public bool in_learning_mode { get; set; }
      public bool in_quarantine { get; set; }
      public string agent { get; set; }
      public List<object> mitigation_actions { get; set; }
      public MetaData meta_data { get; set; }
      public string agent_version { get; set; }
      public FileId file_id { get; set; }
      public string created_date { get; set; }
      public bool from_cloud { get; set; }
      public bool hidden { get; set; }
      public string malicious_group_id { get; set; }
      public string id { get; set; }
      public bool silent_threat { get; set; }
    }
  }
}