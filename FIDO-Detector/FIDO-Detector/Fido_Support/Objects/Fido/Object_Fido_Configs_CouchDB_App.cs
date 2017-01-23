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

namespace FIDO_Detector.Fido_Support.Objects.Fido
{
  public class Object_Fido_Configs_CouchDB_App
  {
    public class Key
    {
      public bool Test { get; set; }
      public string ticker { get; set; }
      public string fidotimout { get; set; }
      public string sqltimeout { get; set; }
      public string unknownkeepalive { get; set; }
      public List<string> detectors { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Key value { get; set; }
    }

    public class StartupConfigs
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }
}