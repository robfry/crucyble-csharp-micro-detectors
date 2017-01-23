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
  public class Object_Fido_Configs_CouchDB_Integrations
  {
    public class Inventory
    {
      public bool enabled { get; set; }
    }

    public class Dhcpdetect
    {
      public bool enabled { get; set; }
    }

    public class Hostdetect
    {
      public bool enabled { get; set; }
    }

    public class Userdetect
    {
      public bool enabled { get; set; }
    }

    public class Assetscore
    {
      public bool enabled { get; set; }
    }

    public class Threatstack
    {
      public bool virustotal { get; set; }
      public bool threatgrid { get; set; }
      public bool opendns { get; set; }
      public bool alienvault { get; set; }
    }

    public class Value
    {
      public Inventory inventory { get; set; }
      public Dhcpdetect dhcpdetect { get; set; }
      public Hostdetect hostdetect { get; set; }
      public Userdetect userdetect { get; set; }
      public Assetscore assetscore { get; set; }
      public Threatstack threatstack { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

    public class RootObject
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }
}