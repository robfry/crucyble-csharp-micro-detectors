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

namespace FIDO_Detector.Fido_Support.Objects.CouchDB
{
  public class Object_CouchDB_AlertID
  {
    public class Value
    {
      public string SourceIP { get; set; }
      public string Hostname { get; set; }
      public string TimeOccurred { get; set; }
      public int PreviousScore { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

    public class AlertID
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }

  public class Object_CouchDB_Previous
  {
    public class Value
    {
      public List<string> Hash { get; set; }
      public List<string> DstIP { get; set; }
      public string Domain { get; set; }
      public string TimeOccurred { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

    public class Name
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }
}