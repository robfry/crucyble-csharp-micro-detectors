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
  public class Object_Fido_Email_Configs
  {
    public class Email
    {
      public string fidoemail { get; set; }
      public string primaryemail { get; set; }
      public string secondaryemail { get; set; }
      public string helpdeskemail { get; set; }
      public string nonalertemail { get; set; }
      public string erroremail { get; set; }
      public bool runerroremail { get; set; }
    }

    public class Value
    {
      public Email email { get; set; }
      public bool Test { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

    public class EmailConfigs
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }
}