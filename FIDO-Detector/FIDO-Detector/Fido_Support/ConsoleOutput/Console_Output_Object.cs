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

namespace Fido_Main.Fido_Support.ConsoleOutput
{
  public class Console_Output_Object
  {


    public class Header
    {
      public string version { get; set; }
      public string title { get; set; }
      public string subtitle { get; set; }
    }

    public class Detector
    {
      public List<string> Cyphort { get; set; }
      public List<string> ProtectWise { get; set; }
      public List<string> CarbonBlack { get; set; }
      public List<string> SentinelOne { get; set; }
      public List<string> Niddel { get; set; }
    }

    public class Value
    {
      public string _id { get; set; }
      public string _rev { get; set; }
      public Header header { get; set; }
      public Detector detector { get; set; }
      public List<string> status { get; set; }
      public List<string> errors { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public object key { get; set; }
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