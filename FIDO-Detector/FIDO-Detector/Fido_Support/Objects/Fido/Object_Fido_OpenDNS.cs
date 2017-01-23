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

namespace Fido_Main.Fido_Support.Objects.Fido
{
  public class Object_Fido_OpenDNS
  {

    public class ApiQueries
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
    
    public class Queries
    {
      public string domainStatus { get; set; }
      public string whois { get; set; }
      public string BGPRoutesASN { get; set; }
      public string BGPRoutesIP { get; set; }
      public string DomainsLatestTags { get; set; }
      public string LinkedDomains { get; set; }
      public string DomainScore { get; set; }
      public string DnsDBIP { get; set; }
      public string DnsDBDomain { get; set; }
      public string SecurityScore { get; set; }
      public string LatestDomains { get; set; }
    }

    public class Value
    {
      public string uri { get; set; }
      public string apikey { get; set; }
      public Queries apiquery { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

  }
}