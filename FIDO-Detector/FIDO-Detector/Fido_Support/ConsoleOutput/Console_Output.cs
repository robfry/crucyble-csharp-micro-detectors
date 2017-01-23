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

using System;
using System.Net;
using System.Windows.Forms;
using Fido_Main.Fido_Support.Objects.Niddel;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Fido_Support.ConsoleOutput
{
  public class Console_Output
  {


    public void UpdateConsole(string Output, string CurrentDetector)
    {

    }

    public void UpdateConsole(string Output)
    {

    }

    public void CreateConsole()
    {
      const string request = "http://127.0.0.1:5984/fido_console/_design/console/_view/full?limit=20&reduce=false";
      var alertRequest = (HttpWebRequest) WebRequest.Create(request);
      alertRequest.Method = @"GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        var tempReturn = JsonConvert.DeserializeObject<Console_Output_Object.RootObject>(stringreturn);
        
        Console.WriteLine(@"Crucyble... a Fully Integrated Defense Operation love child.");
        Console.WriteLine(@"Currently running version : v" + tempReturn.rows[0].value.header.version);
        Console.WriteLine(@"Loading...");
      }
      catch (WebException wer)
      {

      }
      catch (Exception e)
      {

      }
    }

  }
}