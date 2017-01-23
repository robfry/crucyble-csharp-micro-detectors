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

using System;
using System.Net;
using System.Threading;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.Jamf;
using Fido_Main.Fido_Support.Rest;
using Fido_Main.Fido_Support.XMLHelper;

namespace Fido_Main.Director.SysMgmt
{
  class SysMgmtJamf
  {
    public JamfReturnValues.Computer GetJamf(FidoReturnValues lFidoReturnValues, bool isHostName)
    {
      JamfReturnValues.Computer JamfReturn;
      if (isHostName)
      {
        Console.WriteLine(@"Querying JAMF for computer by hostname.");
        JamfReturn = GetJamfInventoryByID(null, lFidoReturnValues.Hostname);
        return JamfReturn;
      }
      else
      {
        Console.WriteLine(@"Querying JAMF for computers by IP.");
        JamfReturn = GetJamfInventoryByID(lFidoReturnValues.SrcIP, null);
        return JamfReturn;
      }
    }

    private JamfReturnValues.Computer GetJamfInventoryByID(string srcIP, string hostname)
    {
      var jamfReturn = new JamfReturnValues.Computer();
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
      var request = string.IsNullOrEmpty(srcIP) ? @"https://nfjamf.jamfcloud.com/JSSResource/computers/name/" + hostname : @"https://nfjamf.jamfcloud.com/JSSResource/computers/match/" + srcIP;

      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Credentials = new NetworkCredential(@"fido", @"Crup2497jfjfytyt!");
      alertRequest.Method = "GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        Thread.Sleep(1000);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        jamfReturn = stringreturn.ParseXML<JamfReturnValues.Computer>();
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving JAMF inventory section:" + e + " " + request);
      }

      return jamfReturn;
    }

    private JamfReturnValues.Computer ComputerReturn(JamfReturnValues.Computers computers, FidoReturnValues lFidoReturnValues)
    {
      var c = new JamfReturnValues.Computer();

      foreach (var computer in computers.Computer)
      {
        c = GetJamfInventoryByID(computer.Id, null);
        //var i = 0;
        //while (c.General == null & i < 10)
        //{
        //  c = GetJamfInventoryByID(computer.Id, null);
        //  ++i;
        //}
        if (c.General == null) continue;
        if (c.General.Ip_address == lFidoReturnValues.SrcIP)
        {
          lFidoReturnValues.Inventory.Jamf = c;
        }
      }

      return c;
    }
  }
}
