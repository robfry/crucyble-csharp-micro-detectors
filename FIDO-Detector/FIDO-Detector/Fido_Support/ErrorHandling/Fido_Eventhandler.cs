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
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Rest;
using FIDO_Detector.Notification.Email;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.ErrorHandling
{
  //Error handling class to email errors
  public static class Fido_EventHandler
  {
    public static void SendEmail(string sErrorSubject, string sErrorMessage)
    {
      var getREST = new Fido_Rest_Connection();
      var request = API_Endpoints.API_Endpoints.PrimaryConfig.host + API_Endpoints.API_Endpoints.PrimaryConfig.fido_configs.app_configs.email;
        //"http://127.0.0.1:5984/fido_configs/_design/app_configs/_view/email";
      var newRequest = (HttpWebRequest)WebRequest.Create(request);
      newRequest.Method = "GET"; ;
      var stringreturn = getREST.RestCall(newRequest, false);
      var emailconfigs = new Object_Fido_Email_Configs.EmailConfigs();
      if (!string.IsNullOrEmpty(stringreturn))
      {
        emailconfigs = JsonConvert.DeserializeObject<Object_Fido_Email_Configs.EmailConfigs>(stringreturn);
      }

      var sFidoEmail = emailconfigs.rows[0].value.email.fidoemail;
      var sErrorEmail = emailconfigs.rows[0].value.email.erroremail;
      var isGoingToRun = emailconfigs.rows[0].value.email.runerroremail;

      var isTest = emailconfigs.rows[0].value.Test; //new SqLiteDB().ExecuteBool(@"select teststartup from configs_application");

      if (!isGoingToRun) return;
      if (isTest) sErrorSubject = "Test: " + sErrorSubject;

      Email_Send.Send(sErrorEmail, sFidoEmail, sFidoEmail, sErrorSubject, sErrorMessage, null, null);
      Console.WriteLine(sErrorMessage);
      Thread.Sleep(1000);
    }
  }
}
