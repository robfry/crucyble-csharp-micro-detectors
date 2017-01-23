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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Notification.Email
{
  static class Email_Send
  {

    //function to send email
    public static void Send(string sTo, string sCC, string sFrom, string sSubject, string sBody, List<string> lGaugeAttachment, string sEmailAttachment)
    {
      var getREST = new Fido_Rest_Connection();
      var request = Fido_Support.API_Endpoints.API_Endpoints.PrimaryConfig.host + Fido_Support.API_Endpoints.API_Endpoints.PrimaryConfig.fido_configs.app_configs.email;
        //"http://127.0.0.1:5984/fido_configs/_design/app_configs/_view/email";
      var newRequest = (HttpWebRequest)WebRequest.Create(request);
      newRequest.Method = "GET"; ;
      var stringreturn = getREST.RestCall(newRequest, false);
      var emailconfigs = new Object_Fido_Email_Configs.EmailConfigs();
      if (!string.IsNullOrEmpty(stringreturn))
      {
        emailconfigs = JsonConvert.DeserializeObject<Object_Fido_Email_Configs.EmailConfigs>(stringreturn);

      }

      var getREST2 = new Fido_Rest_Connection();
      var request2 = Fido_Support.API_Endpoints.API_Endpoints.PrimaryConfig.host + Fido_Support.API_Endpoints.API_Endpoints.PrimaryConfig.fido_configs.app_configs.emailserver;
        //"http://127.0.0.1:5984/fido_configs/_design/app_configs/_view/emailserver";
      var newRequest2 = (HttpWebRequest)WebRequest.Create(request2);
      newRequest2.Method = "GET"; ;
      var stringreturn2 = getREST2.RestCall(newRequest2, false);
      var emailconfigs2 = new Object_Fido_EmailServer_Configs.EmailServer();
      if (!string.IsNullOrEmpty(stringreturn2))
      {
        emailconfigs2 = JsonConvert.DeserializeObject<Object_Fido_EmailServer_Configs.EmailServer>(stringreturn2);

      }


      var sErrorEmail = emailconfigs.rows[0].value.email.erroremail;
      var sFidoEmail = emailconfigs.rows[0].value.email.fidoemail;
      var sSMTPServer = emailconfigs2.rows[0].value[0].smtp;
      
      try
      {
        var mMessage = new MailMessage {IsBodyHtml = true};
        
        if (!string.IsNullOrEmpty(sTo))
        {
          mMessage.To.Add(sTo);
        }
        else
        {
          Send(sErrorEmail, "", sFidoEmail, "Fido Error", "Fido Failed: No sender specified in email.", null, null);
        }

        if (!string.IsNullOrEmpty(sCC))
        {
          mMessage.CC.Add(sCC);
        }
        mMessage.From = new MailAddress(sFrom);
        mMessage.Body = sBody;
        if (sSubject.Contains("\r\n")) sSubject = sSubject.Replace("\r\n", @"\");
        mMessage.Subject = sSubject; 
        
        if (lGaugeAttachment != null)
        {
          if (mMessage.Body != null)
          {
            var htmlView = AlternateView.CreateAlternateViewFromString(mMessage.Body.Trim(), null, "text/html"); 
            for (var i = 0; i < lGaugeAttachment.Count(); i++)
            {
              switch (i)
              {
                case 0:
                  var totalscore = new LinkedResource(lGaugeAttachment[i], "image/jpg") {ContentId = "totalscore"};
                  htmlView.LinkedResources.Add(totalscore);
                  break;
                case 1:
                  var userscore = new LinkedResource(lGaugeAttachment[i], "image/png") {ContentId = "userscore"};
                  htmlView.LinkedResources.Add(userscore);
                  break;
                case 2:
                  var machinescore = new LinkedResource(lGaugeAttachment[i], "image/png") {ContentId = "machinescore"};
                  htmlView.LinkedResources.Add(machinescore);
                  break;
                case 3:
                  var threatscore = new LinkedResource(lGaugeAttachment[i], "image/png") {ContentId = "threatscore"};
                  htmlView.LinkedResources.Add(threatscore);
                  break;
              }
            }

          
            mMessage.AlternateViews.Add(htmlView);
          }
        }

        if (!string.IsNullOrEmpty(sEmailAttachment))
        {
          var sAttachment = new Attachment(sEmailAttachment);
          
          mMessage.Attachments.Add(sAttachment);
        }

        using (var sSMTP = new SmtpClient(sSMTPServer))
        {
          try
          {
            Console.WriteLine(@"Sending FIDO email.");
            var sSMTPUser = Base64.Decode(emailconfigs2.rows[0].value[0].fidoemail);
            //Object_Fido_Configs.GetAsString("fido.smtp.smtpuserid", string.Empty);
            var sSMTPPwd = Base64.Decode(emailconfigs2.rows[0].value[0].fidopwd);
            //Object_Fido_Configs.GetAsString("fido.smtp.smtppwd", string.Empty);
            sSMTP.Credentials = new NetworkCredential(sSMTPUser, sSMTPPwd);
            sSMTP.Send(mMessage);
          }
          catch (Exception)
          {
            Thread.Sleep(5000);
            Console.WriteLine(@"Failed sending... trying again.");
            var sSMTPUser = Base64.Decode(emailconfigs2.rows[0].value[0].fidoemail);
            //Object_Fido_Configs.GetAsString("fido.smtp.smtpuserid", string.Empty);
            var sSMTPPwd = Base64.Decode(emailconfigs2.rows[0].value[0].fidopwd);
            //Object_Fido_Configs.GetAsString("fido.smtp.smtppwd", string.Empty);
            sSMTP.Credentials = new NetworkCredential(sSMTPUser, sSMTPPwd);
            sSMTP.Send(mMessage);
          }
          finally
          {
            //sSMTP.Dispose();
          }

        }
      }
      catch (Exception e)
      {
        Send(sErrorEmail, sFidoEmail, sFidoEmail, "Fido Error", "Fido Failed: Generic error sending email." + e, null, null);
      }
    }
  }
}
